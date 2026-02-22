"""CLI entrypoint for the PenteraX agentic pentest pipeline.

Subcommands:
    python -m src --cli pipeline       — Run the full 4-phase pipeline
    python -m src --cli skills --list  — List discovered skills
    python -m src --cli skills --setup — Verify skill directories and deps
    python -m src --cli skills --test <name> — Run a quick test
    python -m src --cli validate <file> <schema_type> — Validate a deliverable
    python -m src --cli lookup --product <p> --version <v> — CVE lookup

Direct headless invocation (Phase 3 shorthand):
    python -m src --cli --target-url http://54.146.141.88:3000 --api-key sk-ant-...
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from pathlib import Path

from .config import AppConfig
from .exceptions import PipelineAbortedError
from .logging_handler import setup_logging
from .pipeline import run_pipeline, PipelineConfig, DELIVERABLES_DIR, load_replay_deliverables, save_replay_snapshot
from .preflight import run_preflight
from .skills.skill_loader import SkillRegistry, PROJECT_ROOT, SKILLS_DIR
from .skills.skill_wrappers import (
    parse_nmap,
    validate_deliverable,
    lookup_cve,
    format_known_vulns_for_prompt,
)

logger = logging.getLogger("penterax.cli")


def _setup_logging(verbose: bool = False) -> None:
    setup_logging(verbose=verbose)


# ---------------------------------------------------------------------------
# skills subcommand
# ---------------------------------------------------------------------------

def cmd_skills(args: argparse.Namespace) -> int:
    """Handle the ``skills`` subcommand."""
    registry = SkillRegistry()

    if args.list:
        skills = registry.list_all()
        if not skills:
            print("No skills found. Run 'python -m src skills --setup' to check.")
            return 1
        print(f"\nDiscovered {len(skills)} skill(s):\n")
        for s in skills:
            print(f"  {s['name']}")
            print(f"    Description: {s['description']}")
            print(f"    Scripts:     {', '.join(s['scripts']) or 'none'}")
            print(f"    References:  {', '.join(s['references']) or 'none'}")
            print()
        return 0

    if args.setup:
        print("Checking skill setup...\n")
        ok = True

        # Check skills directory
        if not SKILLS_DIR.exists():
            print(f"  [FAIL] Skills directory not found: {SKILLS_DIR}")
            ok = False
        else:
            print(f"  [OK]   Skills directory: {SKILLS_DIR}")

        # Check each skill
        skills = registry.list_all()
        if not skills:
            print("  [WARN] No skills discovered")
            ok = False
        else:
            for s in skills:
                meta = registry.get(s["name"])
                if meta is None:
                    continue
                print(f"  [OK]   Skill: {meta.name}")
                # Check scripts exist
                for script in meta.scripts:
                    spath = meta.scripts_dir / script
                    if spath.exists():
                        print(f"         [OK]  Script: {script}")
                    else:
                        print(f"         [FAIL] Script missing: {script}")
                        ok = False
                # Check references exist
                for ref in meta.references:
                    rpath = meta.references_dir / ref
                    if rpath.exists():
                        print(f"         [OK]  Reference: {ref}")
                    else:
                        print(f"         [FAIL] Reference missing: {ref}")
                        ok = False

        # Check Python dependencies
        print()
        for dep in ["yaml", "requests"]:
            try:
                __import__(dep)
                print(f"  [OK]   Python module: {dep}")
            except ImportError:
                print(f"  [FAIL] Python module missing: {dep}")
                ok = False

        print()
        if ok:
            print("All checks passed.")
        else:
            print("Some checks failed. Review the output above.")
        return 0 if ok else 1

    if args.test:
        skill_name = args.test
        print(f"Testing skill: {skill_name}\n")
        meta = registry.get(skill_name)
        if meta is None:
            print(f"Skill not found: {skill_name}")
            print(f"Available skills: {registry.skill_names}")
            return 1

        print(f"  Name:        {meta.name}")
        print(f"  Description: {meta.description}")
        print(f"  Directory:   {meta.skill_dir}")
        print(f"  Scripts:     {meta.scripts}")
        print(f"  References:  {meta.references}")
        print()

        # Run a quick test based on skill type
        if skill_name == "network-recon":
            print("  Test: parse_nmap.py --help")
            result = registry.run("network-recon", "parse_nmap.py", args=["--help"])
            print(f"  Exit code: {result.exit_code}")
            if result.raw_stdout:
                for line in result.raw_stdout.strip().split("\n")[:5]:
                    print(f"    {line}")
        elif skill_name == "response-analysis":
            print("  Test: validate_response.py --help")
            result = registry.run("response-analysis", "validate_response.py", args=["--help"])
            print(f"  Exit code: {result.exit_code}")
            if result.raw_stdout:
                for line in result.raw_stdout.strip().split("\n")[:5]:
                    print(f"    {line}")
        elif skill_name == "vulnerability-lookup":
            print("  Test: lookup_cve.py --help")
            result = registry.run("vulnerability-lookup", "lookup_cve.py", args=["--help"])
            print(f"  Exit code: {result.exit_code}")
            if result.raw_stdout:
                for line in result.raw_stdout.strip().split("\n")[:5]:
                    print(f"    {line}")
        else:
            print(f"  No built-in test for skill '{skill_name}'. "
                  "Listing scripts only.")

        print("\n  Prompt context preview (first 500 chars):")
        ctx = registry.build_prompt_context(skill_name)
        print(f"    {ctx[:500]}...")
        return 0

    # Default: show help
    print("Use --list, --setup, or --test <skill-name>")
    return 1


# ---------------------------------------------------------------------------
# validate subcommand
# ---------------------------------------------------------------------------

def cmd_validate(args: argparse.Namespace) -> int:
    """Handle the ``validate`` subcommand."""
    registry = SkillRegistry()
    path = Path(args.file)

    if not path.exists():
        print(f"File not found: {path}")
        return 1

    print(f"Validating: {path} (schema: {args.schema_type})")
    result = validate_deliverable(registry, path, args.schema_type)

    if result.success:
        print("  PASSED — deliverable is valid.")
    else:
        print("  FAILED — validation errors:")
        if isinstance(result.output, dict):
            for err in result.output.get("errors", []):
                print(f"    - {err}")
        elif result.errors:
            for err in result.errors:
                print(f"    - {err}")

    return 0 if result.success else 1


# ---------------------------------------------------------------------------
# lookup subcommand
# ---------------------------------------------------------------------------

def cmd_lookup(args: argparse.Namespace) -> int:
    """Handle the ``lookup`` subcommand."""
    registry = SkillRegistry()

    if not args.product and not args.cwe and not args.keyword:
        print("Provide at least one of: --product, --cwe, --keyword")
        return 1

    print(f"Looking up CVEs...", end=" ", flush=True)
    result = lookup_cve(
        registry,
        product=args.product or "",
        version=args.version or "",
        cwe=args.cwe or "",
        keyword=args.keyword or "",
        severity=args.severity or "",
    )

    if not result.success:
        print("FAILED")
        for err in result.errors:
            print(f"  Error: {err}")
        return 1

    print("done.\n")

    if isinstance(result.output, dict):
        results = result.output.get("results", [])
        total = result.output.get("total_results", len(results))
        print(f"Found {total} vulnerabilit{'y' if total == 1 else 'ies'}:\n")

        for vuln in results:
            cve = vuln.get("cve_id", "N/A")
            sev = vuln.get("severity", "UNKNOWN")
            cvss = vuln.get("cvss_v3", 0.0)
            summary = vuln.get("summary", "No description")
            exploit = "Yes" if vuln.get("exploit_available") else "No"
            cwe_id = vuln.get("cwe", "")

            print(f"  {cve} ({sev}, CVSS {cvss})")
            print(f"    {summary[:120]}")
            if cwe_id:
                print(f"    CWE: {cwe_id}")
            print(f"    Exploit available: {exploit}")
            print()

        if args.json:
            print("--- Raw JSON ---")
            print(json.dumps(result.output, indent=2))
    else:
        print("Raw output:")
        print(result.raw_stdout or str(result.output))

    return 0


# ---------------------------------------------------------------------------
# pipeline subcommand
# ---------------------------------------------------------------------------

def cmd_pipeline(args: argparse.Namespace) -> int:
    """Handle the ``pipeline`` subcommand — full agentic run."""
    # Build AppConfig from CLI args
    cfg = AppConfig(
        target_url=args.target,
        anthropic_api_key=getattr(args, "api_key", "") or "",
        output_dir=Path(args.output),
        max_retries=args.retries,
        max_budget_usd=float(getattr(args, "budget", 10.0) or 10.0),
        verbose=args.verbose,
    )

    return _run_pipeline_from_config(cfg, resume_from=getattr(args, "resume_from", None), replay=getattr(args, "replay", False))


# ---------------------------------------------------------------------------
# Direct headless invocation (--target-url / --api-key shorthand)
# ---------------------------------------------------------------------------

def cmd_direct(args: argparse.Namespace) -> int:
    """Direct pipeline run from top-level flags (no subcommand)."""
    cfg = AppConfig(
        target_url=args.target_url,
        anthropic_api_key=args.api_key,
        output_dir=Path(args.output_dir) if args.output_dir else DELIVERABLES_DIR,
        max_retries=int(args.max_retries or 3),
        max_budget_usd=float(args.budget or 10.0),
        verbose=args.verbose,
    )
    return _run_pipeline_from_config(cfg, resume_from=args.resume_from, replay=args.replay)


def _run_pipeline_from_config(
    cfg: AppConfig,
    *,
    resume_from: str | None = None,
    replay: bool = False,
) -> int:
    """Shared logic for running the pipeline from a config."""
    errors = cfg.validate()
    if errors and not replay:
        for e in errors:
            print(f"  Config error: {e}")
        return 1

    # Setup logging to file as well
    setup_logging(verbose=cfg.verbose, log_dir=cfg.output_dir)

    pipeline_cfg = cfg.to_pipeline_config()

    print(f"Starting PenteraX pipeline")
    print(f"  Target:  {pipeline_cfg.target_url}")
    print(f"  Output:  {pipeline_cfg.output_dir}")
    print(f"  Retries: {pipeline_cfg.max_retries}")
    print(f"  Budget:  ${cfg.max_budget_usd:.2f}")
    if resume_from:
        print(f"  Resume:  from '{resume_from}' phase")
    if replay:
        print(f"\n  ╔══════════════════════════════════════════╗")
        print(f"  ║          [REPLAY MODE]                  ║")
        print(f"  ║  Using pre-recorded deliverables         ║")
        print(f"  ╚══════════════════════════════════════════╝\n")
        restored = load_replay_deliverables(pipeline_cfg.output_dir)
        if not restored:
            print("  No replay deliverables found. Run a full pipeline first,")
            print("  then use 'save-replay' or copy files to deliverables/replay/.")
            return 1
        print(f"  Restored {len(restored)} deliverable(s) from replay:")
        for r in restored:
            print(f"    - {r}")
        print()
    print()

    # Preflight
    if not replay:
        pf = run_preflight(cfg)
        print(pf.summary)
        if not pf.all_critical_passed:
            print("\nPre-flight FAILED — aborting.")
            return 1
        print()

    # SIGINT → cooperative stop
    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    # Build agent runner (None for replay mode)
    agent_runner_fn = None
    if not replay:
        from .agent_runner import AgentRunner
        from .agent_loop import MCP_TOOLS, SkillToolDispatcher
        from .skills.skill_loader import SkillRegistry as SR

        runner = AgentRunner(
            api_key=cfg.anthropic_api_key,
            max_budget_usd=cfg.max_budget_usd,
            stop_event=stop_event,
        )
        registry = SR()
        dispatcher = SkillToolDispatcher(registry)
        runner._tools = MCP_TOOLS
        runner._tool_dispatcher = dispatcher
        agent_runner_fn = runner.run

    try:
        result = run_pipeline(
            config=pipeline_cfg,
            agent_runner=agent_runner_fn,
            stop_event=stop_event,
            resume_from=resume_from,
        )
    except PipelineAbortedError:
        print("\nPipeline aborted by user.")
        return 130

    print(f"\n{'=' * 60}")
    print(f"Pipeline complete in {result.total_duration_seconds:.1f}s")
    print(f"Deliverables generated: {len(result.deliverables_generated)}")
    for d in result.deliverables_generated:
        print(f"  - {d}")

    print(f"\nPhase summary:")
    for phase in result.phases:
        status = "PASS" if phase.success else "FAIL"
        val = "validated" if phase.validation_passed else "not validated"
        print(f"  [{status}] {phase.phase_name} ({phase.duration_seconds:.1f}s, {val})")
        if phase.errors:
            for err in phase.errors:
                print(f"         Error: {err}")

    if not replay and agent_runner_fn is not None:
        print(f"\n  Total API cost: ${runner.total_cost_usd:.4f}")

    return 0 if all(p.success for p in result.phases) else 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="penterax",
        description="PenteraX — Agentic Cybersecurity Pipeline",
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")

    # Direct-invocation flags (no subcommand needed)
    parser.add_argument("--target-url", type=str, default="",
                        help="Target URL for direct pipeline run")
    parser.add_argument("--api-key", type=str, default="",
                        help="Anthropic API key")
    parser.add_argument("--output-dir", type=str, default="",
                        help="Output directory (default: deliverables/)")
    parser.add_argument("--max-retries", type=int, default=3,
                        help="Max retries per phase (default: 3)")
    parser.add_argument("--budget", type=float, default=10.0,
                        help="Max API budget in USD (default: 10.0)")
    parser.add_argument("--resume-from",
                        choices=["recon", "analysis", "exploit", "report"],
                        help="Resume pipeline from a specific phase")
    parser.add_argument("--replay", action="store_true",
                        help="Use pre-recorded deliverables (no API calls)")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- skills ---
    sp_skills = subparsers.add_parser("skills", help="Manage and test skills")
    sp_skills.add_argument("--list", action="store_true",
                           help="List all discovered skills")
    sp_skills.add_argument("--setup", action="store_true",
                           help="Verify skill setup and dependencies")
    sp_skills.add_argument("--test", type=str, metavar="SKILL",
                           help="Run a quick test for a specific skill")

    # --- validate ---
    sp_validate = subparsers.add_parser("validate", help="Validate a deliverable")
    sp_validate.add_argument("file", help="Path to the deliverable file")
    sp_validate.add_argument("schema_type",
                             choices=["recon_report", "hypotheses",
                                      "findings", "pentest_report"],
                             help="Schema type for validation")

    # --- lookup ---
    sp_lookup = subparsers.add_parser("lookup", help="Look up CVEs")
    sp_lookup.add_argument("--product", type=str, help="Product name")
    sp_lookup.add_argument("--version", type=str, help="Version string")
    sp_lookup.add_argument("--cwe", type=str, help="CWE identifier")
    sp_lookup.add_argument("--keyword", type=str, help="Keyword search")
    sp_lookup.add_argument("--severity", type=str,
                           choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                           help="Filter by severity")
    sp_lookup.add_argument("--json", action="store_true",
                           help="Also print raw JSON output")

    # --- pipeline ---
    sp_pipeline = subparsers.add_parser("pipeline", help="Run the full pipeline")
    sp_pipeline.add_argument("--target", default="http://54.146.141.88:3000",
                             help="Target URL (default: http://54.146.141.88:3000)")
    sp_pipeline.add_argument("--api-key", type=str, default="",
                             help="Anthropic API key")
    sp_pipeline.add_argument("--repo", default="./repos/juice-shop",
                             help="Path to target repo")
    sp_pipeline.add_argument("--output", default="./deliverables",
                             help="Output directory for deliverables")
    sp_pipeline.add_argument("--retries", type=int, default=3,
                             help="Max retries per phase (default: 3)")
    sp_pipeline.add_argument("--budget", type=float, default=10.0,
                             help="Max API budget in USD (default: 10.0)")
    sp_pipeline.add_argument("--resume-from",
                             choices=["recon", "analysis", "exploit", "report"],
                             help="Resume from a specific phase")
    sp_pipeline.add_argument("--replay", action="store_true",
                             help="Use pre-recorded deliverables")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

    # Direct invocation: --target-url provided without subcommand
    if args.target_url and args.command is None:
        return cmd_direct(args)

    if args.command is None:
        parser.print_help()
        return 0

    dispatch = {
        "skills": cmd_skills,
        "validate": cmd_validate,
        "lookup": cmd_lookup,
        "pipeline": cmd_pipeline,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nAborted.")
        return 130
    except Exception as e:
        logger.error("Unhandled error: %s", e, exc_info=args.verbose)
        print(f"\nError: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
