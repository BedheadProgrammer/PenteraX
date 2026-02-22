"""CLI entrypoint for the SPAIDER Agent pipeline.

Subcommands:
    python -m src pipeline       — Run the full 4-phase pipeline
    python -m src skills --list  — List discovered skills
    python -m src skills --setup — Verify skill directories and dependencies
    python -m src skills --test <name> — Run a quick test of a skill
    python -m src validate <file> <schema_type> — Validate a deliverable
    python -m src lookup --product <p> --version <v> — CVE lookup
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .skills.skill_loader import SkillRegistry, PROJECT_ROOT, SKILLS_DIR
from .skills.skill_wrappers import (
    parse_nmap,
    validate_deliverable,
    lookup_cve,
    format_known_vulns_for_prompt,
)
from .pipeline import run_pipeline, PipelineConfig
from .agent_loop import setup_agentic_loop, AgenticLoopConfig

logger = logging.getLogger("spaider.cli")


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


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
    """Handle the ``pipeline`` subcommand."""
    config = PipelineConfig(
        target_url=args.target,
        repo_path=args.repo,
        output_dir=Path(args.output),
        max_retries=args.retries,
        verbose=args.verbose,
    )

    print(f"Starting SPAIDER pipeline")
    print(f"  Target:  {config.target_url}")
    print(f"  Repo:    {config.repo_path}")
    print(f"  Output:  {config.output_dir}")
    print(f"  Retries: {config.max_retries}")
    print()

    # No agent_runner — the pipeline validates existing deliverables
    # or skips agent execution phases
    result = run_pipeline(config=config)

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

    return 0 if all(p.success for p in result.phases) else 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spaider",
        description="SPAIDER Agent — Agentic Cybersecurity Pipeline",
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")

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
    sp_pipeline.add_argument("--target", default="http://localhost:3000",
                             help="Target URL (default: http://localhost:3000)")
    sp_pipeline.add_argument("--repo", default="./repos/juice-shop",
                             help="Path to target repo")
    sp_pipeline.add_argument("--output", default="./deliverables",
                             help="Output directory for deliverables")
    sp_pipeline.add_argument("--retries", type=int, default=3,
                             help="Max retries per phase (default: 3)")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

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
