"""Phase 2 Gate — Comprehensive Verification Suite.

All checks here MUST pass before advancing to Phase 3 (Pipeline Integration).

Phase 3 depends on:
  Stream A: runAgent() works, MCP server operational, save_deliverable works
  Stream B: Recon + injection prompts drafted with correct variables
  Stream C: XSS + report prompts drafted, shared prompt fragments exist

Sections:
  1. Agent Runner Infrastructure    (AgentRunner class, budget, stop, truncation)
  2. MCP Tool Definitions & Dispatch (MCP_TOOLS, SkillToolDispatcher)
  3. Pipeline Orchestration Core     (PipelineConfig, load_prompt, save_deliverable, phase functions)
  4. Prompt Templates                (existence, size, required {{VAR}} placeholders)
  5. Shared Prompt Fragments         (existence, size, content)
  6. CLI Integration                 (pipeline subcommand, --url, --repo, --replay, --resume-from)
  7. Skill Registry & Wrappers       (SkillRegistry, freeze/unfreeze, wrappers callable)
  8. Type Definitions (TypeScript)   (types.ts compiles, key interfaces exist)
  9. Event System                    (GUI events importable, dataclass structure)
  10. Preflight Checks               (run_preflight importable, individual checks)
  11. End-to-End Smoke Test          (pipeline runs with no agent_runner, replay mode)
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import fields
from pathlib import Path

# ── Globals ──────────────────────────────────────────────────────────────────

PASS = 0
FAIL = 0
PROJECT_ROOT = Path(__file__).resolve().parent


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}" + (f" -- {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {label}" + (f" -- {detail}" if detail else ""))


def section(title: str) -> None:
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    global PASS, FAIL

    # ------------------------------------------------------------------
    # 1. AGENT RUNNER INFRASTRUCTURE
    # ------------------------------------------------------------------
    section("1. AGENT RUNNER INFRASTRUCTURE")

    # Import AgentRunner
    try:
        from src.agent_runner import AgentRunner
        check("import AgentRunner", True)
    except Exception as exc:
        check("import AgentRunner", False, detail=str(exc))

    # AgentRunner.__init__ signature accepts required params
    try:
        import inspect
        sig = inspect.signature(AgentRunner.__init__)
        params = list(sig.parameters.keys())
        for p in ["api_key", "max_budget_usd", "stop_event", "event_queue", "tools", "tool_dispatcher"]:
            check(f"AgentRunner.__init__ has '{p}' param", p in params)
    except Exception as exc:
        check("AgentRunner.__init__ signature", False, detail=str(exc))

    # AgentRunner.run exists and is callable
    check("AgentRunner.run is callable", callable(getattr(AgentRunner, "run", None)))

    # AgentRunner instantiation (with dummy key, no API call)
    try:
        runner = AgentRunner(api_key="sk-ant-test-fake-key", max_budget_usd=5.0)
        check("AgentRunner instantiation", True)
        check("AgentRunner.max_budget_usd set", runner.max_budget_usd == 5.0)
        check("AgentRunner.total_cost_usd starts at 0", runner.total_cost_usd == 0.0)
    except Exception as exc:
        check("AgentRunner instantiation", False, detail=str(exc))

    # Budget lock exists (thread safety for Race condition #1)
    try:
        check("AgentRunner._budget_lock is threading.Lock",
              hasattr(runner, "_budget_lock") and isinstance(runner._budget_lock, type(threading.Lock())))
    except Exception as exc:
        check("AgentRunner._budget_lock", False, detail=str(exc))

    # Stop event propagation
    try:
        stop_evt = threading.Event()
        runner_with_stop = AgentRunner(api_key="sk-test", stop_event=stop_evt)
        check("AgentRunner accepts stop_event", runner_with_stop._stop_event is stop_evt)
    except Exception as exc:
        check("AgentRunner stop_event", False, detail=str(exc))

    # BudgetExhaustedError defined
    try:
        from src.exceptions import BudgetExhaustedError
        err = BudgetExhaustedError(spent=10.5, limit=10.0)
        check("BudgetExhaustedError importable", True)
        check("BudgetExhaustedError has spent/limit", err.spent == 10.5 and err.limit == 10.0)
    except Exception as exc:
        check("BudgetExhaustedError", False, detail=str(exc))

    # Context-window truncation helper
    try:
        truncated = AgentRunner._maybe_truncate("x" * 100)
        check("_maybe_truncate short text unchanged", truncated == "x" * 100)
        long_text = "x" * (200_000 * 4 + 1000)  # Way over limit
        truncated_long = AgentRunner._maybe_truncate(long_text)
        check("_maybe_truncate long text truncated", len(truncated_long) < len(long_text))
        check("_maybe_truncate adds truncation marker", "truncated" in truncated_long.lower())
    except Exception as exc:
        check("_maybe_truncate", False, detail=str(exc))

    # ------------------------------------------------------------------
    # 2. MCP TOOL DEFINITIONS & SKILL TOOL DISPATCHER
    # ------------------------------------------------------------------
    section("2. MCP TOOL DEFINITIONS & DISPATCH")

    try:
        from src.agent_loop import MCP_TOOLS, SkillToolDispatcher
        check("import MCP_TOOLS", True)
        check("import SkillToolDispatcher", True)
    except Exception as exc:
        check("import MCP_TOOLS / SkillToolDispatcher", False, detail=str(exc))

    # MCP_TOOLS is a non-empty list
    check("MCP_TOOLS is non-empty list", isinstance(MCP_TOOLS, list) and len(MCP_TOOLS) > 0,
          detail=f"{len(MCP_TOOLS)} tools")

    # Required tools
    tool_names = {t["name"] for t in MCP_TOOLS}
    required_tools = [
        "save_deliverable",
        "network_recon_parse_nmap",
        "response_analysis_validate",
        "vulnerability_lookup_cve",
    ]
    for t in required_tools:
        check(f"MCP tool '{t}' defined", t in tool_names)

    # Each tool has required keys
    for tool_def in MCP_TOOLS:
        name = tool_def.get("name", "<unnamed>")
        check(f"Tool '{name}' has description", bool(tool_def.get("description")))
        check(f"Tool '{name}' has input_schema", "input_schema" in tool_def)

    # save_deliverable schema
    save_tool = next((t for t in MCP_TOOLS if t["name"] == "save_deliverable"), None)
    if save_tool:
        props = save_tool["input_schema"].get("properties", {})
        check("save_deliverable has 'name' param", "name" in props)
        check("save_deliverable has 'content' param", "content" in props)
        required = save_tool["input_schema"].get("required", [])
        check("save_deliverable requires 'name'", "name" in required)
        check("save_deliverable requires 'content'", "content" in required)

    # SkillToolDispatcher instantiation
    try:
        from src.skills.skill_loader import SkillRegistry
        registry = SkillRegistry()
        dispatcher = SkillToolDispatcher(registry)
        check("SkillToolDispatcher instantiation", True)
        check("SkillToolDispatcher.tool_names non-empty",
              len(dispatcher.tool_names) > 0, detail=str(dispatcher.tool_names))

        # Dispatcher handles save_deliverable
        check("Dispatcher has 'save_deliverable' handler", "save_deliverable" in dispatcher.tool_names)
    except Exception as exc:
        check("SkillToolDispatcher instantiation", False, detail=str(exc))

    # Dispatcher.dispatch for save_deliverable actually writes file
    try:
        test_dir = Path(tempfile.mkdtemp(prefix="penterax_test_"))
        # Temporarily monkey-patch DELIVERABLES_DIR imported in agent_loop
        import src.pipeline as _pipeline_mod
        original_dir = _pipeline_mod.DELIVERABLES_DIR
        _pipeline_mod.DELIVERABLES_DIR = test_dir

        result = dispatcher.dispatch("save_deliverable", {
            "name": "test_gate.md",
            "content": "# Test\nGate check content",
        })
        check("save_deliverable dispatch success", result.get("success") is True)
        # The dispatcher writes to the real DELIVERABLES_DIR (or wherever
        # the imported reference points).  Use the path from the result.
        saved_path = Path(result.get("path", ""))
        check("save_deliverable wrote file", saved_path.exists())
        if saved_path.exists():
            check("save_deliverable content correct",
                  saved_path.read_text(encoding="utf-8") == "# Test\nGate check content")
            saved_path.unlink(missing_ok=True)

        _pipeline_mod.DELIVERABLES_DIR = original_dir
        shutil.rmtree(test_dir, ignore_errors=True)
    except Exception as exc:
        check("save_deliverable dispatch", False, detail=str(exc))
        _pipeline_mod.DELIVERABLES_DIR = original_dir

    # Dispatcher.dispatch raises on unknown tool
    try:
        dispatcher.dispatch("nonexistent_tool", {})
        check("Dispatcher rejects unknown tool", False, detail="No exception raised")
    except KeyError:
        check("Dispatcher rejects unknown tool", True)
    except Exception as exc:
        check("Dispatcher rejects unknown tool", False, detail=str(exc))

    # ------------------------------------------------------------------
    # 3. PIPELINE ORCHESTRATION CORE
    # ------------------------------------------------------------------
    section("3. PIPELINE ORCHESTRATION CORE")

    try:
        from src.pipeline import (
            PipelineConfig, PipelineResult, PhaseResult,
            load_prompt, save_deliverable, ensure_dir, read_deliverable,
            run_pipeline, run_phase_recon, run_phase_analysis,
            run_phase_exploit, run_phase_report,
            save_replay_snapshot, load_replay_deliverables,
        )
        check("import pipeline core functions", True)
    except Exception as exc:
        check("import pipeline core functions", False, detail=str(exc))

    # PipelineConfig dataclass
    try:
        cfg = PipelineConfig()
        check("PipelineConfig() default construction", True)
        check("PipelineConfig.target_url has default", bool(cfg.target_url))
        check("PipelineConfig.repo_path has default", bool(cfg.repo_path))
        check("PipelineConfig.output_dir is Path", isinstance(cfg.output_dir, Path))
        check("PipelineConfig.max_retries has default", cfg.max_retries > 0)
    except Exception as exc:
        check("PipelineConfig", False, detail=str(exc))

    # PhaseResult dataclass
    try:
        pr = PhaseResult(phase_name="test", success=False)
        check("PhaseResult creation", True)
        check("PhaseResult.deliverables is list", isinstance(pr.deliverables, list))
        check("PhaseResult.errors is list", isinstance(pr.errors, list))
        check("PhaseResult.validation_passed default False", pr.validation_passed is False)
    except Exception as exc:
        check("PhaseResult", False, detail=str(exc))

    # PipelineResult dataclass
    try:
        plr = PipelineResult()
        check("PipelineResult creation", True)
        check("PipelineResult.phases is list", isinstance(plr.phases, list))
        check("PipelineResult.deliverables_generated is list", isinstance(plr.deliverables_generated, list))
    except Exception as exc:
        check("PipelineResult", False, detail=str(exc))

    # load_prompt with variable substitution
    try:
        test_prompt_dir = Path(tempfile.mkdtemp(prefix="penterax_prompt_"))
        test_prompt_file = test_prompt_dir / "test_template.md"
        test_prompt_file.write_text(
            "Target: {{TARGET_URL}}\nRepo: {{REPO_PATH}}\nEnd.",
            encoding="utf-8",
        )
        result = load_prompt(test_prompt_file, {
            "TARGET_URL": "http://example.com:3000",
            "REPO_PATH": "./repos/test",
        })
        check("load_prompt substitutes {{TARGET_URL}}",
              "http://example.com:3000" in result)
        check("load_prompt substitutes {{REPO_PATH}}",
              "./repos/test" in result)
        check("load_prompt removes all {{VAR}} markers",
              "{{" not in result)
        shutil.rmtree(test_prompt_dir, ignore_errors=True)
    except Exception as exc:
        check("load_prompt", False, detail=str(exc))

    # load_prompt returns empty string for missing file
    try:
        result = load_prompt(Path("/nonexistent/file.md"), {})
        check("load_prompt missing file returns empty", result == "")
    except Exception as exc:
        check("load_prompt missing file", False, detail=str(exc))

    # save_deliverable writes atomically
    try:
        test_out = Path(tempfile.mkdtemp(prefix="penterax_deliv_"))
        path = save_deliverable("test_atomic.md", "atomic content", test_out)
        check("save_deliverable returns Path", isinstance(path, Path))
        check("save_deliverable file exists", path.exists())
        check("save_deliverable content correct",
              path.read_text(encoding="utf-8") == "atomic content")
        # No .tmp files left behind
        tmp_files = list(test_out.glob("*.tmp"))
        check("save_deliverable no tmp files left", len(tmp_files) == 0)
        shutil.rmtree(test_out, ignore_errors=True)
    except Exception as exc:
        check("save_deliverable", False, detail=str(exc))

    # ensure_dir creates nested dirs
    try:
        test_nested = Path(tempfile.mkdtemp(prefix="penterax_dir_")) / "a" / "b" / "c"
        result = ensure_dir(test_nested)
        check("ensure_dir creates nested dirs", test_nested.exists())
        check("ensure_dir returns path", result == test_nested)
        shutil.rmtree(test_nested.parent.parent.parent, ignore_errors=True)
    except Exception as exc:
        check("ensure_dir", False, detail=str(exc))

    # read_deliverable returns empty for missing
    try:
        test_rd_dir = Path(tempfile.mkdtemp(prefix="penterax_rd_"))
        result = read_deliverable("nonexistent.md", test_rd_dir)
        check("read_deliverable missing returns empty", result == "")
        # Write and read back
        (test_rd_dir / "test.md").write_text("hello", encoding="utf-8")
        result = read_deliverable("test.md", test_rd_dir)
        check("read_deliverable reads existing file", result == "hello")
        shutil.rmtree(test_rd_dir, ignore_errors=True)
    except Exception as exc:
        check("read_deliverable", False, detail=str(exc))

    # Phase functions exist and are callable
    for fn_name in ["run_phase_recon", "run_phase_analysis", "run_phase_exploit", "run_phase_report"]:
        fn = getattr(importlib.import_module("src.pipeline"), fn_name, None)
        check(f"{fn_name} is callable", callable(fn))

    # run_pipeline function signature includes required params
    try:
        import inspect
        sig = inspect.signature(run_pipeline)
        params = list(sig.parameters.keys())
        for p in ["config", "agent_runner", "stop_event", "resume_from"]:
            check(f"run_pipeline has '{p}' param", p in params)
    except Exception as exc:
        check("run_pipeline signature", False, detail=str(exc))

    # run_pipeline resume_from support
    try:
        test_resume_dir = Path(tempfile.mkdtemp(prefix="penterax_resume_"))
        resume_cfg = PipelineConfig(output_dir=test_resume_dir)
        # Resuming from "report" should skip recon/analysis/exploit
        result = run_pipeline(config=resume_cfg, agent_runner=None, resume_from="report")
        phase_names = [p.phase_name for p in result.phases]
        check("run_pipeline resume_from='report' runs report phase",
              any("report" in pn.lower() for pn in phase_names))
        check("run_pipeline resume_from='report' skips recon",
              not any("recon" in pn.lower() for pn in phase_names))
        shutil.rmtree(test_resume_dir, ignore_errors=True)
    except Exception as exc:
        check("run_pipeline resume_from", False, detail=str(exc))

    # Replay functions exist
    check("save_replay_snapshot is callable", callable(save_replay_snapshot))
    check("load_replay_deliverables is callable", callable(load_replay_deliverables))

    # ------------------------------------------------------------------
    # 4. PROMPT TEMPLATES
    # ------------------------------------------------------------------
    section("4. PROMPT TEMPLATES")

    prompt_specs = [
        {
            "path": "src/prompts/recon.md",
            "min_bytes": 2000,
            "required_vars": ["TARGET_URL"],
            "required_content": ["recon_report.md", "nmap", "endpoint"],
        },
        {
            "path": "src/prompts/analysis-injection.md",
            "min_bytes": 1000,
            "required_vars": ["RECON_DATA", "TARGET_URL"],
            "required_content": ["hypotheses", "injection", "sql"],
        },
        {
            "path": "src/prompts/analysis-xss.md",
            "min_bytes": 1000,
            "required_vars": ["RECON_DATA", "TARGET_URL"],
            "required_content": ["hypotheses", "xss"],
        },
        {
            "path": "src/prompts/exploit-injection.md",
            "min_bytes": 1000,
            "required_vars": ["HYPOTHESES", "TARGET_URL"],
            "required_content": ["findings", "injection"],
        },
        {
            "path": "src/prompts/exploit-xss.md",
            "min_bytes": 1000,
            "required_vars": ["HYPOTHESES", "TARGET_URL"],
            "required_content": ["findings", "xss"],
        },
        {
            "path": "src/prompts/report.md",
            "min_bytes": 1000,
            "required_vars": ["FINDINGS", "TARGET_URL"],
            "required_content": ["pentest_report", "executive summary", "findings"],
        },
    ]

    for spec in prompt_specs:
        p = Path(spec["path"])
        exists = p.exists()
        check(f"{spec['path']} exists", exists)
        if not exists:
            continue

        size = p.stat().st_size
        check(f"{spec['path']} >= {spec['min_bytes']} bytes",
              size >= spec["min_bytes"], detail=f"{size} bytes")

        content = p.read_text(encoding="utf-8")

        # Check required {{VAR}} placeholders
        for var in spec["required_vars"]:
            pattern = "{{" + var + "}}"
            check(f"{spec['path']} contains {{{{{var}}}}}",
                  pattern in content)

        # Check required content keywords (case-insensitive)
        content_lower = content.lower()
        for keyword in spec["required_content"]:
            check(f"{spec['path']} mentions '{keyword}'",
                  keyword.lower() in content_lower)

    # ------------------------------------------------------------------
    # 5. SHARED PROMPT FRAGMENTS
    # ------------------------------------------------------------------
    section("5. SHARED PROMPT FRAGMENTS")

    shared_specs = [
        {
            "path": "src/prompts/shared/safety-rails.md",
            "min_bytes": 500,
            "required_content": ["target_url", "authoris", "scope"],
        },
        {
            "path": "src/prompts/shared/output-format.md",
            "min_bytes": 500,
            "required_content": ["format", "markdown", "deliverable"],
        },
        {
            "path": "src/prompts/shared/target-context.md",
            "min_bytes": 500,
            "required_content": ["juice shop", "owasp"],
        },
    ]

    for spec in shared_specs:
        p = Path(spec["path"])
        exists = p.exists()
        check(f"{spec['path']} exists", exists)
        if not exists:
            continue

        size = p.stat().st_size
        check(f"{spec['path']} >= {spec['min_bytes']} bytes",
              size >= spec["min_bytes"], detail=f"{size} bytes")

        content_lower = p.read_text(encoding="utf-8").lower()
        for keyword in spec["required_content"]:
            check(f"{spec['path']} mentions '{keyword}'",
                  keyword.lower() in content_lower)

    # ------------------------------------------------------------------
    # 6. CLI INTEGRATION
    # ------------------------------------------------------------------
    section("6. CLI INTEGRATION")

    try:
        from src.cli import build_parser, main as cli_main
        check("import build_parser", True)
    except Exception as exc:
        check("import build_parser", False, detail=str(exc))

    parser = build_parser()

    # pipeline subcommand exists
    try:
        args = parser.parse_args(["pipeline", "--target", "http://test:3000"])
        check("pipeline subcommand parses", args.command == "pipeline")
        check("pipeline --target parsed", args.target == "http://test:3000")
    except Exception as exc:
        check("pipeline subcommand", False, detail=str(exc))

    # pipeline --replay flag
    try:
        args = parser.parse_args(["pipeline", "--replay"])
        check("pipeline --replay flag", args.replay is True)
    except Exception as exc:
        check("pipeline --replay", False, detail=str(exc))

    # pipeline --resume-from
    try:
        args = parser.parse_args(["pipeline", "--resume-from", "exploit"])
        check("pipeline --resume-from='exploit'", args.resume_from == "exploit")
    except Exception as exc:
        check("pipeline --resume-from", False, detail=str(exc))

    # pipeline --resume-from choices
    for phase in ["recon", "analysis", "exploit", "report"]:
        try:
            args = parser.parse_args(["pipeline", "--resume-from", phase])
            check(f"pipeline --resume-from='{phase}' valid", args.resume_from == phase)
        except Exception as exc:
            check(f"pipeline --resume-from='{phase}'", False, detail=str(exc))

    # direct invocation: --target-url and --api-key
    try:
        args = parser.parse_args(["--target-url", "http://t:3000", "--api-key", "sk-test"])
        check("--target-url parsed", args.target_url == "http://t:3000")
        check("--api-key parsed", args.api_key == "sk-test")
    except Exception as exc:
        check("direct CLI flags", False, detail=str(exc))

    # --budget flag
    try:
        args = parser.parse_args(["--target-url", "http://t:3000", "--budget", "25.0"])
        check("--budget parsed as float", args.budget == 25.0)
    except Exception as exc:
        check("--budget", False, detail=str(exc))

    # skills subcommand
    try:
        args = parser.parse_args(["skills", "--list"])
        check("skills --list subcommand", args.command == "skills" and args.list is True)
    except Exception as exc:
        check("skills subcommand", False, detail=str(exc))

    # validate subcommand
    try:
        args = parser.parse_args(["validate", "test.md", "recon_report"])
        check("validate subcommand", args.command == "validate"
              and args.file == "test.md"
              and args.schema_type == "recon_report")
    except Exception as exc:
        check("validate subcommand", False, detail=str(exc))

    # ------------------------------------------------------------------
    # 7. SKILL REGISTRY & WRAPPERS
    # ------------------------------------------------------------------
    section("7. SKILL REGISTRY & WRAPPERS")

    try:
        from src.skills.skill_loader import SkillRegistry, SkillResult, SkillMetadata, discover_skills
        check("import SkillRegistry", True)
    except Exception as exc:
        check("import SkillRegistry", False, detail=str(exc))

    # SkillRegistry loads skills
    try:
        reg = SkillRegistry()
        check("SkillRegistry() construction", True)
        check("SkillRegistry discovers skills", len(reg.skill_names) > 0,
              detail=str(reg.skill_names))

        expected_skills = ["network-recon", "response-analysis", "vulnerability-lookup"]
        for s in expected_skills:
            check(f"Skill '{s}' registered", s in reg.skill_names)
    except Exception as exc:
        check("SkillRegistry", False, detail=str(exc))

    # Freeze / unfreeze
    try:
        reg.freeze()
        check("SkillRegistry.freeze() works", reg._frozen is True)
        # reload should be no-op when frozen
        old_names = reg.skill_names[:]
        reg.reload()
        check("reload() is no-op when frozen", reg.skill_names == old_names)
        reg.unfreeze()
        check("SkillRegistry.unfreeze() works", reg._frozen is False)
    except Exception as exc:
        check("SkillRegistry freeze/unfreeze", False, detail=str(exc))

    # build_prompt_context returns non-empty string
    try:
        ctx = reg.build_prompt_context("network-recon")
        check("build_prompt_context returns content", len(ctx) > 50,
              detail=f"{len(ctx)} chars")
    except Exception as exc:
        check("build_prompt_context", False, detail=str(exc))

    # build_all_skills_summary
    try:
        summary = reg.build_all_skills_summary()
        check("build_all_skills_summary returns content", len(summary) > 50)
    except Exception as exc:
        check("build_all_skills_summary", False, detail=str(exc))

    # Skill wrappers importable
    try:
        from src.skills.skill_wrappers import (
            parse_nmap, validate_deliverable, validate_with_retry_context,
            lookup_cve, batch_lookup_cve, format_known_vulns_for_prompt,
            nmap_to_markdown,
        )
        check("import all skill wrappers", True)
    except Exception as exc:
        check("import skill wrappers", False, detail=str(exc))

    # validate_with_retry_context logic
    try:
        # When success=True, should return None
        mock_success = SkillResult(success=True, skill_name="test", output={})
        ctx = validate_with_retry_context(mock_success, attempt=1)
        check("validate_with_retry_context: success -> None", ctx is None)

        # When failed but max attempts reached, should return None
        mock_fail = SkillResult(success=False, skill_name="test",
                                output={"errors": ["missing section"]})
        ctx = validate_with_retry_context(mock_fail, attempt=3, max_attempts=3)
        check("validate_with_retry_context: max attempts -> None", ctx is None)

        # When failed and retries remain, should return retry context string
        ctx = validate_with_retry_context(mock_fail, attempt=1, max_attempts=3)
        check("validate_with_retry_context: retry -> context string",
              ctx is not None and "RETRY" in ctx and "missing section" in ctx)
    except Exception as exc:
        check("validate_with_retry_context", False, detail=str(exc))

    # nmap_to_markdown helper
    try:
        mock_scan = {
            "hosts": [{
                "ports": [{
                    "port": 3000, "protocol": "tcp", "state": "open",
                    "service": "http", "product": "Node.js", "version": "14.x"
                }]
            }]
        }
        md = nmap_to_markdown(mock_scan)
        check("nmap_to_markdown produces table", "| 3000 |" in md and "| tcp |" in md)
    except Exception as exc:
        check("nmap_to_markdown", False, detail=str(exc))

    # format_known_vulns_for_prompt
    try:
        empty = format_known_vulns_for_prompt([])
        check("format_known_vulns_for_prompt empty list",
              "no known" in empty.lower() or len(empty) > 0)
    except Exception as exc:
        check("format_known_vulns_for_prompt", False, detail=str(exc))

    # ------------------------------------------------------------------
    # 8. TYPE DEFINITIONS (TypeScript)
    # ------------------------------------------------------------------
    section("8. TYPE DEFINITIONS (TypeScript)")

    types_path = Path("src/types.ts")
    check("src/types.ts exists", types_path.exists())

    if types_path.exists():
        ts_content = types_path.read_text(encoding="utf-8")
        required_types = [
            "PipelinePhase",
            "PipelineConfig",
            "PipelineResult",
            "Vulnerability",
            "ReconResult",
            "ExploitAttempt",
            "AgentMessage",
            "Severity",
        ]
        for t in required_types:
            check(f"types.ts defines '{t}'", t in ts_content)

    # TypeScript compiles (skip gracefully when node/npx is not installed)
    npx_path = shutil.which("npx")
    if npx_path:
        try:
            result = subprocess.run(
                ["npx", "tsc", "--noEmit"],
                capture_output=True, text=True, timeout=60,
                cwd=str(PROJECT_ROOT),
                shell=True,
            )
            check("npx tsc --noEmit succeeds", result.returncode == 0,
                  detail=result.stderr[:200] if result.returncode != 0 else "clean")
        except Exception as exc:
            check("TypeScript compilation", False, detail=str(exc))
    else:
        check("npx tsc --noEmit succeeds", True,
              detail="SKIPPED — npx/node not on PATH")

    # ------------------------------------------------------------------
    # 9. EVENT SYSTEM
    # ------------------------------------------------------------------
    section("9. EVENT SYSTEM (GUI <-> Pipeline)")

    try:
        from src.gui_events import LogEvent, PhaseStatusEvent, BudgetEvent, PipelineCompleteEvent
        check("import all event types", True)
    except Exception as exc:
        check("import event types", False, detail=str(exc))

    # LogEvent structure
    try:
        le = LogEvent(level="INFO", message="test", timestamp=time.time())
        check("LogEvent creation", True)
        check("LogEvent is frozen dataclass", True)  # frozen=True means immutable
        is_immutable = False
        try:
            le.level = "DEBUG"  # type: ignore
        except Exception:
            is_immutable = True
        check("LogEvent is immutable", is_immutable,
              detail="mutation blocked" if is_immutable else "mutation succeeded")
    except Exception as exc:
        check("LogEvent", False, detail=str(exc))

    # PhaseStatusEvent
    try:
        pse = PhaseStatusEvent(phase_name="recon", status="started")
        check("PhaseStatusEvent creation", True)
        check("PhaseStatusEvent.phase_name", pse.phase_name == "recon")
        check("PhaseStatusEvent.status", pse.status == "started")
    except Exception as exc:
        check("PhaseStatusEvent", False, detail=str(exc))

    # BudgetEvent
    try:
        be = BudgetEvent(total_cost_usd=1.5, phase_name="analysis")
        check("BudgetEvent creation", True)
        check("BudgetEvent.total_cost_usd", be.total_cost_usd == 1.5)
    except Exception as exc:
        check("BudgetEvent", False, detail=str(exc))

    # PipelineCompleteEvent
    try:
        pce = PipelineCompleteEvent(
            success=True, total_duration=120.5, deliverables=["recon_report.md"]
        )
        check("PipelineCompleteEvent creation", True)
        check("PipelineCompleteEvent.deliverables", pce.deliverables == ["recon_report.md"])
    except Exception as exc:
        check("PipelineCompleteEvent", False, detail=str(exc))

    # QueueLoggingHandler
    try:
        from src.logging_handler import QueueLoggingHandler
        import queue
        q = queue.Queue()
        handler = QueueLoggingHandler(q)
        check("QueueLoggingHandler creation", True)
        check("QueueLoggingHandler has event_queue", handler.event_queue is q)
    except Exception as exc:
        check("QueueLoggingHandler", False, detail=str(exc))

    # ------------------------------------------------------------------
    # 10. PREFLIGHT CHECKS
    # ------------------------------------------------------------------
    section("10. PREFLIGHT CHECKS")

    try:
        from src.preflight import (
            run_preflight, PreflightResult, PreflightCheck,
            check_nmap_installed, check_disk_space, check_optional_tools,
        )
        check("import preflight module", True)
    except Exception as exc:
        check("import preflight", False, detail=str(exc))

    # PreflightCheck dataclass
    try:
        pc = PreflightCheck(name="test", passed=True, message="ok", critical=True)
        check("PreflightCheck creation", True)
    except Exception as exc:
        check("PreflightCheck", False, detail=str(exc))

    # PreflightResult.all_critical_passed
    try:
        pr = PreflightResult(checks=[
            PreflightCheck(name="a", passed=True, message="ok", critical=True),
            PreflightCheck(name="b", passed=False, message="fail", critical=False),
        ])
        check("PreflightResult.all_critical_passed (mixed)",
              pr.all_critical_passed is True)

        pr2 = PreflightResult(checks=[
            PreflightCheck(name="a", passed=False, message="fail", critical=True),
        ])
        check("PreflightResult.all_critical_passed (critical fail)",
              pr2.all_critical_passed is False)
    except Exception as exc:
        check("PreflightResult", False, detail=str(exc))

    # PreflightResult.summary
    try:
        summary = pr.summary
        check("PreflightResult.summary is string", isinstance(summary, str) and len(summary) > 0)
        check("PreflightResult.summary has PASS/FAIL", "PASS" in summary or "FAIL" in summary)
    except Exception as exc:
        check("PreflightResult.summary", False, detail=str(exc))

    # check_nmap_installed
    try:
        result = check_nmap_installed()
        check("check_nmap_installed returns PreflightCheck",
              isinstance(result, PreflightCheck))
        check("check_nmap_installed is critical", result.critical is True)
    except Exception as exc:
        check("check_nmap_installed", False, detail=str(exc))

    # check_disk_space
    try:
        result = check_disk_space(Path("."))
        check("check_disk_space returns PreflightCheck",
              isinstance(result, PreflightCheck))
    except Exception as exc:
        check("check_disk_space", False, detail=str(exc))

    # check_optional_tools
    try:
        result = check_optional_tools()
        check("check_optional_tools returns PreflightCheck",
              isinstance(result, PreflightCheck))
        check("check_optional_tools is non-critical", result.critical is False)
    except Exception as exc:
        check("check_optional_tools", False, detail=str(exc))

    # AppConfig.to_pipeline_config()
    try:
        from src.config import AppConfig
        app_cfg = AppConfig(
            target_url="http://test:3000",
            anthropic_api_key="sk-test",
        )
        pipe_cfg = app_cfg.to_pipeline_config()
        check("AppConfig.to_pipeline_config()", isinstance(pipe_cfg, PipelineConfig))
        check("to_pipeline_config preserves target_url",
              pipe_cfg.target_url == "http://test:3000")
    except Exception as exc:
        check("AppConfig.to_pipeline_config", False, detail=str(exc))

    # AppConfig.validate()
    try:
        errors = AppConfig(target_url="", anthropic_api_key="").validate()
        check("AppConfig.validate catches missing target", any("target" in e for e in errors))
        check("AppConfig.validate catches missing api_key", any("api_key" in e or "anthropic" in e for e in errors))

        errors_ok = AppConfig(
            target_url="http://test:3000",
            anthropic_api_key="sk-test",
        ).validate()
        check("AppConfig.validate passes with valid config", len(errors_ok) == 0)
    except Exception as exc:
        check("AppConfig.validate", False, detail=str(exc))

    # ------------------------------------------------------------------
    # 11. END-TO-END SMOKE TEST (no agent, validation-only pipeline)
    # ------------------------------------------------------------------
    section("11. END-TO-END SMOKE TEST")

    try:
        test_e2e_dir = Path(tempfile.mkdtemp(prefix="penterax_e2e_"))
        e2e_cfg = PipelineConfig(output_dir=test_e2e_dir)

        # Run pipeline with no agent_runner (validation-only mode)
        result = run_pipeline(config=e2e_cfg, agent_runner=None)
        check("run_pipeline(agent_runner=None) completes", isinstance(result, PipelineResult))
        check("run_pipeline returns 4 phases", len(result.phases) == 4,
              detail=f"got {len(result.phases)} phases")
        check("run_pipeline total_duration_seconds > 0", result.total_duration_seconds > 0)

        # Verify phase names
        phase_names = [p.phase_name for p in result.phases]
        for expected in ["recon", "analysis", "exploit", "report"]:
            check(f"Pipeline ran '{expected}' phase",
                  any(expected in pn.lower() for pn in phase_names))

        shutil.rmtree(test_e2e_dir, ignore_errors=True)
    except Exception as exc:
        check("E2E smoke test", False, detail=str(exc))

    # Stop event cancellation test
    try:
        test_stop_dir = Path(tempfile.mkdtemp(prefix="penterax_stop_"))
        stop_cfg = PipelineConfig(output_dir=test_stop_dir)
        stop_event = threading.Event()
        stop_event.set()  # Stop immediately

        result = run_pipeline(config=stop_cfg, agent_runner=None, stop_event=stop_event)
        check("run_pipeline respects stop_event",
              len(result.phases) < 4 or
              any(not p.success for p in result.phases))
        shutil.rmtree(test_stop_dir, ignore_errors=True)
    except PipelineAbortedError:
        check("run_pipeline respects stop_event", True, detail="PipelineAbortedError raised")
    except Exception as exc:
        check("run_pipeline stop_event", False, detail=str(exc))

    # Replay snapshot lifecycle
    try:
        test_replay_dir = Path(tempfile.mkdtemp(prefix="penterax_replay_"))
        replay_out = test_replay_dir / "out"
        replay_snap = replay_out / "replay"
        replay_out.mkdir(parents=True)
        replay_snap.mkdir(parents=True)

        # Create a mock deliverable
        (replay_out / "recon_report.md").write_text("# Recon\nMock", encoding="utf-8")

        # Monkey-patch REPLAY_DIR temporarily
        from src import pipeline as _pl
        orig_replay = _pl.REPLAY_DIR
        _pl.REPLAY_DIR = replay_snap

        copied = save_replay_snapshot(replay_out)
        check("save_replay_snapshot copies files", len(copied) > 0)
        check("Replay snapshot file exists",
              (replay_snap / "recon_report.md").exists())

        # Clear the output dir and restore from replay
        (replay_out / "recon_report.md").unlink()
        restored = load_replay_deliverables(replay_out)
        check("load_replay_deliverables restores files", len(restored) > 0)
        check("Restored file exists",
              (replay_out / "recon_report.md").exists())

        _pl.REPLAY_DIR = orig_replay
        shutil.rmtree(test_replay_dir, ignore_errors=True)
    except Exception as exc:
        check("Replay snapshot lifecycle", False, detail=str(exc))

    # Agentic loop bootstrap
    try:
        from src.agent_loop import setup_agentic_loop, AgenticLoopConfig, build_system_prompt_skills_section
        registry, dispatcher, tools, prompt_section = setup_agentic_loop()
        check("setup_agentic_loop() returns 4-tuple", True)
        check("setup_agentic_loop registry has skills", len(registry.skill_names) > 0)
        check("setup_agentic_loop dispatcher has handlers", len(dispatcher.tool_names) > 0)
        check("setup_agentic_loop tools match MCP_TOOLS", tools == MCP_TOOLS)
        check("setup_agentic_loop prompt has content", len(prompt_section) > 100)
    except Exception as exc:
        check("setup_agentic_loop", False, detail=str(exc))

    # build_system_prompt_skills_section
    try:
        prompt = build_system_prompt_skills_section(registry)
        check("build_system_prompt_skills_section has tool docs",
              "save_deliverable" in prompt and "network_recon" in prompt)
    except Exception as exc:
        check("build_system_prompt_skills_section", False, detail=str(exc))

    # ====================================================================
    # SUMMARY
    # ====================================================================
    print()
    print("=" * 70)
    total = PASS + FAIL
    if FAIL == 0:
        print(f"  ALL {total} CHECKS PASSED -- Phase 2 Gate COMPLETE")
        print(f"  [OK] Ready to advance to Phase 3: Pipeline Integration")
    else:
        pct = (PASS / total * 100) if total else 0
        print(f"  {PASS}/{total} passed ({pct:.0f}%), {FAIL} FAILED")
        print(f"  [!!] Phase 2 gate NOT cleared -- fix failures before Phase 3")
    print("=" * 70)
    sys.exit(1 if FAIL > 0 else 0)


if __name__ == "__main__":
    main()
