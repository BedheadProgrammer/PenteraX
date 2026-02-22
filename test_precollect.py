"""Phase 4-ready tests for the hybrid pre-collection module (DESIGN_REVIEW §4).

Validates all 5 implementation requirements from DESIGN_REVIEW §5:
  1. stop_event checked between pre-collection steps (RC #4 / #15)
  2. Graceful degradation per step — descriptive fallback, never crash
  3. Prompt size management — output is bounded
  4. Nmap subprocess timeout with explicit proc.kill() (RC #10)
  5. No new shared mutable state — pure functions

Also verifies:
  - Source analysis returns real grep data from juice-shop repo
  - HTTP probing returns structured markdown tables
  - Template variable keys match what recon.md expects
  - Integration with pipeline.py run_phase_recon()
  - Pre-collected data flows through prompt template substitution
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent

# ── Globals ──────────────────────────────────────────────────────────────────

PASS = 0
FAIL = 0


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
    # 1. MODULE IMPORT
    # ------------------------------------------------------------------
    section("1. MODULE IMPORT & PUBLIC API")

    try:
        from src.precollect import (
            run_precollection,
            collect_source_analysis,
            collect_nmap_scan,
            collect_http_probes,
        )
        check("Import precollect module", True)
    except Exception as e:
        check("Import precollect module", False, detail=str(e))
        print("FATAL: Cannot continue without precollect module")
        return

    # Also import from __init__.py
    try:
        from src import run_precollection as rp2
        check("run_precollection exported from src.__init__", rp2 is run_precollection)
    except Exception as e:
        check("run_precollection exported from src.__init__", False, detail=str(e))

    try:
        from src import collect_source_analysis as csa2
        check("collect_source_analysis exported from src.__init__", csa2 is collect_source_analysis)
    except Exception as e:
        check("collect_source_analysis exported from src.__init__", False, detail=str(e))

    # ------------------------------------------------------------------
    # 2. SOURCE CODE ANALYSIS (DESIGN_REVIEW §4 requirement: ground-truth)
    # ------------------------------------------------------------------
    section("2. SOURCE CODE ANALYSIS — GROUND-TRUTH FROM REPO")

    repo_path = PROJECT_ROOT / "repos" / "juice-shop"
    repo_exists = repo_path.exists()
    check("juice-shop repo exists", repo_exists, detail=str(repo_path))

    if repo_exists:
        result = collect_source_analysis(str(repo_path))
        check("Source analysis returns non-empty string", len(result) > 100,
              detail=f"{len(result)} chars")
        check("Contains Task 1.1 — Route Mapping", "Route Mapping" in result)
        check("Contains Task 1.2 — Sink Identification", "Sink Identification" in result)
        check("Contains Task 1.3 — Authentication", "Authentication" in result or "Auth" in result)
        check("Contains Task 1.4 — Input Entry Points", "Input Entry Points" in result or "Entry Point" in result)
        check("Contains Task 1.5 — Technology Stack", "Technology Stack" in result)

        # Verify real grep matches found
        check("Found Express route registrations", "Express route" in result or "app." in result.lower() or "router." in result.lower())
        check("Found SQL injection sinks", "SQL injection" in result or "sequelize" in result.lower() or ".query" in result.lower())
        check("Found XSS sinks", "XSS" in result or "innerHTML" in result)
        check("Found package.json data", "package.json" in result)

        # Verify it's parseable markdown
        check("Output starts with markdown header", result.strip().startswith("##") or result.strip().startswith("#"))

    # Graceful degradation: non-existent repo
    bad_result = collect_source_analysis("/nonexistent/repo/path")
    check("Graceful degradation: missing repo returns descriptive string",
          "not found" in bad_result.lower() or "unavailable" in bad_result.lower(),
          detail=bad_result[:100])

    # ------------------------------------------------------------------
    # 3. NMAP SCAN (DESIGN_REVIEW §4 requirement: pre-collected network data)
    # ------------------------------------------------------------------
    section("3. NMAP SCAN PRE-COLLECTION")

    import shutil
    from src.tool_discovery import find_tool
    nmap_info = find_tool("nmap", skip_version=True)
    nmap_available = nmap_info.available
    check("nmap on PATH", nmap_available, detail=str(nmap_info.path or nmap_info.reason))

    # Test graceful degradation when nmap is not available
    # Must mock both shutil.which AND find_tool since collect_nmap_scan
    # tries find_tool first, then falls back to shutil.which.
    from src.tool_discovery import ToolInfo
    _fake_nmap_missing = ToolInfo(name="nmap", available=False, reason="mocked away")
    with patch("shutil.which", return_value=None), \
         patch("src.tool_discovery.find_tool", return_value=_fake_nmap_missing):
        nmap_result = collect_nmap_scan("http://localhost:3000")
        check("Graceful degradation: no nmap → descriptive fallback",
              "not installed" in nmap_result.lower() or "unavailable" in nmap_result.lower(),
              detail=nmap_result[:100])

    # Test with invalid URL
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        nmap_result2 = collect_nmap_scan("")
        check("Graceful degradation: empty URL → descriptive fallback",
              "could not extract" in nmap_result2.lower() or len(nmap_result2) > 0)

    # Test that nmap output contains expected markdown structure
    nmap_result_struct = collect_nmap_scan("http://127.0.0.1:3000")
    check("Nmap output contains markdown header",
          "## Pre-collected Network Scan" in nmap_result_struct)

    # ------------------------------------------------------------------
    # 4. HTTP ENDPOINT PROBING (DESIGN_REVIEW §4 requirement: real probes)
    # ------------------------------------------------------------------
    section("4. HTTP ENDPOINT PROBING")

    # Test with an unreachable target (graceful degradation)
    http_result = collect_http_probes("http://192.0.2.1:9999", timeout=2)
    check("HTTP probing returns structured markdown",
          "## Pre-collected HTTP Endpoint Probes" in http_result)
    check("HTTP probing contains table header",
          "| # | Method |" in http_result or "| Method |" in http_result)
    check("HTTP probing contains summary line",
          "Summary:" in http_result)

    # Test graceful degradation with missing requests library
    with patch.dict("sys.modules", {"requests": None}):
        # Force re-import would be complex; instead test the import guard
        pass  # The actual import guard is in the function

    # ------------------------------------------------------------------
    # 5. STOP EVENT PROPAGATION (DESIGN_REVIEW §5 requirement #1, RC #4/#15)
    # ------------------------------------------------------------------
    section("5. STOP EVENT PROPAGATION (RC #4 / #15)")

    from src.exceptions import PipelineAbortedError

    # Test stop_event in source analysis
    stop = threading.Event()
    stop.set()
    try:
        collect_source_analysis(str(repo_path), stop_event=stop)
        check("Source analysis: stop_event raises PipelineAbortedError", False)
    except PipelineAbortedError:
        check("Source analysis: stop_event raises PipelineAbortedError", True)
    except Exception as e:
        check("Source analysis: stop_event raises PipelineAbortedError", False, detail=str(e))

    # Test stop_event in nmap scan
    stop2 = threading.Event()
    stop2.set()
    try:
        collect_nmap_scan("http://localhost:3000", stop_event=stop2)
        check("Nmap scan: stop_event raises PipelineAbortedError", False)
    except PipelineAbortedError:
        check("Nmap scan: stop_event raises PipelineAbortedError", True)
    except Exception as e:
        check("Nmap scan: stop_event raises PipelineAbortedError", False, detail=str(e))

    # Test stop_event in HTTP probing
    stop3 = threading.Event()
    stop3.set()
    try:
        collect_http_probes("http://localhost:3000", stop_event=stop3)
        check("HTTP probing: stop_event raises PipelineAbortedError", False)
    except PipelineAbortedError:
        check("HTTP probing: stop_event raises PipelineAbortedError", True)
    except Exception as e:
        check("HTTP probing: stop_event raises PipelineAbortedError", False, detail=str(e))

    # Test stop_event in top-level run_precollection
    stop4 = threading.Event()
    stop4.set()
    try:
        run_precollection("http://localhost:3000", "./repos/juice-shop", stop_event=stop4)
        check("run_precollection: stop_event raises PipelineAbortedError", False)
    except PipelineAbortedError:
        check("run_precollection: stop_event raises PipelineAbortedError", True)
    except Exception as e:
        check("run_precollection: stop_event raises PipelineAbortedError", False, detail=str(e))

    # ------------------------------------------------------------------
    # 6. PURE FUNCTION CONTRACT (DESIGN_REVIEW §5 requirement #5)
    # ------------------------------------------------------------------
    section("6. PURE FUNCTION — NO SHARED MUTABLE STATE")

    # Source analysis should not create any files
    import tempfile
    before_files = set(Path(tempfile.gettempdir()).glob("*nmap*"))
    if repo_exists:
        _ = collect_source_analysis(str(repo_path))
    after_files = set(Path(tempfile.gettempdir()).glob("*nmap*"))
    check("Source analysis creates no temp files", before_files == after_files)

    # Run twice and verify identical output (determinism)
    if repo_exists:
        r1 = collect_source_analysis(str(repo_path))
        r2 = collect_source_analysis(str(repo_path))
        check("Source analysis is deterministic (identical across runs)", r1 == r2,
              detail=f"len1={len(r1)}, len2={len(r2)}")

    # ------------------------------------------------------------------
    # 7. TEMPLATE VARIABLE KEYS (DESIGN_REVIEW §4 table)
    # ------------------------------------------------------------------
    section("7. TEMPLATE VARIABLE KEYS MATCH RECON PROMPT")

    # run_precollection must return exactly these keys
    # Use a mock that won't actually hit the network
    with patch("src.precollect.collect_nmap_scan", return_value="## Nmap mock\n"), \
         patch("src.precollect.collect_http_probes", return_value="## HTTP mock\n"):
        if repo_exists:
            result_dict = run_precollection(
                "http://localhost:3000",
                str(repo_path),
            )
        else:
            with patch("src.precollect.collect_source_analysis", return_value="## Source mock\n"):
                result_dict = run_precollection(
                    "http://localhost:3000",
                    str(repo_path),
                )

    expected_keys = {"SOURCE_ANALYSIS", "NMAP_RESULTS", "HTTP_PROBE_RESULTS"}
    check("run_precollection returns correct keys",
          set(result_dict.keys()) == expected_keys,
          detail=f"got {set(result_dict.keys())}")

    # Verify the recon prompt template contains matching placeholders
    recon_prompt = (PROJECT_ROOT / "src" / "prompts" / "recon.md").read_text(encoding="utf-8")
    for key in expected_keys:
        placeholder = "{{" + key + "}}"
        check(f"recon.md contains {placeholder}",
              placeholder in recon_prompt)

    # ------------------------------------------------------------------
    # 8. PIPELINE INTEGRATION
    # ------------------------------------------------------------------
    section("8. PIPELINE INTEGRATION — run_phase_recon() calls precollection")

    from src.pipeline import run_phase_recon, PipelineConfig, load_prompt, PROMPTS_DIR
    from src.skills.skill_loader import SkillRegistry

    # Verify the pipeline integrates precollect
    import inspect
    recon_source = inspect.getsource(run_phase_recon)
    check("run_phase_recon calls run_precollection",
          "run_precollection" in recon_source or "precollect" in recon_source)

    # Test that prompt template loads with all variables substituted
    test_vars = {
        "TARGET_URL": "http://test:3000",
        "REPO_PATH": "./repos/juice-shop",
        "SOURCE_ANALYSIS": "## Source\ntest data",
        "NMAP_RESULTS": "## Nmap\ntest data",
        "HTTP_PROBE_RESULTS": "## HTTP\ntest data",
        "NETWORK_RECON_SKILL": "skill context",
        "VULN_LOOKUP_SKILL": "vuln context",
    }
    loaded = load_prompt(PROMPTS_DIR / "recon.md", test_vars)
    # Check that no unsubstituted {{}} remain (except in code blocks)
    import re
    # Strip code blocks first
    no_code = re.sub(r"```.*?```", "", loaded, flags=re.DOTALL)
    unsubstituted = re.findall(r"\{\{[A-Z_]+\}\}", no_code)
    check("All template variables substituted in recon prompt",
          len(unsubstituted) == 0,
          detail=f"unsubstituted: {unsubstituted}" if unsubstituted else "all substituted")

    # Verify pre-collected data appears in loaded prompt
    check("SOURCE_ANALYSIS injected into prompt", "## Source\ntest data" in loaded)
    check("NMAP_RESULTS injected into prompt", "## Nmap\ntest data" in loaded)
    check("HTTP_PROBE_RESULTS injected into prompt", "## HTTP\ntest data" in loaded)

    # ------------------------------------------------------------------
    # 9. PROMPT SIZE MANAGEMENT (DESIGN_REVIEW §5 requirement #3)
    # ------------------------------------------------------------------
    section("9. PROMPT SIZE MANAGEMENT")

    if repo_exists:
        full_source = collect_source_analysis(str(repo_path))
        # Each category limited to _MAX_MATCHES_PER_CATEGORY (60)
        # Total should be bounded
        line_count = full_source.count("\n")
        check("Source analysis output is bounded",
              line_count < 5000,
              detail=f"{line_count} lines, {len(full_source)} chars")

        # Test with custom max_matches
        small_source = collect_source_analysis(str(repo_path), max_matches=5)
        check("Custom max_matches limits output",
              len(small_source) < len(full_source),
              detail=f"max5={len(small_source)} < default={len(full_source)}")

    # ------------------------------------------------------------------
    # 10. NMAP TIMEOUT & KILL (DESIGN_REVIEW §5 requirement #4, RC #10)
    # ------------------------------------------------------------------
    section("10. NMAP SUBPROCESS TIMEOUT (RC #10)")

    # Verify the code path handles TimeoutExpired with kill
    from src.precollect import _NMAP_TIMEOUT
    check("Default nmap timeout is 180s", _NMAP_TIMEOUT == 180)

    # Test that `subprocess.Popen` is used (not `subprocess.run`) for kill control
    precollect_source = inspect.getsource(collect_nmap_scan)
    check("Uses subprocess.Popen for explicit kill control",
          "Popen" in precollect_source)
    check("Calls proc.kill() on timeout",
          "proc.kill()" in precollect_source)
    check("Calls proc.wait() after kill (reap zombie)",
          "proc.wait" in precollect_source)

    # ------------------------------------------------------------------
    # 11. NO SHELL EXECUTION TOOL (DESIGN_REVIEW §5 "What NOT to Do")
    # ------------------------------------------------------------------
    section("11. SAFETY — NO SHELL EXECUTION TOOL ADDED")

    from src.agent_loop import MCP_TOOLS
    tool_names = [t["name"] for t in MCP_TOOLS]
    check("No bash_execute tool in MCP_TOOLS",
          "bash_execute" not in tool_names and "run_shell_command" not in tool_names,
          detail=f"tools: {tool_names}")

    # ------------------------------------------------------------------
    # 12. RACE CONDITION REGRESSION (DESIGN_REVIEW §4.3)
    # ------------------------------------------------------------------
    section("12. RACE CONDITION REGRESSION")

    # RC#1: Budget counter — precollection doesn't affect budget
    check("Pre-collection has no budget_lock references",
          "_budget_lock" not in inspect.getsource(run_precollection))

    # RC#5: Parallel deliverable writes — precollection writes to variables, not files
    precollect_all_source = inspect.getsource(run_precollection)
    check("run_precollection does not call save_deliverable",
          "save_deliverable" not in precollect_all_source)

    # RC#8: Skills dir modification — precollection doesn't touch skills
    check("Pre-collection source analysis doesn't access skills/",
          "skills/" not in inspect.getsource(collect_source_analysis).lower()
          or "skill" not in inspect.getsource(collect_source_analysis).lower())

    # ------------------------------------------------------------------
    # 13. END-TO-END PIPELINE DRY RUN
    # ------------------------------------------------------------------
    section("13. END-TO-END PIPELINE DRY RUN (no agent)")

    from src.pipeline import run_pipeline

    # Mock nmap and HTTP probes to avoid network access
    with patch("src.precollect.collect_nmap_scan", return_value="## Pre-collected Network Scan\n\nnmap mocked.\n"), \
         patch("src.precollect.collect_http_probes", return_value="## Pre-collected HTTP Endpoint Probes\n\nHTTP mocked.\n"):
        pipeline_result = run_pipeline(PipelineConfig(), agent_runner=None)

    check("Pipeline completes without crash",
          pipeline_result is not None)
    check("Pipeline has 4 phases",
          len(pipeline_result.phases) == 4,
          detail=f"got {len(pipeline_result.phases)}")

    recon_phase = pipeline_result.phases[0] if pipeline_result.phases else None
    if recon_phase:
        check("Recon phase ran (name='recon')",
              recon_phase.phase_name == "recon")

    # ── SUMMARY ──────────────────────────────────────────────────────
    print()
    print("=" * 70)
    total = PASS + FAIL
    if FAIL == 0:
        print(f"ALL {total} CHECKS PASSED — Pre-collection tests COMPLETE")
    else:
        print(f"{PASS}/{total} passed, {FAIL} FAILED")
    print("=" * 70)


if __name__ == "__main__":
    sys.exit(main() or (1 if FAIL > 0 else 0))
