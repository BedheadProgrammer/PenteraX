"""Stream C2 — Standalone report agent test against Juice Shop findings.

Runs:
  Step 1 (Mock):  Report agent with mock findings data  (tests/mock-data/)
  Step 2 (Real):  Report agent with real agent output    (deliverables/)

Validates that pentest_report.md is professional and contains all required sections.
"""

import logging
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("stream_c2")

from src.pipeline import (
    PipelineConfig,
    DELIVERABLES_DIR,
    PROMPTS_DIR,
    ensure_dir,
    load_prompt,
    save_deliverable,
    read_deliverable,
)
from src.skills.skill_loader import SkillRegistry
from src.agent_runner import AgentRunner
from src.agent_loop import MCP_TOOLS, SkillToolDispatcher

# ── Configuration ──────────────────────────────────────────────────────────
TARGET_URL = "http://54.146.141.88:3000"
API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MAX_BUDGET = 5.0  # budget cap for report generation
PROJECT_ROOT = Path(__file__).resolve().parent

if not API_KEY:
    print("ERROR: ANTHROPIC_API_KEY not set in environment or .env")
    sys.exit(1)

print(f"{'=' * 60}")
print(f"Stream C2 — Report Agent Testing")
print(f"{'=' * 60}")
print(f"  Target:  {TARGET_URL}")
print(f"  Budget:  ${MAX_BUDGET:.2f}")
print(f"  Model:   claude-sonnet-4-20250514")
print()


# ── Quality check helper ──────────────────────────────────────────────────

def validate_report(report_text: str, label: str) -> tuple[int, int, dict[str, bool]]:
    """Run quality checks on a pentest report. Returns (passed, total, checks)."""

    checks: dict[str, bool] = {
        # Structure
        "Has report title": "# PenteraX Penetration Test Report" in report_text
            or "# Penetration Test Report" in report_text
            or "# Pentest Report" in report_text,
        "Has Executive Summary": "## Executive Summary" in report_text,
        "Has Scope & Methodology": "## Scope" in report_text or "## Methodology" in report_text,
        "Has Findings section": "## Findings" in report_text or "### Finding" in report_text,
        "Has Recommendations": "## Recommendations" in report_text or "## Remediation" in report_text,
        "Has Scope Limitations": "Scope Limitation" in report_text or "Out of Scope" in report_text
            or "out of scope" in report_text.lower(),

        # Findings quality
        "Has severity ratings": bool(re.search(r"CRITICAL|HIGH|MEDIUM|LOW", report_text)),
        "Has CVSS scores": "CVSS" in report_text,
        "Has CWE references": "CWE-" in report_text,
        "Has proof/evidence": "Proof" in report_text or "Evidence" in report_text
            or "Request:" in report_text,
        "Has HTTP evidence": "HTTP" in report_text or "GET " in report_text
            or "POST " in report_text,

        # Content
        "Has SQL injection findings": "sql injection" in report_text.lower()
            or "sqli" in report_text.lower(),
        "Has XSS findings": "xss" in report_text.lower()
            or "cross-site" in report_text.lower(),
        "References target URL": TARGET_URL in report_text
            or "54.146.141.88" in report_text,
        "No localhost references": "localhost" not in report_text
            and "127.0.0.1" not in report_text,
        "Has specific remediation": "parameterized" in report_text.lower()
            or "prepared statement" in report_text.lower()
            or "escap" in report_text.lower()
            or "sanitiz" in report_text.lower()
            or "Content-Security-Policy" in report_text,

        # Size / completeness
        "Report is substantial (>2000 chars)": len(report_text) > 2000,
        "Report is comprehensive (>5000 chars)": len(report_text) > 5000,
        "Has multiple findings": len(re.findall(r"### Finding \d+", report_text)) >= 2
            or report_text.count("### ") >= 4,
    }

    passed = sum(1 for v in checks.values() if v)
    total = len(checks)

    print(f"\n  {label} Quality Checks:")
    for name, result in checks.items():
        status = "PASS" if result else "FAIL"
        print(f"    [{status}] {name}")
    print(f"\n    Quality: {passed}/{total} checks passed")

    return passed, total, checks


# ══════════════════════════════════════════════════════════════════════════
# STEP 1: Report from MOCK findings (validate prompt + agent wiring)
# ══════════════════════════════════════════════════════════════════════════
print()
print(f"{'=' * 60}")
print(f"STEP 1: Report Agent — Mock Findings Data")
print(f"{'=' * 60}")

# Load mock findings
mock_data_dir = PROJECT_ROOT / "tests" / "mock-data"
mock_findings_parts = []

for name in ["findings_injection.md", "findings_xss.md"]:
    mock_path = mock_data_dir / name
    if mock_path.exists():
        content = mock_path.read_text(encoding="utf-8")
        mock_findings_parts.append(f"# {name}\n\n{content}")
        print(f"  {name}: {len(content)} chars loaded (mock)")
    else:
        print(f"  WARNING: {mock_path} not found")

if not mock_findings_parts:
    print("  ERROR: No mock findings data found in tests/mock-data/")
    print("         Cannot test report agent without input data.")
    sys.exit(1)

mock_findings_combined = "\n\n---\n\n".join(mock_findings_parts)


# Setup agent
registry = SkillRegistry()
dispatcher = SkillToolDispatcher(registry)

# Use a temp dir for mock test so we don't clobber real deliverables.
# NOTE: Python default args are evaluated at function definition time, so
# monkey-patching DELIVERABLES_DIR doesn't affect save_deliverable's default.
# Instead, we backup the existing report (if any) and restore after mock test.
import src.pipeline as _pipeline_mod
real_report_path = DELIVERABLES_DIR / "pentest_report.md"
backup_report = None
if real_report_path.exists():
    backup_report = real_report_path.read_text(encoding="utf-8")

mock_runner = AgentRunner(
    api_key=API_KEY,
    max_budget_usd=MAX_BUDGET / 2,  # Half budget for mock test
    tools=MCP_TOOLS,
    tool_dispatcher=dispatcher,
    system_prompt=(
        "You are a cybersecurity report-writing agent. "
        "Your job is to synthesise penetration test findings into a professional "
        "pentest report suitable for a technical audience. "
        "Include executive summary, methodology, detailed findings with evidence, "
        "CVSS scores, CWE references, and specific remediation recommendations. "
        "IMPORTANT: Save your final output using the save_deliverable tool "
        "with name='pentest_report.md'."
    ),
)

# Build prompt
mock_prompt_vars = {
    "FINDINGS": mock_findings_combined,
    "TARGET_URL": TARGET_URL,
}
mock_prompt = load_prompt(PROMPTS_DIR / "report.md", mock_prompt_vars)

print(f"  Prompt size: {len(mock_prompt)} chars")
print("  Running report agent with mock data...")

mock_start = time.time()
try:
    mock_output = mock_runner.run(mock_prompt, "report-mock")
    # Save if agent didn't already via tool
    mock_report_path = DELIVERABLES_DIR / "pentest_report.md"
    if not mock_report_path.exists():
        save_deliverable("pentest_report.md", mock_output)
    elif len(mock_output.strip()) > len(mock_report_path.read_text(encoding="utf-8").strip()):
        save_deliverable("pentest_report.md", mock_output)

    mock_elapsed = time.time() - mock_start
    print(f"  Report generated in {mock_elapsed:.1f}s (cost: ${mock_runner.total_cost_usd:.4f})")
except Exception as e:
    print(f"  ERROR: Report agent (mock) failed: {e}")
    # Restore backup if we had one
    if backup_report is not None:
        save_deliverable("pentest_report.md", backup_report)
    sys.exit(1)

# Validate mock report
mock_report_path = DELIVERABLES_DIR / "pentest_report.md"
if mock_report_path.exists():
    mock_report = mock_report_path.read_text(encoding="utf-8")
    print(f"\n  pentest_report.md (mock): {len(mock_report)} chars")
    mock_passed, mock_total, _ = validate_report(mock_report, "Mock Report")
else:
    print("  ERROR: pentest_report.md was not generated!")
    mock_passed, mock_total = 0, 1

mock_cost = mock_runner.total_cost_usd


# ══════════════════════════════════════════════════════════════════════════
# STEP 2: Report from REAL agent output (deliverables/)
# ══════════════════════════════════════════════════════════════════════════
print()
print(f"{'=' * 60}")
print(f"STEP 2: Report Agent — Real Agent Findings")
print(f"{'=' * 60}")

# Load real findings from deliverables/
real_findings_parts = []
for name in ["findings_injection.md", "findings_xss.md"]:
    content = read_deliverable(name)
    if content:
        real_findings_parts.append(f"# {name}\n\n{content}")
        print(f"  {name}: {len(content)} chars loaded (real)")
    else:
        print(f"  WARNING: {name} not found in deliverables/")

# Restore backup from before mock test (so real test starts clean)
if backup_report is not None:
    save_deliverable("pentest_report.md", backup_report)
    print("  (restored pre-existing pentest_report.md backup)")

if not real_findings_parts:
    print("  SKIPPING: No real findings available — run B2 and C1 first.")
    print("  (Mock test above is sufficient for C2 gate if findings are unavailable)")
    real_passed, real_total = 0, 0
else:
    real_findings_combined = "\n\n---\n\n".join(real_findings_parts)

    # Fresh runner for real report
    real_runner = AgentRunner(
        api_key=API_KEY,
        max_budget_usd=MAX_BUDGET - mock_cost,  # remaining budget
        tools=MCP_TOOLS,
        tool_dispatcher=dispatcher,
        system_prompt=(
            "You are a cybersecurity report-writing agent. "
            "Your job is to synthesise penetration test findings into a professional "
            "pentest report suitable for a technical audience. "
            "Include executive summary, methodology, detailed findings with evidence, "
            "CVSS scores, CWE references, and specific remediation recommendations. "
            "IMPORTANT: Save your final output using the save_deliverable tool "
            "with name='pentest_report.md'."
        ),
    )

    # Build prompt
    real_prompt_vars = {
        "FINDINGS": real_findings_combined,
        "TARGET_URL": TARGET_URL,
    }
    real_prompt = load_prompt(PROMPTS_DIR / "report.md", real_prompt_vars)

    print(f"  Prompt size: {len(real_prompt)} chars")
    print(f"  Remaining budget: ${MAX_BUDGET - mock_cost:.4f}")
    print("  Running report agent with real findings...")

    real_start = time.time()
    try:
        real_output = real_runner.run(real_prompt, "report-real")
        # Save if agent didn't already via tool
        real_report_path = DELIVERABLES_DIR / "pentest_report.md"
        if not real_report_path.exists():
            save_deliverable("pentest_report.md", real_output)
        elif len(real_output.strip()) > len(real_report_path.read_text(encoding="utf-8").strip()):
            save_deliverable("pentest_report.md", real_output)

        real_elapsed = time.time() - real_start
        print(f"  Report generated in {real_elapsed:.1f}s (cost: ${real_runner.total_cost_usd:.4f})")
    except Exception as e:
        print(f"  ERROR: Report agent (real) failed: {e}")
        real_passed, real_total = 0, 1

    # Validate real report
    real_report_path = DELIVERABLES_DIR / "pentest_report.md"
    if real_report_path.exists():
        real_report = real_report_path.read_text(encoding="utf-8")
        print(f"\n  pentest_report.md (real): {len(real_report)} chars")
        real_passed, real_total, _ = validate_report(real_report, "Real Report")

        # Also save replay snapshot
        try:
            from src.pipeline import save_replay_snapshot
            copied = save_replay_snapshot()
            if copied:
                print(f"\n  Replay snapshot saved: {len(copied)} files")
        except Exception as e:
            logger.warning("Replay snapshot failed (non-fatal): %s", e)
    else:
        print("  ERROR: pentest_report.md was not generated!")
        real_passed, real_total = 0, 1

    real_cost = real_runner.total_cost_usd


# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print()
print(f"{'=' * 60}")
print(f"STREAM C2 SUMMARY")
print(f"{'=' * 60}")
print(f"  Mock report quality:  {mock_passed}/{mock_total} checks passed")
if real_total > 0:
    print(f"  Real report quality:  {real_passed}/{real_total} checks passed")
else:
    print(f"  Real report quality:  SKIPPED (no real findings)")
print(f"  Mock test cost:       ${mock_cost:.4f}")
if real_findings_parts:
    total_cost = mock_cost + real_cost
    print(f"  Real test cost:       ${real_cost:.4f}")
    print(f"  Total cost:           ${total_cost:.4f}")
else:
    total_cost = mock_cost
    print(f"  Total cost:           ${total_cost:.4f}")
print()

# Gate check
# C2 requires: professional report with all required sections
mock_gate = mock_passed >= 14  # 14/19 minimum for mock
real_gate = real_passed >= 14 if real_total > 0 else True  # Skip if no real data

if mock_gate and real_gate:
    print("  STREAM C2 GATE: PASSED — report quality is sufficient")
    report_exists = (DELIVERABLES_DIR / "pentest_report.md").exists()
    if report_exists:
        print("  pentest_report.md saved to deliverables/")
    else:
        print("  NOTE: Only mock report generated — run with real findings for deliverables/")
else:
    print("  STREAM C2 GATE: NEEDS ITERATION — review report quality")
    if mock_passed < 14:
        print(f"    Mock report: {mock_passed}/{mock_total} (need 14+)")
    if real_total > 0 and real_passed < 14:
        print(f"    Real report: {real_passed}/{real_total} (need 14+)")
    print("    Iterate src/prompts/report.md to improve output quality")

print(f"\n{'=' * 60}")
print(f"Stream C2 test complete.")
print(f"{'=' * 60}")
