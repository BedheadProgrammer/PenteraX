"""Stream B2 — Standalone injection agent test against Juice Shop.

Runs:
  Step 1: Injection-analysis agent  (recon_report.md → hypotheses_injection.md)
  Step 2: Injection-exploit agent   (hypotheses → findings_injection.md)

Validates that the exploit agent finds at least one real SQL injection.
"""

import logging
import os
import sys
import time

from dotenv import load_dotenv

load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("stream_b2")

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
from src.skills.skill_wrappers import (
    batch_lookup_cve,
    format_known_vulns_for_prompt,
)
from src.agent_runner import AgentRunner
from src.agent_loop import MCP_TOOLS, SkillToolDispatcher

# ── Configuration ──────────────────────────────────────────────────────────
TARGET_URL = "http://54.146.141.88:3000"
REPO_PATH = "./repos/juice-shop"
API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MAX_BUDGET = 8.0  # budget cap for analysis + exploit

if not API_KEY:
    print("ERROR: ANTHROPIC_API_KEY not set in environment or .env")
    sys.exit(1)

print(f"{'=' * 60}")
print(f"Stream B2 — Injection Agent Testing")
print(f"{'=' * 60}")
print(f"  Target:  {TARGET_URL}")
print(f"  Repo:    {REPO_PATH}")
print(f"  Budget:  ${MAX_BUDGET:.2f}")
print(f"  Model:   claude-sonnet-4-20250514")
print()

# ── Verify recon_report.md exists ──────────────────────────────────────────
recon_data = read_deliverable("recon_report.md")
if not recon_data:
    print("ERROR: recon_report.md not found in deliverables/.")
    print("       Run Stream B1 (run_recon_standalone.py) first.")
    sys.exit(1)
print(f"  recon_report.md: {len(recon_data)} chars loaded")

# ── Setup ──────────────────────────────────────────────────────────────────
config = PipelineConfig(
    target_url=TARGET_URL,
    repo_path=REPO_PATH,
    output_dir=DELIVERABLES_DIR,
    max_retries=3,
)

registry = SkillRegistry()
dispatcher = SkillToolDispatcher(registry)

# ── Enrich with CVE data ──────────────────────────────────────────────────
known_vulns = ""
try:
    from src.pipeline import _extract_tech_stack_from_recon

    tech_stack = _extract_tech_stack_from_recon(recon_data)
    batch_result = batch_lookup_cve(registry, tech_stack)
    if batch_result.success and isinstance(batch_result.output, list):
        known_vulns = format_known_vulns_for_prompt(batch_result.output)
        print(f"  CVE enrichment: {len(known_vulns)} chars")
except Exception as e:
    logger.warning("CVE batch lookup failed (non-fatal): %s", e)
    known_vulns = "CVE lookup unavailable."


# ══════════════════════════════════════════════════════════════════════════
# STEP 1: Injection Analysis — produce hypotheses_injection.md
# ══════════════════════════════════════════════════════════════════════════
print()
print(f"{'=' * 60}")
print(f"STEP 1: Injection Analysis Agent")
print(f"{'=' * 60}")

analysis_runner = AgentRunner(
    api_key=API_KEY,
    max_budget_usd=MAX_BUDGET,
    tools=MCP_TOOLS,
    tool_dispatcher=dispatcher,
    system_prompt=(
        "You are a cybersecurity analysis agent specializing in injection attacks. "
        "Your job is to analyze reconnaissance data and produce specific, actionable "
        "injection attack hypotheses for the OWASP Juice Shop. "
        "Focus on SQL injection, NoSQL injection, and command injection vectors. "
        "Each hypothesis must cite specific endpoints, parameters, and payloads. "
        "IMPORTANT: Save your final output using the save_deliverable tool "
        "with name='hypotheses_injection.md'."
    ),
)

# Build prompt
analysis_vars = {
    "RECON_DATA": recon_data,
    "KNOWN_VULNS": known_vulns,
    "TARGET_URL": TARGET_URL,
}
analysis_prompt = load_prompt(PROMPTS_DIR / "analysis-injection.md", analysis_vars)

print(f"  Prompt size: {len(analysis_prompt)} chars")
print("  Running analysis agent...")

analysis_start = time.time()
try:
    analysis_output = analysis_runner.run(analysis_prompt, "analysis-injection")
    # Save if agent didn't already via tool
    hyp_path = DELIVERABLES_DIR / "hypotheses_injection.md"
    if not hyp_path.exists() or len(analysis_output.strip()) > len(hyp_path.read_text(encoding="utf-8").strip()):
        save_deliverable("hypotheses_injection.md", analysis_output)
    analysis_elapsed = time.time() - analysis_start
    print(f"  Analysis complete in {analysis_elapsed:.1f}s (cost: ${analysis_runner.total_cost_usd:.4f})")
except Exception as e:
    print(f"  ERROR: Analysis agent failed: {e}")
    sys.exit(1)

# ── Validate hypotheses ───────────────────────────────────────────────────
hypotheses = read_deliverable("hypotheses_injection.md")
if not hypotheses:
    print("  ERROR: hypotheses_injection.md not generated!")
    sys.exit(1)

print(f"\n  hypotheses_injection.md: {len(hypotheses)} chars")

hyp_checks = {
    "Has Hypotheses section": "## Hypotheses" in hypotheses or "### Hypothesis" in hypotheses,
    "Contains /rest/products/search": "/rest/products/search" in hypotheses,
    "Contains /rest/user/login": "/rest/user/login" in hypotheses,
    "Has SQL payloads": "OR 1=1" in hypotheses or "UNION" in hypotheses,
    "Has endpoint references": "**Endpoint:**" in hypotheses,
    "Has parameter references": "**Parameter:**" in hypotheses,
    "Has payload references": "**Payload:**" in hypotheses,
    "Has evidence references": "**Evidence" in hypotheses,
    "At least 3 hypotheses": hypotheses.count("### Hypothesis") >= 3,
}

print("\nHypothesis Quality Checks:")
hyp_passed = 0
for check_name, check_result in hyp_checks.items():
    status = "PASS" if check_result else "FAIL"
    if check_result:
        hyp_passed += 1
    print(f"  [{status}] {check_name}")
print(f"\n  Quality: {hyp_passed}/{len(hyp_checks)} checks passed")

# Keep analysis cost for total tracking
analysis_cost = analysis_runner.total_cost_usd


# ══════════════════════════════════════════════════════════════════════════
# STEP 2: Injection Exploit — produce findings_injection.md
# ══════════════════════════════════════════════════════════════════════════
print()
print(f"{'=' * 60}")
print(f"STEP 2: Injection Exploit Agent")
print(f"{'=' * 60}")

# Fresh runner for exploit phase (shares budget ceiling with analysis)
exploit_runner = AgentRunner(
    api_key=API_KEY,
    max_budget_usd=MAX_BUDGET - analysis_cost,  # remaining budget
    tools=MCP_TOOLS,
    tool_dispatcher=dispatcher,
    system_prompt=(
        "You are a cybersecurity exploitation agent specializing in SQL injection. "
        "Your job is to test injection hypotheses against a LIVE target and produce "
        "concrete proof of exploitation with real HTTP request/response evidence. "
        "MANDATORY APPROACH: Use manual curl commands FIRST for all testing. "
        "URL-encode special characters in payloads. "
        "Establish a baseline response, then send injection payloads, and compare. "
        "Only fall back to sqlmap if 3+ manual payloads fail per endpoint. "
        "Do NOT fabricate evidence — report actual responses. "
        "For the search endpoint, the Products table has 9 columns — use that for UNION injection. "
        "For the login endpoint, use JSON Content-Type with curl -d for POST payloads. "
        "IMPORTANT: Save your final output using the save_deliverable tool "
        "with name='findings_injection.md'."
    ),
)

# Build exploit prompt
exploit_vars = {
    "HYPOTHESES": hypotheses,
    "TARGET_URL": TARGET_URL,
}
exploit_prompt = load_prompt(PROMPTS_DIR / "exploit-injection.md", exploit_vars)

print(f"  Prompt size: {len(exploit_prompt)} chars")
print(f"  Remaining budget: ${MAX_BUDGET - analysis_cost:.4f}")
print("  Running exploit agent...")

exploit_start = time.time()
try:
    exploit_output = exploit_runner.run(exploit_prompt, "exploit-injection")
    # Save if agent didn't already via tool
    find_path = DELIVERABLES_DIR / "findings_injection.md"
    if not find_path.exists() or len(exploit_output.strip()) > len(find_path.read_text(encoding="utf-8").strip()):
        save_deliverable("findings_injection.md", exploit_output)
    exploit_elapsed = time.time() - exploit_start
    print(f"  Exploit complete in {exploit_elapsed:.1f}s (cost: ${exploit_runner.total_cost_usd:.4f})")
except Exception as e:
    print(f"  ERROR: Exploit agent failed: {e}")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════
# STEP 3: Validate Findings
# ══════════════════════════════════════════════════════════════════════════
print()
print(f"{'=' * 60}")
print(f"RESULTS VALIDATION")
print(f"{'=' * 60}")

findings = read_deliverable("findings_injection.md")
if not findings:
    print("  ERROR: findings_injection.md not generated!")
    sys.exit(1)

print(f"  findings_injection.md: {len(findings)} chars")

finding_checks = {
    "Has Findings section": "## Findings" in findings or "### Finding" in findings,
    "Contains endpoint evidence": "/rest/products/search" in findings,
    "Has HTTP request proof": "Request:" in findings or "curl" in findings.lower(),
    "Has HTTP response proof": "Response:" in findings or "200" in findings,
    "Has severity rating": "CRITICAL" in findings or "HIGH" in findings,
    "Has CVSS score": "CVSS" in findings,
    "Has SQL injection confirmation": "sql injection" in findings.lower() or "sql" in findings.lower(),
    "Has payload evidence": "OR 1=1" in findings or "UNION" in findings or "payload" in findings.lower(),
    "Has baseline comparison": "baseline" in findings.lower() or "normal" in findings.lower(),
    "Not all UNCONFIRMED": "[CONFIRMED]" in findings or "Finding" in findings,
}

print("\nFindings Quality Checks:")
find_passed = 0
for check_name, check_result in finding_checks.items():
    status = "PASS" if check_result else "FAIL"
    if check_result:
        find_passed += 1
    print(f"  [{status}] {check_name}")
print(f"\n  Quality: {find_passed}/{len(finding_checks)} checks passed")

# Check for confirmed findings — count Finding sections NOT marked [UNCONFIRMED]
import re
finding_sections = re.findall(r'### Finding \d+.*?(?=### Finding|\Z)', findings, re.DOTALL)
confirmed_count = sum(1 for f in finding_sections if '[UNCONFIRMED]' not in f.upper())
unconfirmed_count = sum(1 for f in finding_sections if '[UNCONFIRMED]' in f.upper())
print(f"\n  Total findings: {len(finding_sections)}")
print(f"  Confirmed findings: {confirmed_count}")
print(f"  UNCONFIRMED findings: {unconfirmed_count}")

# ── Summary ────────────────────────────────────────────────────────────────
total_cost = analysis_cost + exploit_runner.total_cost_usd
total_time = (time.time() - analysis_start)

print()
print(f"{'=' * 60}")
print(f"STREAM B2 SUMMARY")
print(f"{'=' * 60}")
print(f"  Analysis duration: {analysis_elapsed:.1f}s")
print(f"  Exploit duration:  {exploit_elapsed:.1f}s")
print(f"  Total duration:    {total_time:.1f}s")
print(f"  Total API cost:    ${total_cost:.4f}")
print(f"  Hypotheses quality: {hyp_passed}/{len(hyp_checks)}")
print(f"  Findings quality:   {find_passed}/{len(finding_checks)}")
print()

# Gate check — B2 requires at least one proven SQL injection
if confirmed_count > 0 and find_passed >= 6:
    print("  ✓ STREAM B2 GATE: PASSED — at least one SQL injection proven")
else:
    print("  ✗ STREAM B2 GATE: NEEDS ITERATION — review findings and iterate prompts")
    print("    Check findings_injection.md for details on what was attempted.")

print(f"\n{'=' * 60}")
print(f"Stream B2 test complete.")
print(f"{'=' * 60}")
