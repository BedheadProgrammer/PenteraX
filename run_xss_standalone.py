"""Stream C1 — Standalone XSS agent test against Juice Shop.

Runs:
  Step 1: XSS-analysis agent  (recon_report.md → hypotheses_xss.md)
  Step 2: XSS-exploit agent   (hypotheses → findings_xss.md)

Validates that the exploit agent finds at least one real XSS vulnerability.
"""

import logging
import os
import re
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
logger = logging.getLogger("stream_c1")

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
print(f"Stream C1 — XSS Agent Testing")
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
# STEP 1: XSS Analysis — produce hypotheses_xss.md
# ══════════════════════════════════════════════════════════════════════════
print()
print(f"{'=' * 60}")
print(f"STEP 1: XSS Analysis Agent")
print(f"{'=' * 60}")

analysis_runner = AgentRunner(
    api_key=API_KEY,
    max_budget_usd=MAX_BUDGET,
    tools=MCP_TOOLS,
    tool_dispatcher=dispatcher,
    system_prompt=(
        "You are a cybersecurity analysis agent specializing in Cross-Site Scripting (XSS) attacks. "
        "Your job is to analyze reconnaissance data and produce specific, actionable "
        "XSS attack hypotheses for the OWASP Juice Shop. "
        "Focus on DOM-based XSS (especially Angular template injection and innerHTML sinks), "
        "reflected XSS in search/tracking pages, and stored XSS via feedback/user registration. "
        "Each hypothesis must cite specific endpoints, parameters, DOM sinks, and payloads. "
        "Juice Shop uses AngularJS 1.x with known sandbox escapes — prioritize Angular template "
        "injection vectors and bypassSecurityTrustHtml sinks. "
        "IMPORTANT: Save your final output using the save_deliverable tool "
        "with name='hypotheses_xss.md'."
    ),
)

# Build prompt
analysis_vars = {
    "RECON_DATA": recon_data,
    "KNOWN_VULNS": known_vulns,
    "TARGET_URL": TARGET_URL,
}
analysis_prompt = load_prompt(PROMPTS_DIR / "analysis-xss.md", analysis_vars)

print(f"  Prompt size: {len(analysis_prompt)} chars")
print("  Running analysis agent...")

analysis_start = time.time()
try:
    analysis_output = analysis_runner.run(analysis_prompt, "analysis-xss")
    # Save if agent didn't already via tool
    hyp_path = DELIVERABLES_DIR / "hypotheses_xss.md"
    if not hyp_path.exists() or len(analysis_output.strip()) > len(hyp_path.read_text(encoding="utf-8").strip()):
        save_deliverable("hypotheses_xss.md", analysis_output)
    analysis_elapsed = time.time() - analysis_start
    print(f"  Analysis complete in {analysis_elapsed:.1f}s (cost: ${analysis_runner.total_cost_usd:.4f})")
except Exception as e:
    print(f"  ERROR: Analysis agent failed: {e}")
    sys.exit(1)

# ── Validate hypotheses ───────────────────────────────────────────────────
hypotheses = read_deliverable("hypotheses_xss.md")
if not hypotheses:
    print("  ERROR: hypotheses_xss.md not generated!")
    sys.exit(1)

print(f"\n  hypotheses_xss.md: {len(hypotheses)} chars")

hyp_checks = {
    "Has Hypotheses section": "## Hypotheses" in hypotheses or "### Hypothesis" in hypotheses,
    "Contains search endpoint": "search" in hypotheses.lower(),
    "Contains feedback/stored XSS ref": "feedback" in hypotheses.lower() or "stored" in hypotheses.lower(),
    "Has XSS payloads": "<script" in hypotheses or "<iframe" in hypotheses or "<img" in hypotheses or "<svg" in hypotheses or "alert(" in hypotheses,
    "Has DOM sink references": "innerHTML" in hypotheses or "bypassSecurityTrustHtml" in hypotheses or "DOM" in hypotheses,
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
# STEP 2: XSS Exploit — produce findings_xss.md
# ══════════════════════════════════════════════════════════════════════════
print()
print(f"{'=' * 60}")
print(f"STEP 2: XSS Exploit Agent")
print(f"{'=' * 60}")

# Fresh runner for exploit phase (shares budget ceiling with analysis)
exploit_runner = AgentRunner(
    api_key=API_KEY,
    max_budget_usd=MAX_BUDGET - analysis_cost,  # remaining budget
    tools=MCP_TOOLS,
    tool_dispatcher=dispatcher,
    system_prompt=(
        "You are a cybersecurity exploitation agent specializing in Cross-Site Scripting (XSS). "
        "Your job is to test XSS hypotheses against a LIVE target and produce "
        "concrete proof of exploitation with real evidence. "
        "MANDATORY APPROACH: "
        "1. Use the http_request tool to send payloads and check if they are reflected/stored unescaped. "
        "2. For DOM-based XSS, describe the Playwright steps to navigate to the URL with the payload "
        "   and capture dialog events or injected DOM elements. "
        "3. Register a page.on('dialog') listener BEFORE navigating to capture alert() proof. "
        "4. Check for unescaped payloads in the response body — if <script>, <iframe>, <img> appear "
        "   without HTML-encoding (&lt;), it confirms reflected/stored XSS. "
        "5. For the Juice Shop search endpoint, the query is reflected via bypassSecurityTrustHtml — "
        "   try <iframe src=\"javascript:alert(`xss`)\"> as a reliable payload. "
        "6. For stored XSS, POST payloads to /api/Feedbacks or /api/Users and then check "
        "   if the payload renders on the admin panel /#/administration. "
        "Do NOT fabricate evidence — report actual responses. "
        "IMPORTANT: Save your final output using the save_deliverable tool "
        "with name='findings_xss.md'."
    ),
)

# Build exploit prompt
exploit_vars = {
    "HYPOTHESES": hypotheses,
    "TARGET_URL": TARGET_URL,
}
exploit_prompt = load_prompt(PROMPTS_DIR / "exploit-xss.md", exploit_vars)

print(f"  Prompt size: {len(exploit_prompt)} chars")
print(f"  Remaining budget: ${MAX_BUDGET - analysis_cost:.4f}")
print("  Running exploit agent...")

exploit_start = time.time()
try:
    exploit_output = exploit_runner.run(exploit_prompt, "exploit-xss")
    # Save if agent didn't already via tool
    find_path = DELIVERABLES_DIR / "findings_xss.md"
    if not find_path.exists() or len(exploit_output.strip()) > len(find_path.read_text(encoding="utf-8").strip()):
        save_deliverable("findings_xss.md", exploit_output)
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

findings = read_deliverable("findings_xss.md")
if not findings:
    print("  ERROR: findings_xss.md not generated!")
    sys.exit(1)

print(f"  findings_xss.md: {len(findings)} chars")

finding_checks = {
    "Has Findings section": "## Findings" in findings or "### Finding" in findings,
    "Contains endpoint evidence": "search" in findings.lower() or "feedback" in findings.lower(),
    "Has XSS payload in proof": "<script" in findings or "<iframe" in findings or "<img" in findings or "<svg" in findings or "alert(" in findings,
    "Has HTTP or Playwright evidence": "Response" in findings or "page.goto" in findings or "dialog" in findings.lower(),
    "Has severity rating": "CRITICAL" in findings or "HIGH" in findings or "MEDIUM" in findings,
    "Has CVSS score": "CVSS" in findings,
    "Has XSS type classification": "reflected" in findings.lower() or "stored" in findings.lower() or "dom" in findings.lower(),
    "Has DOM or dialog proof": "dialog" in findings.lower() or "innerHTML" in findings.lower() or "DOM" in findings,
    "Has screenshot or evidence ref": "screenshot" in findings.lower() or "evidence" in findings.lower(),
    "Not all UNCONFIRMED": "[CONFIRMED]" in findings or ("Finding" in findings and "[UNCONFIRMED]" not in findings.upper()),
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
print(f"STREAM C1 SUMMARY")
print(f"{'=' * 60}")
print(f"  Analysis duration: {analysis_elapsed:.1f}s")
print(f"  Exploit duration:  {exploit_elapsed:.1f}s")
print(f"  Total duration:    {total_time:.1f}s")
print(f"  Total API cost:    ${total_cost:.4f}")
print(f"  Hypotheses quality: {hyp_passed}/{len(hyp_checks)}")
print(f"  Findings quality:   {find_passed}/{len(finding_checks)}")
print()

# Gate check — C1 requires at least one proven XSS
if confirmed_count > 0 and find_passed >= 6:
    print("  STREAM C1 GATE: PASSED — at least one XSS vulnerability proven")
else:
    print("  STREAM C1 GATE: NEEDS ITERATION — review findings and iterate prompts")
    print("    Check findings_xss.md for details on what was attempted.")

print(f"\n{'=' * 60}")
print(f"Stream C1 test complete.")
print(f"{'=' * 60}")
