#!/usr/bin/env bash
###############################################################################
# Phase 2 Stream C Gate Test — PenteraX
#
# Validates all Stream C deliverables from phase-2-core-infrastructure.md:
#   - analysis-xss.md
#   - exploit-xss.md
#   - report.md
#   - Mock test data files
###############################################################################

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0

green()  { printf "\033[32m✅  %s\033[0m\n" "$*"; }
red()    { printf "\033[31m❌  %s\033[0m\n" "$*"; }

check() {
  local desc="$1"; shift
  if "$@" > /dev/null 2>&1; then
    green "$desc"
    PASS=$((PASS + 1))
  else
    red "$desc"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║      PenteraX — Phase 2 Stream C (XSS + Report) Test       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

###############################################################################
echo "── Gate Criteria: Prompt Template Files Exist ───────────────────"
###############################################################################

check "src/prompts/analysis-xss.md exists" \
  test -f "$ROOT/src/prompts/analysis-xss.md"

check "src/prompts/exploit-xss.md exists" \
  test -f "$ROOT/src/prompts/exploit-xss.md"

check "src/prompts/report.md exists" \
  test -f "$ROOT/src/prompts/report.md"

###############################################################################
echo ""
echo "── analysis-xss.md: Substantive Content ─────────────────────────"
###############################################################################

AXF="$ROOT/src/prompts/analysis-xss.md"

check "analysis-xss.md has ≥50 lines" \
  bash -c "[ \$(wc -l < '$AXF') -ge 50 ]"

check "analysis-xss.md reads {{RECON_DATA}}" \
  bash -c "grep -q '{{RECON_DATA}}' '$AXF'"

check "analysis-xss.md identifies DOM sinks" \
  bash -c "grep -qi 'DOM' '$AXF'"

check "analysis-xss.md identifies reflected inputs" \
  bash -c "grep -qi 'reflected' '$AXF'"

check "analysis-xss.md identifies stored content" \
  bash -c "grep -qi 'stored' '$AXF'"

check "analysis-xss.md defines hypothesis format" \
  bash -c "grep -q 'Hypothesis' '$AXF'"

check "analysis-xss.md includes Endpoint field" \
  bash -c "grep -q '\\*\\*Endpoint:\\*\\*' '$AXF'"

check "analysis-xss.md includes Parameter field" \
  bash -c "grep -q '\\*\\*Parameter:\\*\\*' '$AXF'"

check "analysis-xss.md includes Payload field" \
  bash -c "grep -q '\\*\\*Payload:\\*\\*' '$AXF'"

check "analysis-xss.md includes Expected Result field" \
  bash -c "grep -q '\\*\\*Expected Result:\\*\\*' '$AXF'"

check "analysis-xss.md outputs hypotheses_xss.md" \
  bash -c "grep -q 'hypotheses_xss.md' '$AXF'"

check "analysis-xss.md mentions save_deliverable" \
  bash -c "grep -q 'save_deliverable' '$AXF'"

check "analysis-xss.md has payload guidelines" \
  bash -c "grep -qi 'payload' '$AXF'"

###############################################################################
echo ""
echo "── exploit-xss.md: Substantive Content ──────────────────────────"
###############################################################################

EXF="$ROOT/src/prompts/exploit-xss.md"

check "exploit-xss.md has ≥80 lines" \
  bash -c "[ \$(wc -l < '$EXF') -ge 80 ]"

check "exploit-xss.md reads {{HYPOTHESES}}" \
  bash -c "grep -q '{{HYPOTHESES}}' '$EXF'"

check "exploit-xss.md mentions Playwright" \
  bash -c "grep -qi 'playwright' '$EXF'"

check "exploit-xss.md has dialog event handling" \
  bash -c "grep -qi 'dialog' '$EXF'"

check "exploit-xss.md has DOM change monitoring" \
  bash -c "grep -qi 'DOM' '$EXF'"

check "exploit-xss.md has screenshot evidence capture" \
  bash -c "grep -qi 'screenshot' '$EXF'"

check "exploit-xss.md has retry envelope (3 alternatives)" \
  bash -c "grep -qE '(up to 3|3 alternative)' '$EXF'"

check "exploit-xss.md defines finding format" \
  bash -c "grep -q 'Finding' '$EXF'"

check "exploit-xss.md includes Vulnerability field" \
  bash -c "grep -q '\\*\\*Vulnerability:\\*\\*' '$EXF'"

check "exploit-xss.md includes Proof field" \
  bash -c "grep -q '\\*\\*Proof:\\*\\*' '$EXF'"

check "exploit-xss.md includes Severity field" \
  bash -c "grep -q '\\*\\*Severity:\\*\\*' '$EXF'"

check "exploit-xss.md includes Dialog Captured field" \
  bash -c "grep -q '\\*\\*Dialog Captured:\\*\\*' '$EXF'"

check "exploit-xss.md includes DOM Element Found field" \
  bash -c "grep -q '\\*\\*DOM Element Found:\\*\\*' '$EXF'"

check "exploit-xss.md outputs findings_xss.md" \
  bash -c "grep -q 'findings_xss.md' '$EXF'"

check "exploit-xss.md mentions save_deliverable" \
  bash -c "grep -q 'save_deliverable' '$EXF'"

check "exploit-xss.md has CVSS scoring guidance" \
  bash -c "grep -qi 'CVSS' '$EXF'"

check "exploit-xss.md has anti-fabrication rule" \
  bash -c "grep -qi 'fabricate' '$EXF'"

###############################################################################
echo ""
echo "── report.md: Substantive Content ───────────────────────────────"
###############################################################################

RPF="$ROOT/src/prompts/report.md"

check "report.md has ≥80 lines" \
  bash -c "[ \$(wc -l < '$RPF') -ge 80 ]"

check "report.md reads {{FINDINGS}}" \
  bash -c "grep -q '{{FINDINGS}}' '$RPF'"

check "report.md has Executive Summary section" \
  bash -c "grep -qi 'Executive Summary' '$RPF'"

check "report.md has Scope & Methodology section" \
  bash -c "grep -qi 'Scope.*Methodology' '$RPF'"

check "report.md has Findings section with CVSS" \
  bash -c "grep -qi 'CVSS v3.1' '$RPF'"

check "report.md has Evidence & Proof section" \
  bash -c "grep -qi 'Evidence.*Proof' '$RPF'"

check "report.md has Recommendations section" \
  bash -c "grep -qi 'Recommendations' '$RPF'"

check "report.md has Scope Limitations section" \
  bash -c "grep -qi 'Scope Limitations' '$RPF'"

check "report.md explicitly notes only Injection + XSS tested" \
  bash -c "grep -qE '(SQL Injection|Injection).*Cross-Site Scripting|only.*tested' '$RPF'"

check "report.md outputs pentest_report.md" \
  bash -c "grep -q 'pentest_report.md' '$RPF'"

check "report.md mentions save_deliverable" \
  bash -c "grep -q 'save_deliverable' '$RPF'"

check "report.md has quality checklist" \
  bash -c "grep -qi 'Quality Checklist' '$RPF'"

check "report.md mentions CWE identifiers" \
  bash -c "grep -q 'CWE' '$RPF'"

###############################################################################
echo ""
echo "── Mock Test Data ───────────────────────────────────────────────"
###############################################################################

check "Mock findings_injection.md exists" \
  test -f "$ROOT/tests/mock-data/findings_injection.md"

check "Mock findings_xss.md exists" \
  test -f "$ROOT/tests/mock-data/findings_xss.md"

check "Mock injection findings has ## Findings heading" \
  bash -c "grep -q '## Findings' '$ROOT/tests/mock-data/findings_injection.md'"

check "Mock injection findings has ≥1 finding" \
  bash -c "grep -q '### Finding 1' '$ROOT/tests/mock-data/findings_injection.md'"

check "Mock injection findings has Proof" \
  bash -c "grep -q '\\*\\*Proof:\\*\\*' '$ROOT/tests/mock-data/findings_injection.md'"

check "Mock injection findings has Severity + CVSS" \
  bash -c "grep -q 'CVSS' '$ROOT/tests/mock-data/findings_injection.md'"

check "Mock XSS findings has ## Findings heading" \
  bash -c "grep -q '## Findings' '$ROOT/tests/mock-data/findings_xss.md'"

check "Mock XSS findings has ≥1 finding" \
  bash -c "grep -q '### Finding 1' '$ROOT/tests/mock-data/findings_xss.md'"

check "Mock XSS findings has Dialog Captured" \
  bash -c "grep -q '\\*\\*Dialog Captured:\\*\\*' '$ROOT/tests/mock-data/findings_xss.md'"

check "Mock XSS findings has Screenshot" \
  bash -c "grep -qi 'screenshot' '$ROOT/tests/mock-data/findings_xss.md'"

###############################################################################
echo ""
echo "════════════════════════════════════════════════════════════════"
TOTAL=$((PASS + FAIL))
printf "  Results:  %d / %d passed" "$PASS" "$TOTAL"
if [ "$FAIL" -gt 0 ]; then
  printf ", \033[31m%d FAILED\033[0m" "$FAIL"
fi
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
  red "PHASE 2 STREAM C GATE: FAILED — $FAIL check(s) did not pass"
  exit 1
else
  green "PHASE 2 STREAM C GATE: PASSED — All checks passed!"
  exit 0
fi
