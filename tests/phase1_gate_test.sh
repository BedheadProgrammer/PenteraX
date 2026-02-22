#!/usr/bin/env bash
###############################################################################
# Phase 1 Gate Test — PenteraX
#
# Validates every gate criterion and work-stream deliverable defined in
# phases/phase-1-foundation.md.  Exit code 0 = all gates pass.
###############################################################################

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0
WARN=0

green()  { printf "\033[32m✅  %s\033[0m\n" "$*"; }
red()    { printf "\033[31m❌  %s\033[0m\n" "$*"; }
yellow() { printf "\033[33m⚠️   %s\033[0m\n" "$*"; }

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

warn_check() {
  local desc="$1"; shift
  if "$@" > /dev/null 2>&1; then
    green "$desc"
    PASS=$((PASS + 1))
  else
    yellow "$desc (non-blocking)"
    WARN=$((WARN + 1))
  fi
}

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          PenteraX — Phase 1 Foundation Gate Test            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

###############################################################################
echo "── Gate Criteria ────────────────────────────────────────────────"
###############################################################################

# G1: npm install succeeds
check "npm install succeeds" \
  bash -c "cd '$ROOT' && npm install --ignore-scripts 2>&1"

# G2: TypeScript compiles
check "npx tsc --noEmit succeeds" \
  bash -c "cd '$ROOT' && npx tsc --noEmit 2>&1"

# G3: Juice Shop accessible
check "Juice Shop accessible at http://54.146.141.88:3000" \
  bash -c "curl -sf --connect-timeout 5 http://54.146.141.88:3000 > /dev/null"

# G4: Juice Shop source cloned
check "repos/juice-shop/ exists" \
  test -d "$ROOT/repos/juice-shop"

# G5: External tools
check "nmap available"    command -v nmap
check "whatweb available" command -v whatweb
check "sqlmap available"  command -v sqlmap
check "curl available"    command -v curl

# G6: .env with API key
check ".env file exists" \
  test -f "$ROOT/.env"
check ".env contains ANTHROPIC_API_KEY" \
  bash -c "grep -q 'ANTHROPIC_API_KEY' '$ROOT/.env'"

# G7: XSS research documented
check "XSS research notes exist" \
  test -f "$ROOT/deliverables/xss-research-notes.md"

###############################################################################
echo ""
echo "── Stream A — Project Scaffold ──────────────────────────────────"
###############################################################################

check "package.json exists" \
  test -f "$ROOT/package.json"

check "@anthropic-ai/sdk in dependencies" \
  bash -c "grep -q '@anthropic-ai/sdk' '$ROOT/package.json'"

check "typescript in devDependencies" \
  bash -c "grep -q 'typescript' '$ROOT/package.json'"

check "ts-node in devDependencies" \
  bash -c "grep -q 'ts-node' '$ROOT/package.json'"

check "@types/node in devDependencies" \
  bash -c "grep -q '@types/node' '$ROOT/package.json'"

check "tsconfig.json exists" \
  test -f "$ROOT/tsconfig.json"

check "tsconfig target is ES2022" \
  bash -c "grep -q 'ES2022' '$ROOT/tsconfig.json'"

check "tsconfig strict mode enabled" \
  bash -c "grep -q '\"strict\": true' '$ROOT/tsconfig.json'"

check ".gitignore exists" \
  test -f "$ROOT/.gitignore"

check ".gitignore includes node_modules/" \
  bash -c "grep -q 'node_modules/' '$ROOT/.gitignore'"

check ".gitignore includes .env" \
  bash -c "grep -q '\.env' '$ROOT/.gitignore'"

check ".gitignore includes repos/" \
  bash -c "grep -q 'repos/' '$ROOT/.gitignore'"

check "src/ directory exists" \
  test -d "$ROOT/src"

check "src/prompts/ directory exists" \
  test -d "$ROOT/src/prompts"

check "src/prompts/shared/ directory exists" \
  test -d "$ROOT/src/prompts/shared"

check "deliverables/ directory exists" \
  test -d "$ROOT/deliverables"

check "repos/ directory exists" \
  test -d "$ROOT/repos"

check "src/types.ts exists" \
  test -f "$ROOT/src/types.ts"

check "types.ts has PipelinePhase" \
  bash -c "grep -q 'PipelinePhase' '$ROOT/src/types.ts'"

check "types.ts has Vulnerability" \
  bash -c "grep -q 'Vulnerability' '$ROOT/src/types.ts'"

check "types.ts has ReconResult" \
  bash -c "grep -q 'ReconResult' '$ROOT/src/types.ts'"

check "types.ts has ExploitAttempt" \
  bash -c "grep -q 'ExploitAttempt' '$ROOT/src/types.ts'"

check "types.ts has PipelineConfig" \
  bash -c "grep -q 'PipelineConfig' '$ROOT/src/types.ts'"

check "types.ts has PipelineResult" \
  bash -c "grep -q 'PipelineResult' '$ROOT/src/types.ts'"

###############################################################################
echo ""
echo "── Stream B — Target Environment & Tools ────────────────────────"
###############################################################################

check "Juice Shop HTTP 200" \
  bash -c "[ \"$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://54.146.141.88:3000)\" = '200' ]"

check "repos/juice-shop has package.json" \
  test -f "$ROOT/repos/juice-shop/package.json"

check "nmap version ≥ 7" \
  bash -c "nmap --version 2>&1 | grep -qE 'Nmap version [7-9]'"

check "whatweb version present" \
  bash -c "whatweb --version 2>&1 | grep -qi 'whatweb'"

check "sqlmap version present" \
  bash -c "sqlmap --version 2>&1 | grep -qE '^[0-9]+\.[0-9]'"

###############################################################################
echo ""
echo "── Stream C — Vulnerability Research ────────────────────────────"
###############################################################################

check "Research notes document DOM XSS in search" \
  bash -c "grep -qi 'DOM XSS' '$ROOT/deliverables/xss-research-notes.md'"

check "Research notes document Reflected XSS" \
  bash -c "grep -qi 'Reflected XSS' '$ROOT/deliverables/xss-research-notes.md'"

check "Research notes document Stored XSS" \
  bash -c "grep -qi 'Stored XSS' '$ROOT/deliverables/xss-research-notes.md'"

check "Research notes include payloads" \
  bash -c "grep -qi 'payload' '$ROOT/deliverables/xss-research-notes.md'"

check "Research notes include endpoint structure" \
  bash -c "grep -qiE 'endpoint|route' '$ROOT/deliverables/xss-research-notes.md'"

check "Research notes include Playwright patterns" \
  bash -c "grep -qi 'playwright' '$ROOT/deliverables/xss-research-notes.md'"

check "Research notes include default credentials" \
  bash -c "grep -qi 'admin@juice-sh.op' '$ROOT/deliverables/xss-research-notes.md'"

###############################################################################
echo ""
echo "════════════════════════════════════════════════════════════════"
TOTAL=$((PASS + FAIL + WARN))
printf "  Results:  %d / %d passed" "$PASS" "$TOTAL"
if [ "$WARN" -gt 0 ]; then
  printf ", %d warnings" "$WARN"
fi
if [ "$FAIL" -gt 0 ]; then
  printf ", \033[31m%d FAILED\033[0m" "$FAIL"
fi
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
  red "PHASE 1 GATE: FAILED — $FAIL check(s) did not pass"
  exit 1
else
  green "PHASE 1 GATE: PASSED — All checks passed!"
  exit 0
fi
