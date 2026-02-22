"""Stream B1 — Standalone recon agent test against Juice Shop.

Runs just the recon phase (Phase 0) with a real Claude agent and tools.
Verifies the deliverable contains source-code-derived data.
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
logger = logging.getLogger("stream_b1")

from src.pipeline import run_phase_recon, PipelineConfig, DELIVERABLES_DIR, ensure_dir
from src.skills.skill_loader import SkillRegistry
from src.agent_runner import AgentRunner
from src.agent_loop import MCP_TOOLS, SkillToolDispatcher

# ── Configuration ──────────────────────────────────────────────────────────
TARGET_URL = "http://54.146.141.88:3000"
REPO_PATH = "./repos/juice-shop"
API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MAX_BUDGET = 5.0  # conservative budget cap for recon-only

if not API_KEY:
    print("ERROR: ANTHROPIC_API_KEY not set in environment or .env")
    sys.exit(1)

print(f"{'=' * 60}")
print(f"Stream B1 — Standalone Recon Agent Test")
print(f"{'=' * 60}")
print(f"  Target:  {TARGET_URL}")
print(f"  Repo:    {REPO_PATH}")
print(f"  Budget:  ${MAX_BUDGET:.2f}")
print(f"  Model:   claude-sonnet-4-20250514")
print()

# ── Setup ──────────────────────────────────────────────────────────────────
config = PipelineConfig(
    target_url=TARGET_URL,
    repo_path=REPO_PATH,
    output_dir=DELIVERABLES_DIR,
    max_retries=3,
)

registry = SkillRegistry()
dispatcher = SkillToolDispatcher(registry)

runner = AgentRunner(
    api_key=API_KEY,
    max_budget_usd=MAX_BUDGET,
    tools=MCP_TOOLS,
    tool_dispatcher=dispatcher,
    system_prompt=(
        "You are a cybersecurity reconnaissance agent performing the first phase "
        "of a penetration test. Your job is to analyze the pre-collected data "
        "and produce a comprehensive, structured recon_report.md. "
        "Use the provided tools (especially vulnerability_lookup_cve and "
        "save_deliverable) to complete your task. "
        "IMPORTANT: Save your final report using the save_deliverable tool "
        "with name='recon_report.md'."
    ),
)

agent_runner_fn = runner.run

# ── Run Recon Phase ────────────────────────────────────────────────────────
print("Starting recon phase...")
start = time.time()

result = run_phase_recon(
    registry=registry,
    config=config,
    agent_runner=agent_runner_fn,
)

elapsed = time.time() - start

# ── Report Results ─────────────────────────────────────────────────────────
print()
print(f"{'=' * 60}")
print(f"RECON PHASE RESULT")
print(f"{'=' * 60}")
print(f"  Success:      {result.success}")
print(f"  Deliverables: {result.deliverables}")
print(f"  Validation:   {result.validation_passed}")
print(f"  Duration:     {elapsed:.1f}s")
print(f"  API Cost:     ${runner.total_cost_usd:.4f}")
if result.errors:
    print(f"  Errors:")
    for e in result.errors:
        print(f"    - {e}")

# ── Verify Content Quality ─────────────────────────────────────────────────
recon_path = DELIVERABLES_DIR / "recon_report.md"
if recon_path.exists():
    content = recon_path.read_text(encoding="utf-8")
    print(f"\n  Report size: {len(content)} chars, {content.count(chr(10))} lines")

    # Quality checks
    checks = {
        "Has Technology Stack section": "## Technology Stack" in content or "## technology stack" in content.lower(),
        "Has Endpoints section": "## Endpoints" in content or "## endpoints" in content.lower(),
        "Has Sinks section": "Sink" in content or "sink" in content,
        "Contains source file references": any(
            ext in content for ext in [".ts", ".js", "routes/"]
        ),
        "Has structured table (pipes)": content.count("|") > 10,
        "Mentions SQL injection": "sql" in content.lower() or "injection" in content.lower(),
        "Mentions XSS": "xss" in content.lower() or "cross-site" in content.lower(),
        "Mentions sequelize": "sequelize" in content.lower(),
        "Has prioritized attack surface": "attack surface" in content.lower() or "prioriti" in content.lower(),
    }

    print(f"\nQuality Checks:")
    passed = 0
    for check_name, check_result in checks.items():
        status = "PASS" if check_result else "FAIL"
        if check_result:
            passed += 1
        print(f"  [{status}] {check_name}")

    print(f"\n  Quality: {passed}/{len(checks)} checks passed")
    print(f"\n  First 200 chars preview:")
    print(f"  {content[:200].strip()}")
else:
    print("\n  recon_report.md NOT generated!")
    sys.exit(1)

print(f"\n{'=' * 60}")
print(f"Stream B1 test complete.")
print(f"{'=' * 60}")
