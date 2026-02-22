"""Phase 1 Foundation — Comprehensive Verification Suite.

Tests all 3 streams:
  Stream A: Project Scaffold
  Stream B: Target Environment & Tools
  Stream C: Vulnerability Research
"""

import importlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

PASS = 0
FAIL = 0

def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}" + (f" — {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {label}" + (f" — {detail}" if detail else ""))


def main():
    global PASS, FAIL

    # ── STREAM A: PROJECT SCAFFOLD ──────────────────────────────────
    print("=" * 60)
    print("STREAM A: PROJECT SCAFFOLD")
    print("=" * 60)

    check("src/types.ts exists", Path("src/types.ts").exists())

    for d in ["src", "src/prompts", "src/prompts/shared", "deliverables", "repos"]:
        check(f"{d}/ directory exists", Path(d).exists())

    check(".gitignore exists", Path(".gitignore").exists())

    # package.json
    pkg = json.loads(Path("package.json").read_text())
    check("package.json: @anthropic-ai/sdk", "@anthropic-ai/sdk" in pkg.get("dependencies", {}))
    check("package.json: typescript devDep", "typescript" in pkg.get("devDependencies", {}))
    check("package.json: @types/node devDep", "@types/node" in pkg.get("devDependencies", {}))
    check("package.json: ts-node devDep", "ts-node" in pkg.get("devDependencies", {}))

    # tsconfig.json
    ts = json.loads(Path("tsconfig.json").read_text())
    check("tsconfig: strict=true", ts["compilerOptions"].get("strict") is True)
    check("tsconfig: target=ES2022", ts["compilerOptions"].get("target") == "ES2022")
    check("tsconfig: module=Node16", ts["compilerOptions"].get("module") == "Node16")

    # ── STREAM B: TARGET ENVIRONMENT & TOOLS ────────────────────────
    print()
    print("=" * 60)
    print("STREAM B: TARGET ENVIRONMENT & TOOLS")
    print("=" * 60)

    check("repos/juice-shop cloned", Path("repos/juice-shop").exists())
    check("repos/juice-shop has package.json", Path("repos/juice-shop/package.json").exists())

    nmap_path = shutil.which("nmap")
    check("nmap on PATH", nmap_path is not None, detail=str(nmap_path))

    curl_path = shutil.which("curl") or shutil.which("curl.exe")
    check("curl on PATH", curl_path is not None, detail=str(curl_path))

    sqlmap_spec = importlib.util.find_spec("sqlmap")
    check("sqlmap module installed", sqlmap_spec is not None)

    webtech_spec = importlib.util.find_spec("webtech")
    check("webtech (whatweb alt) installed", webtech_spec is not None)

    # ── STREAM C: VULNERABILITY RESEARCH ────────────────────────────
    print()
    print("=" * 60)
    print("STREAM C: VULNERABILITY RESEARCH")
    print("=" * 60)

    prompts = [
        "src/prompts/recon.md",
        "src/prompts/analysis-xss.md",
        "src/prompts/analysis-injection.md",
        "src/prompts/exploit-xss.md",
        "src/prompts/exploit-injection.md",
        "src/prompts/report.md",
        "src/prompts/shared/safety-rails.md",
        "src/prompts/shared/output-format.md",
        "src/prompts/shared/target-context.md",
    ]
    for p in prompts:
        exists = Path(p).exists()
        size = Path(p).stat().st_size if exists else 0
        check(p, exists and size > 50, detail=f"{size} bytes")

    skills_files = [
        "skills/network-recon/SKILL.md",
        "skills/network-recon/scripts/parse_nmap.py",
        "skills/response-analysis/SKILL.md",
        "skills/response-analysis/scripts/validate_response.py",
        "skills/vulnerability-lookup/SKILL.md",
        "skills/vulnerability-lookup/scripts/lookup_cve.py",
    ]
    for s in skills_files:
        check(s, Path(s).exists())

    # ── MODULE IMPORTS ──────────────────────────────────────────────
    print()
    print("=" * 60)
    print("MODULE IMPORT VERIFICATION")
    print("=" * 60)

    modules = [
        ("src.config", "AppConfig"),
        ("src.preflight", "run_preflight"),
        ("src.cli", "build_parser"),
        ("src.gui", "PenteraXApp"),
        ("src.pipeline", "PipelineConfig"),
        ("src.pipeline", "PipelineResult"),
        ("src.agent_loop", "SkillToolDispatcher"),
        ("src.agent_loop", "AgenticLoopConfig"),
        ("src.agent_runner", "AgentRunner"),
        ("src.skills", "parse_nmap"),
        ("src.skills.skill_loader", "SkillRegistry"),
        ("src.exceptions", "PenteraXError"),
        ("src.gui_events", "LogEvent"),
        ("src.gui_events", "PhaseStatusEvent"),
        ("src.gui_events", "PipelineCompleteEvent"),
        ("src.logging_handler", None),
    ]
    for mod_name, attr_name in modules:
        try:
            mod = importlib.import_module(mod_name)
            if attr_name:
                assert hasattr(mod, attr_name), f"{attr_name} not found"
            check(f"import {mod_name}" + (f".{attr_name}" if attr_name else ""), True)
        except Exception as exc:
            check(f"import {mod_name}", False, detail=str(exc))

    # ── CLI ARGUMENT PARSING ────────────────────────────────────────
    print()
    print("=" * 60)
    print("CLI ARGUMENT PARSING")
    print("=" * 60)

    from src.cli import build_parser
    parser = build_parser()

    args = parser.parse_args(["--target-url", "http://test:3000", "--api-key", "sk-test"])
    check("Basic CLI args", args.target_url == "http://test:3000" and args.api_key == "sk-test")

    args2 = parser.parse_args([
        "--target-url", "http://t:3000", "--api-key", "k",
        "--replay", "--resume-from", "exploit",
    ])
    check("--replay flag", args2.replay is True)
    check("--resume-from", args2.resume_from == "exploit")

    args3 = parser.parse_args(["pipeline", "--replay", "--resume-from", "report"])
    check("pipeline subcommand", args3.replay is True and args3.resume_from == "report")

    # ── SKILL SCRIPT EXECUTION ──────────────────────────────────────
    print()
    print("=" * 60)
    print("SKILL SCRIPT EXECUTION")
    print("=" * 60)

    # Skill scripts: no args → prints usage to stderr, exits 1 (expected behavior)
    for script, expected_exit in [
        ("skills/network-recon/scripts/parse_nmap.py", 1),
        ("skills/response-analysis/scripts/validate_response.py", 1),
        ("skills/vulnerability-lookup/scripts/lookup_cve.py", 1),
    ]:
        try:
            r = subprocess.run(
                [sys.executable, script],
                capture_output=True, text=True, timeout=15,
            )
            output = r.stderr + r.stdout
            has_usage = "usage" in output.lower() or "must specify" in output.lower()
            ok = r.returncode == expected_exit and has_usage
            check(f"{script} (no-args → usage)", ok, detail=f"exit={r.returncode}")
        except Exception as exc:
            check(f"{script} (no-args → usage)", False, detail=str(exc))

    # ── SUMMARY ─────────────────────────────────────────────────────
    print()
    print("=" * 60)
    total = PASS + FAIL
    if FAIL == 0:
        print(f"ALL {total} CHECKS PASSED — Phase 1 Foundation COMPLETE")
    else:
        print(f"{PASS}/{total} passed, {FAIL} FAILED")
    print("=" * 60)

    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
