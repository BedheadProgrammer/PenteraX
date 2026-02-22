#!/usr/bin/env python3
"""Run sqlmap against a target endpoint and output structured JSON.

Usage:
    python3 run_sqlmap.py <target_url> --param <PARAM> [OPTIONS]

Options:
    --param PARAM         Parameter to test for injection
    --method METHOD       HTTP method (default: auto-detect from URL)
    --data DATA           POST body (JSON string or form data)
    --headers HEADERS     Extra headers (comma-separated key:value pairs)
    --dbms DBMS           Target DBMS (default: sqlite for Juice Shop)
    --level N             Test level 1-5 (default: 3)
    --risk N              Risk level 1-3 (default: 2)
    --technique TECH      Injection techniques (default: BEUST)
    --threads N           Concurrent threads (default: 4)
    --timeout N           Subprocess timeout in seconds (default: 120)
    --tamper SCRIPTS      Tamper scripts (comma-separated)
    --dump-tables         Also enumerate tables if injection confirmed
    --output OUTPUT       Path to write JSON output file

Outputs JSON with injection results, technique used, and evidence.
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Add project root so we can import tool_discovery
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from src.tool_discovery import find_tool
except ImportError:
    find_tool = None


def locate_sqlmap() -> list[str]:
    """Find sqlmap and return the command prefix (list of strings).

    sqlmap may be:
    - A standalone executable on PATH
    - A pip-installed console script in the venv
    - Invocable via `python -m sqlmap`
    """
    # Try tool_discovery first
    if find_tool is not None:
        info = find_tool("sqlmap", skip_version=True)
        if info.available and info.path:
            if info.path.endswith(f"-m sqlmap"):
                return info.path.split()
            return [info.path]

    # Direct PATH lookup
    path = shutil.which("sqlmap")
    if path:
        return [path]

    # Check venv scripts directory
    venv_scripts = Path(sys.executable).parent
    for name in ("sqlmap.exe", "sqlmap"):
        candidate = venv_scripts / name
        if candidate.is_file():
            return [str(candidate)]

    # Fall back to python -m sqlmap
    try:
        result = subprocess.run(
            [sys.executable, "-m", "sqlmap", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return [sys.executable, "-m", "sqlmap"]
    except Exception:
        pass

    return []


def parse_sqlmap_output(raw_output: str) -> dict:
    """Extract structured information from sqlmap's text output."""
    result = {
        "injectable": False,
        "technique": "",
        "dbms": "",
        "payloads": [],
        "tables": [],
        "injection_points": [],
    }

    # Check for confirmed injection
    if "is vulnerable" in raw_output or "injectable" in raw_output.lower():
        result["injectable"] = True

    # Extract injection type/technique
    tech_patterns = [
        (r"Type:\s*(.+?)(?:\n|$)", "technique"),
        (r"back-end DBMS:\s*(.+?)(?:\n|$)", "dbms"),
    ]
    for pattern, key in tech_patterns:
        match = re.search(pattern, raw_output)
        if match:
            result[key] = match.group(1).strip()

    # Extract payloads
    payload_matches = re.findall(
        r"Payload:\s*(.+?)(?:\n|$)", raw_output
    )
    result["payloads"] = [p.strip() for p in payload_matches]

    # Extract table names
    table_section = re.search(
        r"Database:.*?\n((?:\[\*\]\s+\w+\n?)+)", raw_output, re.DOTALL
    )
    if table_section:
        tables = re.findall(r"\[\*\]\s+(\w+)", table_section.group(1))
        result["tables"] = tables

    # Also try the "available databases" pattern
    db_section = re.findall(r"\[\*\]\s+(\S+)", raw_output)
    if db_section and not result["tables"]:
        result["tables"] = db_section[:20]  # Cap at 20

    # Extract injection point details
    inj_blocks = re.findall(
        r"Parameter:\s*(.+?)\n(.*?)(?=Parameter:|---|\Z)",
        raw_output, re.DOTALL,
    )
    for param, block in inj_blocks:
        point = {"parameter": param.strip(), "types": []}
        types = re.findall(r"Type:\s*(.+?)(?:\n|$)", block)
        point["types"] = [t.strip() for t in types]
        result["injection_points"].append(point)

    return result


def run_sqlmap(
    target_url: str,
    param: str,
    method: str | None = None,
    data: str | None = None,
    headers: str | None = None,
    dbms: str = "sqlite",
    level: int = 3,
    risk: int = 2,
    technique: str = "BEUST",
    threads: int = 4,
    tamper: str | None = None,
    dump_tables: bool = False,
    timeout: int = 120,
) -> dict:
    """Execute sqlmap and return structured JSON results."""

    sqlmap_cmd = locate_sqlmap()
    if not sqlmap_cmd:
        return {
            "success": False,
            "error": "sqlmap not found. Install via: pip install sqlmap",
            "target_url": target_url,
            "parameter": param,
            "injectable": False,
        }

    # Build command
    cmd = sqlmap_cmd + [
        "-u", target_url,
        "-p", param,
        "--batch",              # Non-interactive
        f"--dbms={dbms}",
        f"--level={level}",
        f"--risk={risk}",
        f"--technique={technique}",
        f"--threads={threads}",
        "--flush-session",      # Fresh test each time
        "--disable-coloring",   # Clean output for parsing
    ]

    if method:
        cmd += ["--method", method]
    if data:
        cmd += ["--data", data]
    if headers:
        for header in headers.split(","):
            header = header.strip()
            if header:
                cmd += ["-H", header]
    if tamper:
        cmd += ["--tamper", tamper]
    if dump_tables:
        cmd += ["--tables"]

    # Use a temp directory for sqlmap output
    tmp_dir = tempfile.mkdtemp(prefix="sqlmap_")
    cmd += ["--output-dir", tmp_dir]

    result = {
        "success": False,
        "command": " ".join(cmd),
        "target_url": target_url,
        "parameter": param,
        "injectable": False,
        "technique": "",
        "dbms": dbms,
        "payloads": [],
        "tables": [],
        "evidence": {},
        "raw_output": "",
        "exit_code": -1,
    }

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            result["error"] = f"sqlmap timed out after {timeout}s"
            result["raw_output"] = ""
            return result

        result["raw_output"] = stdout
        result["exit_code"] = proc.returncode

        # Parse the output
        parsed = parse_sqlmap_output(stdout)
        result["injectable"] = parsed["injectable"]
        result["technique"] = parsed["technique"]
        if parsed["dbms"]:
            result["dbms"] = parsed["dbms"]
        result["payloads"] = parsed["payloads"]
        result["tables"] = parsed["tables"]
        result["injection_points"] = parsed.get("injection_points", [])

        # Check for sqlmap's session data
        try:
            for root, dirs, files in os.walk(tmp_dir):
                for f in files:
                    if f == "log":
                        log_path = Path(root) / f
                        log_content = log_path.read_text(encoding="utf-8", errors="replace")
                        result["evidence"]["log"] = log_content[:5000]
                    elif f == "target.txt":
                        target_path = Path(root) / f
                        result["evidence"]["target_info"] = target_path.read_text(
                            encoding="utf-8", errors="replace"
                        )[:2000]
        except Exception:
            pass

        result["success"] = True

    except FileNotFoundError:
        result["error"] = f"sqlmap binary not found: {sqlmap_cmd}"
    except OSError as e:
        result["error"] = f"Failed to execute sqlmap: {e}"
    finally:
        # Clean up temp directory
        try:
            import shutil as sh
            sh.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Run sqlmap SQL injection test and output structured JSON."
    )
    parser.add_argument("target_url", help="Target URL with query parameters.")
    parser.add_argument("--param", "-p", required=True, help="Parameter to test.")
    parser.add_argument("--method", help="HTTP method (GET/POST).")
    parser.add_argument("--data", help="POST data (JSON or form-encoded).")
    parser.add_argument("--headers", help="Extra headers (comma-separated key:value).")
    parser.add_argument("--dbms", default="sqlite", help="Target DBMS (default: sqlite).")
    parser.add_argument("--level", type=int, default=3, choices=range(1, 6), help="Test level 1-5.")
    parser.add_argument("--risk", type=int, default=2, choices=range(1, 4), help="Risk level 1-3.")
    parser.add_argument("--technique", default="BEUST", help="Injection techniques (default: BEUST).")
    parser.add_argument("--threads", type=int, default=4, help="Concurrent threads.")
    parser.add_argument("--tamper", help="Tamper scripts (comma-separated).")
    parser.add_argument("--dump-tables", action="store_true", help="Enumerate tables if injectable.")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout in seconds.")
    parser.add_argument("--output", help="Path to write JSON output file.")

    args = parser.parse_args()

    result = run_sqlmap(
        target_url=args.target_url,
        param=args.param,
        method=args.method,
        data=args.data,
        headers=args.headers,
        dbms=args.dbms,
        level=args.level,
        risk=args.risk,
        technique=args.technique,
        threads=args.threads,
        tamper=args.tamper,
        dump_tables=args.dump_tables,
        timeout=args.timeout,
    )

    json_str = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(json_str, encoding="utf-8")
        print(json.dumps({"success": True, "output_file": args.output}))
    else:
        print(json_str)


if __name__ == "__main__":
    main()
