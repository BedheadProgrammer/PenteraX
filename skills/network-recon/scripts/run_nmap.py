#!/usr/bin/env python3
"""Run nmap against a target and output structured JSON.

Usage:
    python3 run_nmap.py <target_host> [--ports PORTS] [--profile PROFILE]
                                       [--output OUTPUT_JSON] [--xml-output XML_PATH]
                                       [--timeout SECONDS]

Profiles:
    quick         -sV -T4 --top-ports 100
    standard      -sV -sC -T3 -p-
    stealth       -sS -T2 -Pn --top-ports 1000 --randomize-hosts
    web-focused   -sV -p 80,443,8080,8443,3000,5000,8000,9000 + HTTP scripts

Default profile is 'web-focused' (matches recon.md Step 2 for Juice Shop).

JSON output matches the parse_nmap.py schema so downstream consumers are compatible.
"""

import argparse
import json
import os
import platform
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
    find_tool = None  # Standalone fallback


# ---------------------------------------------------------------------------
# Scan profiles (from SKILL.md)
# ---------------------------------------------------------------------------

PROFILES = {
    "quick": ["-sV", "-T4", "--top-ports", "100"],
    "standard": ["-sV", "-sC", "-T3", "-p-"],
    "stealth": ["-sS", "-T2", "-Pn", "--top-ports", "1000", "--randomize-hosts"],
    "web-focused": [
        "-sV",
        "-p", "80,443,8080,8443,3000,5000,8000,9000",
        "--script", "http-enum,http-title,http-headers,http-methods",
    ],
}

# AWS-safe flags always applied
AWS_FLAGS = ["-Pn", "--host-timeout", "120s"]


def locate_nmap() -> str:
    """Find nmap binary using tool_discovery or fallback."""
    if find_tool is not None:
        info = find_tool("nmap", skip_version=True)
        if info.available and info.path:
            return info.path

    # Fallback: direct lookup
    path = shutil.which("nmap")
    if path:
        return path

    # Windows well-known paths
    if platform.system() == "Windows":
        for candidate in [
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
        ]:
            if Path(candidate).is_file():
                return candidate

    print(json.dumps({
        "success": False,
        "error": "nmap not found. Install nmap and ensure it is on PATH, "
                 "or set the NMAP_PATH environment variable.",
    }))
    sys.exit(1)


def run_nmap(
    target: str,
    profile: str = "web-focused",
    ports: str | None = None,
    xml_output: str | None = None,
    timeout: int = 180,
) -> dict:
    """Execute nmap and return structured JSON results."""

    nmap_path = locate_nmap()

    # Build command
    profile_flags = PROFILES.get(profile, PROFILES["web-focused"])
    cmd = [nmap_path] + profile_flags + AWS_FLAGS

    # Override ports if specified
    if ports:
        # Remove any existing -p flag from profile
        cleaned = []
        skip_next = False
        for flag in cmd[1:]:
            if skip_next:
                skip_next = False
                continue
            if flag == "-p":
                skip_next = True
                continue
            if flag.startswith("-p") and len(flag) > 2:
                continue
            cleaned.append(flag)
        cmd = [nmap_path] + cleaned + ["-p", ports]

    # Temp file for XML output
    if xml_output:
        xml_path = xml_output
    else:
        fd, xml_path = tempfile.mkstemp(suffix="_nmap_scan.xml")
        os.close(fd)

    cmd += ["-oX", xml_path, target]

    result = {
        "success": False,
        "command": " ".join(cmd),
        "target": target,
        "profile": profile,
        "scan_info": {},
        "hosts": [],
        "raw_stdout": "",
        "raw_stderr": "",
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
            result["error"] = f"nmap timed out after {timeout}s"
            result["raw_stdout"] = ""
            result["raw_stderr"] = ""
            return result

        result["raw_stdout"] = stdout
        result["raw_stderr"] = stderr
        result["exit_code"] = proc.returncode

        # Parse XML output using the sibling parse_nmap.py logic
        xml_file = Path(xml_path)
        if xml_file.exists() and xml_file.stat().st_size > 0:
            try:
                # Import the sibling parser
                parse_script = Path(__file__).parent / "parse_nmap.py"
                if parse_script.exists():
                    # Use the existing parser
                    import importlib.util
                    spec = importlib.util.spec_from_file_location("parse_nmap", str(parse_script))
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    parsed = mod.parse_nmap_xml(str(xml_path))
                    result["scan_info"] = parsed.get("scan_info", {})
                    result["hosts"] = parsed.get("hosts", [])
                    result["success"] = True
                else:
                    # Minimal inline parser
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(str(xml_path))
                    root = tree.getroot()
                    result["scan_info"] = {
                        "args": root.get("args", ""),
                        "scanner": root.get("scanner", "nmap"),
                        "version": root.get("version", ""),
                    }
                    result["success"] = True
            except Exception as e:
                result["parse_error"] = str(e)
                # Still mark success if nmap ran OK
                result["success"] = proc.returncode == 0

        elif proc.returncode == 0:
            result["success"] = True
            result["warning"] = "No XML output produced"

    except FileNotFoundError:
        result["error"] = f"nmap binary not found at {nmap_path}"
    except OSError as e:
        result["error"] = f"Failed to execute nmap: {e}"
    finally:
        # Clean up temp XML if we created it
        if not xml_output:
            try:
                os.unlink(xml_path)
            except OSError:
                pass

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Run nmap scan and output structured JSON."
    )
    parser.add_argument("target", help="Target host or IP to scan.")
    parser.add_argument(
        "--profile", choices=list(PROFILES.keys()), default="web-focused",
        help="Scan profile (default: web-focused).",
    )
    parser.add_argument("--ports", help="Override port specification (e.g. '80,443,3000').")
    parser.add_argument("--output", help="Path to write JSON output file.")
    parser.add_argument("--xml-output", help="Path to save raw nmap XML (not deleted).")
    parser.add_argument("--timeout", type=int, default=180, help="Timeout in seconds (default: 180).")

    args = parser.parse_args()

    result = run_nmap(
        target=args.target,
        profile=args.profile,
        ports=args.ports,
        xml_output=args.xml_output,
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
