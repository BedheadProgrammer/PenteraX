#!/usr/bin/env python3
"""Run whatweb against a target and output structured JSON.

Usage:
    python3 run_whatweb.py <target_url> [--aggression LEVEL] [--output OUTPUT_JSON]

WhatWeb fingerprints web technologies (frameworks, CMS, JS libraries, server
software) from HTTP responses.  The JSON output is designed to merge into
the nmap scan results under ``scan_info.technologies``.

Falls back to a Python-based lightweight fingerprinter if whatweb is not
installed (common on Windows where Ruby is not available).
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Add project root so we can import tool_discovery
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from src.tool_discovery import find_tool
except ImportError:
    find_tool = None


# ---------------------------------------------------------------------------
# Lightweight fallback fingerprinter (no external dependency)
# ---------------------------------------------------------------------------

def _fingerprint_fallback(target_url: str) -> dict:
    """Python-based technology fingerprinting when whatweb is unavailable.

    Uses HTTP response headers and HTML content to identify technologies.
    Less thorough than whatweb but zero-dependency.
    """
    try:
        import requests
    except ImportError:
        return {
            "success": False,
            "error": "Neither whatweb nor the requests library is available.",
            "target": target_url,
            "technologies": [],
            "fallback": True,
        }

    technologies: list[dict[str, str]] = []

    try:
        resp = requests.get(target_url, timeout=15, allow_redirects=True)
        headers = resp.headers
        body = resp.text[:10000]  # First 10KB

        # Server header
        server = headers.get("Server", "")
        if server:
            technologies.append({"name": "Server", "version": server, "source": "header"})

        # X-Powered-By
        powered = headers.get("X-Powered-By", "")
        if powered:
            technologies.append({"name": "X-Powered-By", "version": powered, "source": "header"})

        # Express detection
        if "express" in powered.lower() or "express" in server.lower():
            technologies.append({"name": "Express", "version": powered, "source": "header"})

        # Content-Security-Policy hints
        csp = headers.get("Content-Security-Policy", "")
        if csp:
            technologies.append({"name": "CSP", "version": csp[:100], "source": "header"})

        # Angular detection
        if "ng-app" in body or "ng-version" in body or "<app-root" in body:
            ng_version = ""
            ng_match = re.search(r'ng-version="([^"]+)"', body)
            if ng_match:
                ng_version = ng_match.group(1)
            technologies.append({"name": "Angular", "version": ng_version, "source": "html"})

        # React detection
        if "react" in body.lower() or "__NEXT_DATA__" in body or "data-reactroot" in body:
            technologies.append({"name": "React", "version": "", "source": "html"})

        # jQuery detection
        jquery_match = re.search(r'jquery[.-](\d+\.\d+(?:\.\d+)?)', body, re.IGNORECASE)
        if jquery_match:
            technologies.append({"name": "jQuery", "version": jquery_match.group(1), "source": "html"})

        # Bootstrap detection
        if "bootstrap" in body.lower():
            bs_match = re.search(r'bootstrap[.-](\d+\.\d+(?:\.\d+)?)', body, re.IGNORECASE)
            ver = bs_match.group(1) if bs_match else ""
            technologies.append({"name": "Bootstrap", "version": ver, "source": "html"})

        # Cookie-based detection
        cookies = resp.headers.get("Set-Cookie", "")
        if "express" in cookies.lower() or "connect.sid" in cookies:
            technologies.append({"name": "Express Session", "version": "", "source": "cookie"})

        # Meta generator tag
        gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', body, re.IGNORECASE)
        if gen_match:
            technologies.append({"name": "Generator", "version": gen_match.group(1), "source": "meta"})

        # Detect common JS frameworks from script tags
        script_srcs = re.findall(r'src="([^"]+\.js)"', body)
        for src in script_srcs:
            lower = src.lower()
            if "angular" in lower or "ng-" in lower:
                technologies.append({"name": "Angular (JS)", "version": "", "source": "script"})
            elif "vue" in lower:
                technologies.append({"name": "Vue.js", "version": "", "source": "script"})
            elif "socket.io" in lower:
                technologies.append({"name": "Socket.IO", "version": "", "source": "script"})

        return {
            "success": True,
            "target": target_url,
            "status_code": resp.status_code,
            "technologies": technologies,
            "fallback": True,
            "note": "Results from lightweight Python fingerprinter (whatweb not available).",
        }

    except Exception as e:
        return {
            "success": False,
            "target": target_url,
            "error": str(e),
            "technologies": [],
            "fallback": True,
        }


# ---------------------------------------------------------------------------
# WhatWeb runner
# ---------------------------------------------------------------------------

def _parse_whatweb_json(raw_json: str) -> list[dict]:
    """Parse whatweb --log-json output (one JSON object per line)."""
    results = []
    for line in raw_json.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def _extract_technologies(whatweb_results: list[dict]) -> list[dict[str, str]]:
    """Extract a flat technology list from whatweb JSON output."""
    technologies = []
    for entry in whatweb_results:
        plugins = entry.get("plugins", {})
        for plugin_name, plugin_data in plugins.items():
            version = ""
            if isinstance(plugin_data, dict):
                ver_list = plugin_data.get("version", [])
                if ver_list and isinstance(ver_list, list):
                    version = ver_list[0]
                elif isinstance(ver_list, str):
                    version = ver_list
                string = plugin_data.get("string", [])
                if not version and string:
                    version = string[0] if isinstance(string, list) else str(string)
            technologies.append({
                "name": plugin_name,
                "version": str(version),
                "source": "whatweb",
            })
    return technologies


def run_whatweb(
    target_url: str,
    aggression: int = 3,
    timeout: int = 60,
) -> dict:
    """Execute whatweb and return structured JSON results.

    Falls back to Python-based fingerprinting if whatweb is not available.
    """
    # Try to find whatweb
    whatweb_path = None
    if find_tool is not None:
        info = find_tool("whatweb", skip_version=True)
        if info.available and info.path:
            whatweb_path = info.path
    else:
        whatweb_path = shutil.which("whatweb")

    if not whatweb_path:
        # Fall back to Python fingerprinter
        return _fingerprint_fallback(target_url)

    cmd = [
        whatweb_path,
        "--color=never",
        f"-a{aggression}",
        "--log-json=-",  # JSON output to stdout
        target_url,
    ]

    result = {
        "success": False,
        "command": " ".join(cmd),
        "target": target_url,
        "technologies": [],
        "raw_output": "",
        "fallback": False,
    }

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        result["raw_output"] = proc.stdout
        result["exit_code"] = proc.returncode

        if proc.returncode == 0 and proc.stdout.strip():
            whatweb_data = _parse_whatweb_json(proc.stdout)
            result["technologies"] = _extract_technologies(whatweb_data)
            result["raw_results"] = whatweb_data
            result["success"] = True
        else:
            result["error"] = proc.stderr or "whatweb produced no output"
            # Fall back if whatweb failed
            fallback = _fingerprint_fallback(target_url)
            result["technologies"] = fallback.get("technologies", [])
            result["fallback"] = True

    except subprocess.TimeoutExpired:
        result["error"] = f"whatweb timed out after {timeout}s"
        fallback = _fingerprint_fallback(target_url)
        result["technologies"] = fallback.get("technologies", [])
        result["fallback"] = True
    except FileNotFoundError:
        result["error"] = f"whatweb not found at {whatweb_path}"
        fallback = _fingerprint_fallback(target_url)
        result["technologies"] = fallback.get("technologies", [])
        result["fallback"] = True
    except OSError as e:
        result["error"] = str(e)
        fallback = _fingerprint_fallback(target_url)
        result["technologies"] = fallback.get("technologies", [])
        result["fallback"] = True

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Run whatweb (or fallback) for web technology fingerprinting."
    )
    parser.add_argument("target_url", help="Target URL to fingerprint.")
    parser.add_argument(
        "--aggression", "-a", type=int, default=3, choices=[1, 2, 3, 4],
        help="WhatWeb aggression level (default: 3).",
    )
    parser.add_argument("--output", help="Path to write JSON output file.")
    parser.add_argument(
        "--timeout", type=int, default=60,
        help="Timeout in seconds (default: 60).",
    )

    args = parser.parse_args()

    result = run_whatweb(
        target_url=args.target_url,
        aggression=args.aggression,
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
