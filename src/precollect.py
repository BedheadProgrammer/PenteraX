"""Hybrid pre-collection — gathers ground-truth recon data before the agent runs.

Implements the design decision from DESIGN_REVIEW.md §4:

    Data                  Collector              Mechanism
    ───────────────────   ───────────────────    ──────────────────────────────
    Source code analysis  Pipeline (pre-agent)   Python reads repo, pattern matching
    Nmap scan             Pipeline (pre-agent)   subprocess runs nmap, parses XML
    HTTP endpoint probing Pipeline (pre-agent)   requests library probes endpoints
    CVE lookup            Agent (existing tool)  Already works via vulnerability_lookup_cve
    Sink consolidation    Agent (reasoning)      LLM reasoning capability

Design requirements (DESIGN_REVIEW.md §5):
  1. Check ``stop_event`` between pre-collection steps  (RC #4 / #15)
  2. Graceful degradation per step — return descriptive fallback, never crash
  3. Prompt size management — configurable line limits per pattern category
  4. Nmap subprocess timeout with explicit ``proc.kill()``  (RC #10)
  5. No new shared mutable state — pure functions: config in, strings out
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .exceptions import PipelineAbortedError

logger = logging.getLogger("spaider.precollect")

# Maximum grep matches per pattern category (DESIGN_REVIEW §5 requirement #3)
_MAX_MATCHES_PER_CATEGORY = 60

# Nmap subprocess timeout in seconds (DESIGN_REVIEW §5 requirement #4)
_NMAP_TIMEOUT = 180

# HTTP probe timeout per request (seconds)
_HTTP_PROBE_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Stop-event helper (shared across all steps)
# ---------------------------------------------------------------------------

def _check_stop(stop_event: threading.Event | None) -> None:
    """Raise ``PipelineAbortedError`` if the user requested a stop."""
    if stop_event is not None and stop_event.is_set():
        raise PipelineAbortedError("Pipeline aborted by user.")


# ---------------------------------------------------------------------------
# 1. Source Code Analysis
# ---------------------------------------------------------------------------

def _grep_repo(repo_path: Path, pattern: str, paths: list[str],
               max_matches: int = _MAX_MATCHES_PER_CATEGORY) -> list[str]:
    """Search for *pattern* in files under *repo_path* / *paths*.

    Returns a list of ``file:line: content`` strings, capped at *max_matches*.
    Uses Python ``re`` (no shell — DESIGN_REVIEW §5 "What NOT to Do").
    """
    compiled = re.compile(pattern, re.IGNORECASE)
    matches: list[str] = []

    for rel_dir in paths:
        search_dir = repo_path / rel_dir
        if not search_dir.exists():
            continue
        # Handle both files and directories
        if search_dir.is_file():
            targets = [search_dir]
        else:
            targets = sorted(search_dir.rglob("*"))

        for fpath in targets:
            if not fpath.is_file():
                continue
            # Only search text-like files
            if fpath.suffix not in (".ts", ".js", ".json", ".html", ".yml", ".yaml",
                                    ".md", ".txt", ".mjs", ".cjs", ".jsx", ".tsx"):
                continue
            try:
                lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                if compiled.search(line):
                    rel = fpath.relative_to(repo_path)
                    matches.append(f"{rel}:{lineno}: {line.rstrip()}")
                    if len(matches) >= max_matches:
                        return matches
    return matches


def collect_source_analysis(
    repo_path: str | Path,
    stop_event: threading.Event | None = None,
    max_matches: int = _MAX_MATCHES_PER_CATEGORY,
) -> str:
    """Perform source-code analysis on the target repository.

    Implements recon.md Step 1 (Tasks 1.1–1.5) deterministically in Python.
    Returns a markdown-formatted string for injection as ``{{SOURCE_ANALYSIS}}``.

    This is a **pure function**: takes config in, returns a string out.
    No shared mutable state is created (DESIGN_REVIEW §5 requirement #5).
    """
    repo = Path(repo_path).resolve()
    if not repo.exists():
        msg = f"Repository not found at {repo_path} — source analysis unavailable."
        logger.warning(msg)
        return msg

    sections: list[str] = []
    sections.append("## Pre-collected Source Code Analysis\n")
    sections.append(f"Repository: `{repo_path}`\n")

    # ── Task 1.1 — Route Mapping ──────────────────────────────────────
    _check_stop(stop_event)
    sections.append("### Task 1.1 — Route Mapping\n")

    route_patterns = {
        "Express route registrations": (
            r"(app|router)\.(get|post|put|delete|patch|use)\s*\(",
            ["routes/", "server.ts"],
        ),
        "Angular client-side routes": (
            r"(path\s*:|RouterModule|Routes)",
            ["frontend/src/app/"],
        ),
    }

    for label, (pattern, search_paths) in route_patterns.items():
        matches = _grep_repo(repo, pattern, search_paths, max_matches)
        sections.append(f"**{label}** ({len(matches)} matches):\n")
        if matches:
            sections.append("```")
            sections.append("\n".join(matches))
            sections.append("```\n")
        else:
            sections.append("_No matches found._\n")

    # ── Task 1.2 — Sink Identification ────────────────────────────────
    _check_stop(stop_event)
    sections.append("### Task 1.2 — Sink Identification\n")

    sink_patterns = {
        "SQL injection sinks (raw queries, sequelize.query)": (
            r"(sequelize\.query|\.query\s*\(|raw\s*:\s*true|replacements)",
            ["routes/", "models/"],
        ),
        "XSS sinks (innerHTML, document.write, eval)": (
            r"(innerHTML|outerHTML|document\.write|eval\s*\(|\[innerHTML\]|bypassSecurityTrustHtml)",
            ["frontend/src/"],
        ),
        "Command injection sinks": (
            r"(child_process|exec\s*\(|spawn\s*\(|execFile\s*\()",
            ["routes/", "lib/"],
        ),
        "Path traversal sinks": (
            r"(path\.join|path\.resolve|readFile|createReadStream)",
            ["routes/"],
        ),
    }

    for label, (pattern, search_paths) in sink_patterns.items():
        matches = _grep_repo(repo, pattern, search_paths, max_matches)
        sections.append(f"**{label}** ({len(matches)} matches):\n")
        if matches:
            sections.append("```")
            sections.append("\n".join(matches))
            sections.append("```\n")
        else:
            sections.append("_No matches found._\n")

    # ── Task 1.3 — Auth Mechanism Analysis ────────────────────────────
    _check_stop(stop_event)
    sections.append("### Task 1.3 — Authentication Mechanism\n")

    auth_patterns = {
        "JWT / token handling": (
            r"(jwt|jsonwebtoken|verify\s*\(|sign\s*\()",
            ["routes/", "lib/"],
        ),
        "Auth middleware": (
            r"(middleware|authorize|authenticate|isAuthed|security\.)",
            ["routes/", "lib/", "server.ts"],
        ),
    }

    for label, (pattern, search_paths) in auth_patterns.items():
        matches = _grep_repo(repo, pattern, search_paths, max_matches)
        sections.append(f"**{label}** ({len(matches)} matches):\n")
        if matches:
            sections.append("```")
            sections.append("\n".join(matches))
            sections.append("```\n")
        else:
            sections.append("_No matches found._\n")

    # Check verify.ts specifically
    verify_ts = repo / "routes" / "verify.ts"
    if verify_ts.exists():
        try:
            content = verify_ts.read_text(encoding="utf-8", errors="replace")
            sections.append("**routes/verify.ts (full content):**\n")
            sections.append("```typescript")
            # Trim to reasonable size
            line_list = content.splitlines()
            if len(line_list) > 120:
                sections.append("\n".join(line_list[:120]))
                sections.append(f"... ({len(line_list) - 120} more lines)")
            else:
                sections.append(content)
            sections.append("```\n")
        except OSError:
            pass

    # ── Task 1.4 — Input Entry Point Mapping ─────────────────────────
    _check_stop(stop_event)
    sections.append("### Task 1.4 — Input Entry Points\n")

    input_patterns = {
        "Request parameter access": (
            r"(req\.query|req\.params|req\.body|req\.headers|req\.cookies)",
            ["routes/"],
        ),
        "Body parsing configuration": (
            r"(bodyParser|express\.json|express\.urlencoded|multer|busboy)",
            ["server.ts", "routes/"],
        ),
    }

    for label, (pattern, search_paths) in input_patterns.items():
        matches = _grep_repo(repo, pattern, search_paths, max_matches)
        sections.append(f"**{label}** ({len(matches)} matches):\n")
        if matches:
            sections.append("```")
            sections.append("\n".join(matches))
            sections.append("```\n")
        else:
            sections.append("_No matches found._\n")

    # ── Task 1.5 — Technology Stack Identification ────────────────────
    _check_stop(stop_event)
    sections.append("### Task 1.5 — Technology Stack\n")

    pkg_json = repo / "package.json"
    if pkg_json.exists():
        try:
            pkg_data = json.loads(pkg_json.read_text(encoding="utf-8"))
            deps = pkg_data.get("dependencies", {})
            dev_deps = pkg_data.get("devDependencies", {})

            # Key security-relevant packages
            key_packages = [
                "express", "angular", "@angular/core", "sequelize", "sqlite3",
                "jsonwebtoken", "sanitize-html", "helmet", "cors", "cookie-parser",
                "body-parser", "multer", "express-jwt", "passport",
                "juice-shop-ctf-cli", "pug", "ejs",
            ]

            sections.append("**Key dependencies from package.json:**\n")
            sections.append("| Package | Version | Type |")
            sections.append("|---------|---------|------|")
            for pkg_name in key_packages:
                if pkg_name in deps:
                    sections.append(f"| {pkg_name} | {deps[pkg_name]} | dependency |")
                elif pkg_name in dev_deps:
                    sections.append(f"| {pkg_name} | {dev_deps[pkg_name]} | devDependency |")

            # Also list ALL dependencies for completeness
            sections.append("\n**All dependencies:**\n")
            sections.append("| Package | Version |")
            sections.append("|---------|---------|")
            for name, ver in sorted(deps.items()):
                sections.append(f"| {name} | {ver} |")
            sections.append("")
        except (OSError, json.JSONDecodeError) as e:
            sections.append(f"_Could not parse package.json: {e}_\n")
    else:
        sections.append("_package.json not found._\n")

    result = "\n".join(sections)
    logger.info("Source analysis complete: %d characters, %d lines",
                len(result), result.count("\n"))
    return result


# ---------------------------------------------------------------------------
# 2. Nmap Scan
# ---------------------------------------------------------------------------

def collect_nmap_scan(
    target_url: str,
    stop_event: threading.Event | None = None,
    timeout: int = _NMAP_TIMEOUT,
) -> str:
    """Run nmap against the target and return structured results as markdown.

    Implements recon.md Step 2 with the security constraints from DESIGN_REVIEW:
    - Uses ``subprocess.Popen`` with explicit ``proc.kill()`` on timeout (RC #10)
    - Uses ``-Pn --host-timeout 120s`` for AWS targets (RC #12)
    - Returns descriptive fallback string on any failure (requirement #2)

    This is a **pure function**: takes config in, returns a string out.
    """
    _check_stop(stop_event)

    # Check nmap availability via tool_discovery
    nmap_path = None
    try:
        from .tool_discovery import find_tool
        info = find_tool("nmap", skip_version=True)
        if info.available and info.path:
            nmap_path = info.path
    except ImportError:
        nmap_path = shutil.which("nmap")

    if not nmap_path:
        nmap_path = shutil.which("nmap")

    if not nmap_path:
        msg = ("## Pre-collected Network Scan\n\n"
               "nmap is not installed or not on PATH — network scan unavailable.\n"
               "Install nmap and ensure it is on the system PATH to enable scanning.\n")
        logger.warning("nmap not found on PATH — skipping network scan")
        return msg

    # Extract host from target URL
    parsed = urlparse(target_url)
    host = parsed.hostname or parsed.netloc
    if not host:
        msg = ("## Pre-collected Network Scan\n\n"
               f"Could not extract hostname from target URL: {target_url}\n")
        logger.warning("Could not extract hostname from %s", target_url)
        return msg

    _check_stop(stop_event)

    # Create a temp file for XML output
    fd, xml_path = tempfile.mkstemp(suffix="_nmap_scan.xml")
    os.close(fd)

    # Build nmap command per recon.md Step 2
    cmd = [
        nmap_path,
        "-sV",
        "-p", "80,443,8080,8443,3000,5000,8000,9000",
        "--script", "http-enum,http-title,http-headers,http-methods",
        "-Pn",                   # Skip host discovery — AWS SGs may block ICMP (RC #12)
        "--host-timeout", "120s",  # AWS latency safety
        "-oX", xml_path,
        host,
    ]

    sections: list[str] = ["## Pre-collected Network Scan\n"]
    sections.append(f"Target host: `{host}` (extracted from `{target_url}`)\n")
    sections.append(f"Command: `{' '.join(cmd)}`\n")

    try:
        logger.info("Running nmap: %s", " ".join(cmd))
        # Use Popen for explicit kill on timeout (DESIGN_REVIEW §5 requirement #4)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Poll the subprocess in a loop so we can check stop_event frequently
        # instead of blocking on a single communicate() call (Phase 4 — Step 4.7).
        _POLL_INTERVAL = 0.25  # seconds between stop_event checks
        elapsed_wait = 0.0
        stdout, stderr = "", ""
        try:
            while proc.poll() is None:
                # Check stop_event every poll interval
                if stop_event is not None and stop_event.is_set():
                    proc.kill()
                    proc.wait(timeout=5)
                    raise PipelineAbortedError("Pipeline aborted by user.")
                time.sleep(_POLL_INTERVAL)
                elapsed_wait += _POLL_INTERVAL
                if elapsed_wait >= timeout:
                    raise subprocess.TimeoutExpired(cmd, timeout)
            # Process finished — collect output
            stdout = proc.stdout.read() if proc.stdout else ""
            stderr = proc.stderr.read() if proc.stderr else ""
        except subprocess.TimeoutExpired:
            # Explicit kill required — subprocess.run() may not terminate
            # the child on all platforms (DESIGN_REVIEW §5 requirement #4)
            proc.kill()
            proc.wait(timeout=5)  # Reap the zombie
            logger.warning("nmap timed out after %ds — killed.", timeout)
            sections.append(f"**nmap timed out after {timeout}s** — partial results may be available.\n")
            stdout, stderr = "", ""

        if proc.returncode == 0 or Path(xml_path).stat().st_size > 0:
            # Parse the XML output
            xml_content = Path(xml_path).read_text(encoding="utf-8", errors="replace")
            sections.append("**Scan completed successfully.**\n")

            # Try to extract key info from XML using simple parsing
            # (We use Python parsing rather than the skill script to keep this pure)
            scan_results = _parse_nmap_xml_simple(xml_content)
            if scan_results:
                sections.append("| Port | Protocol | State | Service | Product | Version |")
                sections.append("|------|----------|-------|---------|---------|---------|")
                for entry in scan_results:
                    sections.append(
                        f"| {entry['port']} | {entry['protocol']} | {entry['state']} "
                        f"| {entry['service']} | {entry['product']} | {entry['version']} |"
                    )
                sections.append("")

            if stdout.strip():
                sections.append("**nmap stdout:**\n```")
                sections.append(stdout.strip())
                sections.append("```\n")

            # Include raw XML for the agent to process further if needed
            if len(xml_content) < 20000:  # Don't blow up the prompt
                sections.append("<details><summary>Raw nmap XML</summary>\n")
                sections.append(f"```xml\n{xml_content}\n```\n")
                sections.append("</details>\n")
        else:
            sections.append(f"**nmap exited with code {proc.returncode}.**\n")
            if stderr:
                sections.append(f"stderr:\n```\n{stderr.strip()}\n```\n")

    except FileNotFoundError:
        sections.append("nmap binary not found — network scan unavailable.\n")
        logger.warning("nmap binary not found")
    except OSError as e:
        sections.append(f"nmap execution failed: {e}\n")
        logger.warning("nmap execution failed: %s", e)
    finally:
        # Clean up temp file
        try:
            os.unlink(xml_path)
        except OSError:
            pass

    result = "\n".join(sections)
    logger.info("Nmap scan complete: %d characters", len(result))
    return result


def _parse_nmap_xml_simple(xml_content: str) -> list[dict[str, str]]:
    """Minimal nmap XML parser — extract port/service/version info.

    Uses regex rather than xml.etree to be resilient against malformed XML
    from interrupted scans.
    """
    results: list[dict[str, str]] = []

    # Find all <port> ... </port> or self-closing port entries
    port_blocks = re.finditer(
        r'<port\s+protocol="([^"]*?)"\s+portid="([^"]*?)"[^>]*>'
        r'(.*?)'
        r'(?:</port>|/>)',
        xml_content,
        re.DOTALL,
    )

    for match in port_blocks:
        protocol = match.group(1)
        port = match.group(2)
        block = match.group(3)

        state = ""
        state_match = re.search(r'<state\s+state="([^"]*?)"', block)
        if state_match:
            state = state_match.group(1)

        service = product = version = ""
        svc_match = re.search(
            r'<service\s+([^>]*?)/?>', block
        )
        if svc_match:
            attrs = svc_match.group(1)
            name_m = re.search(r'name="([^"]*?)"', attrs)
            prod_m = re.search(r'product="([^"]*?)"', attrs)
            ver_m = re.search(r'version="([^"]*?)"', attrs)
            service = name_m.group(1) if name_m else ""
            product = prod_m.group(1) if prod_m else ""
            version = ver_m.group(1) if ver_m else ""

        results.append({
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "product": product,
            "version": version,
        })

    return results


# ---------------------------------------------------------------------------
# 3. HTTP Endpoint Probing
# ---------------------------------------------------------------------------

def collect_http_probes(
    target_url: str,
    stop_event: threading.Event | None = None,
    timeout: int = _HTTP_PROBE_TIMEOUT,
) -> str:
    """Probe known Juice Shop endpoints and return structured results.

    Implements recon.md Step 3. Uses the ``requests`` library to send real
    HTTP requests to the target and records status, content-type, and
    notable response patterns.

    Returns a markdown-formatted string for injection as ``{{HTTP_PROBE_RESULTS}}``.

    This is a **pure function**: takes config in, returns a string out.
    """
    try:
        import requests as req_lib
    except ImportError:
        msg = ("## Pre-collected HTTP Endpoint Probes\n\n"
               "requests library not installed — HTTP probing unavailable.\n")
        logger.warning("requests library not available for HTTP probing")
        return msg

    _check_stop(stop_event)

    base = target_url.rstrip("/")

    # Endpoints from recon.md Step 3
    probe_specs: list[dict[str, Any]] = [
        {"method": "GET",  "path": "/",                           "label": "Main page"},
        {"method": "GET",  "path": "/api/Products",               "label": "Product listing"},
        {"method": "GET",  "path": "/rest/products/search?q=test","label": "Search endpoint"},
        {"method": "POST", "path": "/rest/user/login",            "label": "Authentication",
         "json": {"email": "test@test.com", "password": "test"}},
        {"method": "GET",  "path": "/api/Feedbacks",              "label": "Feedback system"},
        {"method": "GET",  "path": "/api/Complaints",             "label": "Complaint submission"},
        {"method": "GET",  "path": "/api/Recycles",               "label": "Recycle endpoint"},
        {"method": "GET",  "path": "/rest/basket/1",              "label": "Shopping basket"},
        {"method": "GET",  "path": "/api/Challenges",             "label": "Challenge listing (meta)"},
        {"method": "GET",  "path": "/api/SecurityQuestions",      "label": "Security questions"},
        {"method": "POST", "path": "/api/Users",                  "label": "User registration",
         "json": {"email": "probe@test.com", "password": "Probe1234!", "passwordRepeat": "Probe1234!",
                  "securityQuestion": {"id": 1, "answer": "probe"}}},
        {"method": "GET",  "path": "/b2b/v2/orders",             "label": "B2B API"},
        {"method": "GET",  "path": "/api/Quantitys",             "label": "Quantity endpoint"},
        {"method": "GET",  "path": "/rest/memories",             "label": "Memories endpoint"},
        {"method": "GET",  "path": "/api/Cards",                 "label": "Payment cards"},
        {"method": "GET",  "path": "/api/Deliverys",             "label": "Delivery options"},
        {"method": "GET",  "path": "/api/Addresss",              "label": "Addresses"},
        {"method": "GET",  "path": "/profile",                   "label": "User profile"},
        {"method": "GET",  "path": "/ftp",                       "label": "FTP directory listing"},
        {"method": "GET",  "path": "/encryptionkeys",            "label": "Encryption keys"},
        {"method": "GET",  "path": "/metrics",                   "label": "Prometheus metrics"},
        {"method": "GET",  "path": "/snippets",                  "label": "Code snippets"},
        {"method": "GET",  "path": "/dataerasure",               "label": "Data erasure page"},
        {"method": "GET",  "path": "/api-docs",                  "label": "Swagger API docs"},
        {"method": "GET",  "path": "/rest/admin/application-configuration",
         "label": "Admin config"},
    ]

    sections: list[str] = ["## Pre-collected HTTP Endpoint Probes\n"]
    sections.append(f"Target: `{base}`\n")
    sections.append("| # | Method | Endpoint | Label | Status | Content-Type | Size | Notes |")
    sections.append("|---|--------|----------|-------|--------|--------------|------|-------|")

    reachable = 0
    total = len(probe_specs)

    for idx, spec in enumerate(probe_specs, 1):
        _check_stop(stop_event)

        method = spec["method"]
        url = f"{base}{spec['path']}"
        label = spec["label"]

        # Use a shorter timeout when stop has been requested or is imminent
        # so individual requests don't block stop-event propagation.
        req_timeout = min(timeout, 2) if (stop_event and stop_event.is_set()) else timeout

        try:
            if method == "GET":
                resp = req_lib.get(url, timeout=req_timeout, allow_redirects=True)
            elif method == "POST":
                resp = req_lib.post(url, json=spec.get("json"), timeout=req_timeout,
                                    allow_redirects=True)
            else:
                resp = req_lib.request(method, url, timeout=req_timeout,
                                       allow_redirects=True)

            status = resp.status_code
            ct = resp.headers.get("Content-Type", "")[:50]
            size = len(resp.content)
            notes = ""

            # Extract notable patterns
            if status < 400:
                reachable += 1
            if "application/json" in ct:
                try:
                    body = resp.json()
                    if isinstance(body, dict):
                        if "data" in body:
                            data = body["data"]
                            if isinstance(data, list):
                                notes = f"JSON array: {len(data)} items"
                            else:
                                notes = f"JSON object with 'data' key"
                        elif "error" in body:
                            notes = f"Error: {str(body.get('error', ''))[:60]}"
                        elif "message" in body:
                            notes = f"Msg: {str(body.get('message', ''))[:60]}"
                    elif isinstance(body, list):
                        notes = f"JSON array: {len(body)} items"
                except Exception:
                    notes = "JSON parse failed"
            elif "text/html" in ct:
                text = resp.text[:500]
                title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE)
                if title_match:
                    notes = f"Title: {title_match.group(1)[:50]}"

            sections.append(
                f"| {idx} | {method} | {spec['path']} | {label} "
                f"| {status} | {ct} | {size} | {notes} |"
            )

        except req_lib.Timeout:
            sections.append(
                f"| {idx} | {method} | {spec['path']} | {label} "
                f"| TIMEOUT | — | — | Timed out after {timeout}s |"
            )
        except req_lib.ConnectionError as e:
            sections.append(
                f"| {idx} | {method} | {spec['path']} | {label} "
                f"| CONN_ERR | — | — | {str(e)[:60]} |"
            )
        except Exception as e:
            sections.append(
                f"| {idx} | {method} | {spec['path']} | {label} "
                f"| ERROR | — | — | {str(e)[:60]} |"
            )

    sections.append(f"\n**Summary:** {reachable}/{total} endpoints reachable.\n")

    # Try to extract Angular routes from the JS bundle
    _check_stop(stop_event)
    try:
        main_page = req_lib.get(f"{base}/", timeout=timeout)
        # Look for main.js or runtime.js references
        js_refs = re.findall(r'src="((?:runtime|main|polyfills)[^"]*\.js)"', main_page.text)
        if js_refs:
            sections.append("### Client-Side JavaScript Bundles\n")
            sections.append("Detected bundles:")
            for js_ref in js_refs[:5]:
                sections.append(f"- `{js_ref}`")

            # Fetch main.js and extract route paths
            for js_ref in js_refs[:2]:  # Only first two to avoid bloat
                try:
                    js_url = f"{base}/{js_ref.lstrip('/')}"
                    js_resp = req_lib.get(js_url, timeout=timeout)
                    if js_resp.status_code == 200:
                        js_text = js_resp.text
                        # Extract Angular route paths
                        route_paths = set(re.findall(
                            r'path\s*:\s*["\']([^"\']+)["\']', js_text
                        ))
                        if route_paths:
                            sections.append(f"\n**Client routes extracted from `{js_ref}`:**")
                            for rp in sorted(route_paths)[:40]:
                                sections.append(f"- `/{rp}`")
                            sections.append("")
                except Exception:
                    pass
            sections.append("")
    except Exception as e:
        sections.append(f"\n_Could not extract client-side routes: {e}_\n")

    result = "\n".join(sections)
    logger.info("HTTP probing complete: %d/%d reachable, %d characters",
                reachable, total, len(result))
    return result


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------

def run_precollection(
    target_url: str,
    repo_path: str | Path,
    stop_event: threading.Event | None = None,
    skip_network: bool = False,
) -> dict[str, str]:
    """Run all pre-collection steps sequentially and return template variables.

    Returns a dict with keys:
    - ``SOURCE_ANALYSIS``: Source code analysis markdown
    - ``NMAP_RESULTS``: Nmap scan results markdown
    - ``HTTP_PROBE_RESULTS``: HTTP endpoint probe results markdown

    Per DESIGN_REVIEW §4.3 / "What NOT to Do":
    - Steps run **sequentially** (no parallelism)
    - ``stop_event`` is checked between each step (RC #4 / #15)
    - Each step degrades gracefully on failure (requirement #2)

    Args:
        target_url: Target URL for network scans.
        repo_path: Path to the source code repository.
        stop_event: If set, abort pre-collection early.
        skip_network: If True, skip expensive network operations (nmap,
                      HTTP probes).  Used when no agent_runner is provided
                      so tests don't waste 180s waiting for nmap to time out.
    """
    logger.info("=" * 60)
    logger.info("PRE-COLLECTION START")
    logger.info("  Target: %s | Repo: %s", target_url, repo_path)
    logger.info("=" * 60)

    start = time.time()
    results: dict[str, str] = {}

    # Step 1: Source code analysis (CRITICAL — do this FIRST, per ShannonAI)
    _check_stop(stop_event)
    logger.info("Pre-collection step 1/3: Source code analysis...")
    step_start = time.time()
    try:
        results["SOURCE_ANALYSIS"] = collect_source_analysis(
            repo_path, stop_event=stop_event
        )
    except PipelineAbortedError:
        raise
    except Exception as e:
        logger.warning("Source analysis failed (non-fatal): %s", e)
        results["SOURCE_ANALYSIS"] = (
            f"## Pre-collected Source Code Analysis\n\n"
            f"Source analysis failed: {e}\n"
        )
    logger.info("  Step 1 complete: %.1fs", time.time() - step_start)

    # Step 2: Nmap scan
    _check_stop(stop_event)
    if skip_network:
        logger.info("Pre-collection step 2/3: Network scan SKIPPED (skip_network=True)")
        results["NMAP_RESULTS"] = (
            "## Pre-collected Network Scan\n\n"
            "Network scan skipped (no agent_runner — test/validation mode).\n"
        )
    else:
        logger.info("Pre-collection step 2/3: Network scan (nmap)...")
        step_start = time.time()
        try:
            results["NMAP_RESULTS"] = collect_nmap_scan(
                target_url, stop_event=stop_event
            )
        except PipelineAbortedError:
            raise
        except Exception as e:
            logger.warning("Nmap scan failed (non-fatal): %s", e)
            results["NMAP_RESULTS"] = (
                f"## Pre-collected Network Scan\n\n"
                f"Network scan failed: {e}\n"
            )
        logger.info("  Step 2 complete: %.1fs", time.time() - step_start)

    # Step 3: HTTP endpoint probing
    _check_stop(stop_event)
    if skip_network:
        logger.info("Pre-collection step 3/3: HTTP probing SKIPPED (skip_network=True)")
        results["HTTP_PROBE_RESULTS"] = (
            "## Pre-collected HTTP Endpoint Probes\n\n"
            "HTTP probing skipped (no agent_runner — test/validation mode).\n"
        )
    else:
        logger.info("Pre-collection step 3/3: HTTP endpoint probing...")
        step_start = time.time()
        try:
            results["HTTP_PROBE_RESULTS"] = collect_http_probes(
                target_url, stop_event=stop_event
            )
        except PipelineAbortedError:
            raise
        except Exception as e:
            logger.warning("HTTP probing failed (non-fatal): %s", e)
            results["HTTP_PROBE_RESULTS"] = (
                f"## Pre-collected HTTP Endpoint Probes\n\n"
                f"HTTP probing failed: {e}\n"
            )
        logger.info("  Step 3 complete: %.1fs", time.time() - step_start)

    total_chars = sum(len(v) for v in results.values())
    logger.info("=" * 60)
    logger.info(
        "PRE-COLLECTION COMPLETE — %.1fs, %d total characters injected",
        time.time() - start,
        total_chars,
    )
    logger.info("=" * 60)

    return results
