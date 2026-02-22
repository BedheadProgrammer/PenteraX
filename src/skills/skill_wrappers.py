"""Typed wrapper functions for each SPAIDER skill.

These provide a clean Python API over the raw skill scripts so the pipeline
and agentic loop can call them without constructing CLI args manually.

Each function:
1. Accepts typed Python arguments
2. Invokes the underlying skill script via SkillRegistry.run()
3. Returns a structured SkillResult
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from .skill_loader import SkillRegistry, SkillResult

logger = logging.getLogger("spaider.skills")


# ---------------------------------------------------------------------------
# NetworkReconSkill wrappers
# ---------------------------------------------------------------------------

def parse_nmap(
    registry: SkillRegistry,
    xml_path: str | Path,
    output_path: str | Path | None = None,
    markdown: bool = True,
) -> SkillResult:
    """Parse nmap XML into structured JSON.

    Wraps ``skills/network-recon/scripts/parse_nmap.py``.

    Args:
        registry: The loaded SkillRegistry.
        xml_path: Path to the nmap XML output file.
        output_path: Optional path to write JSON output to.
        markdown: If True, also produce a markdown table on stderr.

    Returns:
        SkillResult with ``output`` set to the parsed JSON dict.
    """
    args = [str(xml_path)]
    if output_path:
        args += ["--output", str(output_path)]
    if markdown:
        args.append("--markdown")

    return registry.run("network-recon", "parse_nmap.py", args=args)


def nmap_to_markdown(scan_result: dict) -> str:
    """Convert a parse_nmap JSON result into a markdown table.

    This is a pure-Python helper that doesn't shell out — useful when you
    already have the parsed JSON in memory.
    """
    lines = ["| Port | Protocol | State | Service | Product | Version |"]
    lines.append("|------|----------|-------|---------|---------|---------|")

    for host in scan_result.get("hosts", []):
        for port in host.get("ports", []):
            lines.append(
                f"| {port['port']} | {port['protocol']} | {port['state']} "
                f"| {port['service']} | {port['product']} | {port['version']} |"
            )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ResponseAnalysisSkill wrappers
# ---------------------------------------------------------------------------

def validate_deliverable(
    registry: SkillRegistry,
    deliverable_path: str | Path,
    schema_type: str,
) -> SkillResult:
    """Validate a pipeline deliverable against its expected schema.

    Wraps ``skills/response-analysis/scripts/validate_response.py``.

    Args:
        registry: The loaded SkillRegistry.
        deliverable_path: Path to the deliverable markdown file.
        schema_type: One of "recon_report", "hypotheses", "findings", "pentest_report".

    Returns:
        SkillResult whose ``output`` is a dict with keys:
        ``valid`` (bool), ``errors`` (list[str]), ``error_count`` (int).
    """
    return registry.run(
        "response-analysis",
        "validate_response.py",
        args=[str(deliverable_path), schema_type],
    )


def validate_with_retry_context(
    validation_result: SkillResult,
    attempt: int,
    max_attempts: int = 3,
) -> str | None:
    """Build a retry-prompt injection string from a failed validation.

    Implements PenteraX §5.9 retry protocol.  Returns None if validation
    passed or retries are exhausted.

    Args:
        validation_result: The SkillResult from ``validate_deliverable``.
        attempt: Current attempt number (1-based).
        max_attempts: Maximum retries allowed.

    Returns:
        A string to inject into the agent's next prompt, or None.
    """
    if validation_result.success:
        return None
    if attempt >= max_attempts:
        return None

    errors = []
    if isinstance(validation_result.output, dict):
        errors = validation_result.output.get("errors", [])
    elif validation_result.errors:
        errors = validation_result.errors

    error_text = "\n".join(f"  - {e}" for e in errors)

    return (
        f"RETRY CONTEXT (attempt {attempt + 1}/{max_attempts}):\n"
        f"Your previous output failed validation.\n"
        f"Errors:\n{error_text}\n\n"
        f"Fix these specific issues in your next attempt. "
        f"Do not reproduce the same errors."
    )


# ---------------------------------------------------------------------------
# VulnerabilityLookupSkill wrappers
# ---------------------------------------------------------------------------

def lookup_cve(
    registry: SkillRegistry,
    product: str = "",
    version: str = "",
    cwe: str = "",
    keyword: str = "",
    severity: str = "",
) -> SkillResult:
    """Look up known CVEs for a product/version or CWE.

    Wraps ``skills/vulnerability-lookup/scripts/lookup_cve.py``.

    Args:
        registry: The loaded SkillRegistry.
        product: Software product name (e.g. "express").
        version: Version string (e.g. "4.17.1").
        cwe: CWE identifier (e.g. "CWE-89" or "89").
        keyword: Free-text keyword search.
        severity: Filter by severity level (CRITICAL, HIGH, MEDIUM, LOW).

    Returns:
        SkillResult whose ``output`` contains ``results`` list and ``total_results``.
    """
    args: list[str] = []
    if product:
        args += ["--product", product]
    if version:
        args += ["--version", version]
    if cwe:
        args += ["--cwe", cwe]
    if keyword:
        args += ["--keyword", keyword]
    if severity:
        args += ["--severity", severity]

    return registry.run(
        "vulnerability-lookup",
        "lookup_cve.py",
        args=args,
        timeout=30,
    )


def batch_lookup_cve(
    registry: SkillRegistry,
    tech_stack: list[dict[str, str]],
    batch_file_path: str | Path | None = None,
) -> SkillResult:
    """Batch-lookup CVEs for a list of technology/version pairs.

    Args:
        registry: The loaded SkillRegistry.
        tech_stack: List of dicts with ``product`` and ``version`` keys.
        batch_file_path: Where to write the temp batch JSON. If None, a
                         unique temporary file is created under the project
                         deliverables/ dir (Race condition #7 fix).

    Returns:
        SkillResult whose ``output`` is a list of lookup results.
    """
    from .skill_loader import PROJECT_ROOT

    cleanup_temp = False
    if batch_file_path is None:
        deliverables = PROJECT_ROOT / "deliverables"
        deliverables.mkdir(exist_ok=True)
        fd, batch_file_path = tempfile.mkstemp(
            suffix="_tech_stack_batch.json",
            dir=str(deliverables),
        )
        os.close(fd)
        cleanup_temp = True

    try:
        Path(batch_file_path).write_text(
            json.dumps(tech_stack, indent=2),
            encoding="utf-8",
        )

        result = registry.run(
            "vulnerability-lookup",
            "lookup_cve.py",
            args=["--batch-file", str(batch_file_path)],
            timeout=120,  # Batch lookups have rate-limit sleeps
        )
    finally:
        # Clean up the temp file we created
        if cleanup_temp:
            try:
                os.unlink(batch_file_path)
            except OSError:
                pass

    return result


def format_known_vulns_for_prompt(lookup_results: list[dict]) -> str:
    """Format CVE lookup results into a markdown block for agent prompt injection.

    Produces the ``{{KNOWN_VULNS}}`` template variable content that analysis
    agents consume.
    """
    if not lookup_results:
        return "No known vulnerabilities found for the target stack."

    lines = ["## Known Vulnerabilities for Target Stack\n"]

    for result in lookup_results:
        query = result.get("query", {})
        product = query.get("product", "unknown")
        version = query.get("version", "")
        header = f"{product} {version}".strip()

        vulns = result.get("results", [])
        if not vulns:
            continue

        lines.append(f"### {header}")
        for vuln in vulns:
            cve = vuln.get("cve_id", "N/A")
            sev = vuln.get("severity", "UNKNOWN")
            cvss = vuln.get("cvss_v3", 0.0)
            summary = vuln.get("summary", "")
            exploit = "yes" if vuln.get("exploit_available") else "no"
            cwe = vuln.get("cwe", "")

            line = f"- {cve} ({sev}, CVSS {cvss}): {summary}"
            if cwe:
                line += f" — {cwe}"
            line += f"\n  Exploit available: {exploit}"
            lines.append(line)

        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Nmap runner wrappers
# ---------------------------------------------------------------------------

def run_nmap(
    registry: SkillRegistry,
    target: str,
    profile: str = "web-focused",
    ports: str | None = None,
    xml_output: str | None = None,
    timeout: int = 180,
) -> SkillResult:
    """Run nmap against a target host and return structured JSON.

    Wraps ``skills/network-recon/scripts/run_nmap.py``.

    Args:
        registry: The loaded SkillRegistry.
        target: Target host or IP to scan.
        profile: Scan profile (quick, standard, stealth, web-focused).
        ports: Optional port specification override.
        xml_output: Optional path to save raw XML (not deleted).
        timeout: Subprocess timeout in seconds.

    Returns:
        SkillResult with ``output`` set to the structured scan JSON.
    """
    args = [target, "--profile", profile, "--timeout", str(timeout)]
    if ports:
        args += ["--ports", ports]
    if xml_output:
        args += ["--xml-output", xml_output]

    return registry.run("network-recon", "run_nmap.py", args=args, timeout=timeout + 30)


# ---------------------------------------------------------------------------
# WhatWeb / web fingerprinting wrappers
# ---------------------------------------------------------------------------

def run_whatweb(
    registry: SkillRegistry,
    target_url: str,
    aggression: int = 3,
    timeout: int = 60,
) -> SkillResult:
    """Run whatweb (or fallback fingerprinter) against a target URL.

    Wraps ``skills/network-recon/scripts/run_whatweb.py``.

    Args:
        registry: The loaded SkillRegistry.
        target_url: Target URL to fingerprint.
        aggression: WhatWeb aggression level 1-4 (default: 3).
        timeout: Subprocess timeout in seconds.

    Returns:
        SkillResult with ``output`` containing ``technologies`` list.
    """
    args = [target_url, "--aggression", str(aggression), "--timeout", str(timeout)]
    return registry.run("network-recon", "run_whatweb.py", args=args, timeout=timeout + 15)


def format_technologies_for_prompt(technologies: list[dict]) -> str:
    """Format whatweb/fingerprint results into a markdown block for prompt injection.

    Produces the ``{{TECHNOLOGIES}}`` template variable content.
    """
    if not technologies:
        return "No web technologies identified."

    lines = ["## Identified Web Technologies\n"]
    lines.append("| Technology | Version | Source |")
    lines.append("|------------|---------|--------|")
    for tech in technologies:
        name = tech.get("name", "unknown")
        version = tech.get("version", "")
        source = tech.get("source", "")
        lines.append(f"| {name} | {version} | {source} |")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SQLInjectionSkill wrappers
# ---------------------------------------------------------------------------

def run_sqlmap(
    registry: SkillRegistry,
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
) -> SkillResult:
    """Run sqlmap against a target endpoint to test for SQL injection.

    Wraps ``skills/sql-injection/scripts/run_sqlmap.py``.

    Args:
        registry: The loaded SkillRegistry.
        target_url: Target URL with query parameters.
        param: Parameter to test for injection.
        method: HTTP method (GET/POST). Auto-detected if None.
        data: POST body (JSON or form data).
        headers: Extra headers (comma-separated key:value).
        dbms: Target DBMS (default: sqlite for Juice Shop).
        level: Test level 1-5.
        risk: Risk level 1-3.
        technique: Injection techniques (default: BEUST).
        threads: Concurrent threads.
        tamper: Tamper scripts (comma-separated).
        dump_tables: If True, enumerate tables on confirmed injection.
        timeout: Subprocess timeout in seconds.

    Returns:
        SkillResult with ``output`` containing injection test results.
    """
    args = [
        target_url,
        "--param", param,
        "--dbms", dbms,
        "--level", str(level),
        "--risk", str(risk),
        "--technique", technique,
        "--threads", str(threads),
        "--timeout", str(timeout),
    ]
    if method:
        args += ["--method", method]
    if data:
        args += ["--data", data]
    if headers:
        args += ["--headers", headers]
    if tamper:
        args += ["--tamper", tamper]
    if dump_tables:
        args.append("--dump-tables")

    return registry.run("sql-injection", "run_sqlmap.py", args=args, timeout=timeout + 30)


def format_sqlmap_finding(sqlmap_result: dict, hypothesis_id: str = "") -> str:
    """Format a sqlmap result into a markdown finding block.

    Used to generate entries for ``findings_injection.md``.
    """
    injectable = sqlmap_result.get("injectable", False)
    target = sqlmap_result.get("target_url", "unknown")
    param = sqlmap_result.get("parameter", "unknown")
    technique = sqlmap_result.get("technique", "unknown")
    payloads = sqlmap_result.get("payloads", [])
    tables = sqlmap_result.get("tables", [])

    lines = []
    if hypothesis_id:
        lines.append(f"### Finding — Hypothesis {hypothesis_id}\n")
    else:
        lines.append(f"### SQL Injection Finding\n")

    lines.append(f"**Endpoint:** `{target}`")
    lines.append(f"**Parameter:** `{param}`")
    lines.append(f"**Injectable:** {'Yes' if injectable else 'No'}")

    if injectable:
        lines.append(f"**Technique:** {technique}")
        if payloads:
            lines.append("**Payloads:**")
            for payload in payloads[:5]:
                lines.append(f"- `{payload}`")
        if tables:
            lines.append(f"**Tables discovered:** {', '.join(tables[:10])}")
        lines.append(f"**Severity:** HIGH")
    else:
        lines.append("**Result:** No injection detected with current settings.")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTTP Request wrapper (curl-like)
# ---------------------------------------------------------------------------

def run_http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 30,
    max_response_bytes: int = 10_000,
    file_upload: dict[str, str] | None = None,
) -> SkillResult:
    """Send an HTTP request and return the response.

    This is a pure-Python implementation (no external skill script needed)
    that acts as the agent's ``curl`` equivalent.  It returns the status code,
    response headers, and a truncated response body.

    Args:
        url: Full URL to request.
        method: HTTP method (GET, POST, PUT, DELETE, etc.).
        headers: Optional dict of HTTP headers.
        body: Optional request body (string — typically JSON).
        timeout: Request timeout in seconds.
        max_response_bytes: Maximum bytes of response body to return.
        file_upload: Optional dict for multipart/form-data file upload.
            Keys: ``field`` (form field name), ``filename`` (upload filename),
            ``content`` (file content as string),
            ``content_type`` (MIME type, default ``application/octet-stream``).

    Returns:
        SkillResult with ``output`` containing status_code, headers, body, elapsed.
    """
    import time
    import urllib.request
    import urllib.error
    import urllib.parse

    start = time.monotonic()
    req_headers = dict(headers) if headers else {}

    try:
        # --- multipart/form-data handling ---
        if file_upload:
            import uuid
            boundary = f"----PenteraXBoundary{uuid.uuid4().hex[:12]}"
            field = file_upload.get("field", "file")
            filename = file_upload.get("filename", "upload.bin")
            content = file_upload.get("content", "")
            content_type = file_upload.get("content_type", "application/octet-stream")

            parts: list[bytes] = []
            parts.append(f"--{boundary}\r\n".encode())
            parts.append(
                f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode()
            )
            parts.append(f"Content-Type: {content_type}\r\n\r\n".encode())
            parts.append(content.encode("utf-8") if isinstance(content, str) else content)
            parts.append(f"\r\n--{boundary}--\r\n".encode())
            data_bytes = b"".join(parts)
            req_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        else:
            data_bytes = body.encode("utf-8") if body else None

        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers=req_headers,
            method=method.upper(),
        )

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            resp_headers = dict(resp.headers)
            raw_body = resp.read(max_response_bytes)
            try:
                body_text = raw_body.decode("utf-8", errors="replace")
            except Exception:
                body_text = repr(raw_body[:max_response_bytes])

        elapsed = time.monotonic() - start
        return SkillResult(
            success=True,
            skill_name="http-request",
            output={
                "status_code": status_code,
                "headers": resp_headers,
                "body": body_text,
                "body_length": len(body_text),
                "elapsed_seconds": round(elapsed, 3),
                "url": url,
                "method": method.upper(),
            },
        )

    except urllib.error.HTTPError as e:
        elapsed = time.monotonic() - start
        try:
            error_body = e.read(max_response_bytes).decode("utf-8", errors="replace")
        except Exception:
            error_body = ""
        return SkillResult(
            success=True,  # HTTP errors are still valid responses
            skill_name="http-request",
            output={
                "status_code": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": error_body,
                "body_length": len(error_body),
                "elapsed_seconds": round(elapsed, 3),
                "url": url,
                "method": method.upper(),
                "error": str(e.reason),
            },
        )

    except Exception as e:
        elapsed = time.monotonic() - start
        return SkillResult(
            success=False,
            skill_name="http-request",
            output={
                "error": str(e),
                "elapsed_seconds": round(elapsed, 3),
                "url": url,
                "method": method.upper(),
            },
            errors=[str(e)],
        )