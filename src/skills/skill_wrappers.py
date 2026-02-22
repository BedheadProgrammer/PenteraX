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
