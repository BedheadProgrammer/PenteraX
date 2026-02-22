#!/usr/bin/env python3
"""Validate SPAIDER pipeline deliverables against expected schemas.

Usage:
    python3 validate_response.py <deliverable_path> <schema_type>

Schema types: recon_report, hypotheses, findings, pentest_report

Exit codes:
    0 — validation passed
    1 — validation failed (errors printed to stdout as JSON)
"""

import json
import re
import sys


# ---------------------------------------------------------------------------
# Cross-cutting validation helpers (Phase 4 — Step 4.5)
# ---------------------------------------------------------------------------

def _check_target_url_consistency(content: str) -> list[str]:
    """Warn if deliverable references localhost / 127.0.0.1 instead of the AWS target."""
    errors: list[str] = []
    localhost_patterns = [
        r"https?://localhost[:/]",
        r"https?://127\.0\.0\.1[:/]",
        r"https?://\[::1\][:/]",
    ]
    for pat in localhost_patterns:
        matches = re.findall(pat, content, re.IGNORECASE)
        if matches:
            errors.append(
                f"Deliverable references localhost ({matches[0]}). "
                "Expected the remote AWS TARGET_URL instead."
            )
    return errors


def _check_evidence_authenticity(content: str) -> list[str]:
    """Sanity-check that HTTP status codes in evidence blocks are plausible."""
    errors: list[str] = []
    # Match patterns like "HTTP/1.1 999" or "status: 999" or "HTTP 999"
    status_codes = re.findall(
        r"(?:HTTP/\d\.\d\s+|status[:\s]+)(\d{3})", content, re.IGNORECASE
    )
    for code_str in status_codes:
        code = int(code_str)
        if code < 100 or code > 599:
            errors.append(
                f"Implausible HTTP status code {code} in evidence "
                "(valid range: 100–599)"
            )
    return errors


def _check_finding_deduplication(content: str) -> list[str]:
    """Warn if the same CVE ID appears multiple times in findings."""
    errors: list[str] = []
    cves = re.findall(r"(CVE-\d{4}-\d{4,})", content)
    seen: dict[str, int] = {}
    for cve in cves:
        seen[cve] = seen.get(cve, 0) + 1
    for cve, count in seen.items():
        if count > 1:
            errors.append(
                f"Duplicate CVE reference: {cve} appears {count} times"
            )
    return errors


def validate_recon_report(content: str) -> list[str]:
    """Validate a recon_report.md deliverable."""
    errors = []

    required_sections = [
        "## Technology Stack",
        "## Endpoints",
        "## Identified Sinks",
        "## Network Scan",
    ]
    for section in required_sections:
        if section not in content:
            errors.append(f"Missing required section: {section}")

    # Check for endpoint table
    if "## Endpoints" in content:
        # Split on level-2 headings only — (?!#) prevents matching ### or deeper
        after_endpoints = content.split("## Endpoints", 1)[1]
        endpoints_section = re.split(r"(?m)^## (?!#)", after_endpoints, maxsplit=1)[0]
        if "|" not in endpoints_section:
            errors.append(
                "## Endpoints section must contain a markdown table "
                "with columns: Route, Method, Parameters, Source File"
            )
        elif "Route" not in endpoints_section or "Method" not in endpoints_section:
            errors.append(
                "## Endpoints table must include Route and Method columns"
            )

    # Cross-cutting: target URL consistency check
    errors.extend(_check_target_url_consistency(content))

    return errors


def validate_hypotheses(content: str) -> list[str]:
    """Validate a hypotheses deliverable."""
    errors = []

    if "## Hypotheses" not in content:
        errors.append("Missing required section: ## Hypotheses")
        return errors

    # Check for at least one hypothesis
    hypothesis_pattern = r"### Hypothesis \d+"
    hypotheses = re.findall(hypothesis_pattern, content)
    if not hypotheses:
        errors.append(
            "Must contain at least one '### Hypothesis N' sub-heading"
        )
        return errors

    # Check each hypothesis has required fields
    required_fields = ["**Endpoint:**", "**Parameter:**", "**Payload:**", "**Expected Result:**"]
    hyp_sections = re.split(r"### Hypothesis \d+", content)[1:]  # skip pre-heading text
    for i, section in enumerate(hyp_sections, 1):
        for field in required_fields:
            if field not in section:
                errors.append(f"Hypothesis {i} missing required field: {field}")

    return errors


def validate_findings(content: str) -> list[str]:
    """Validate a findings deliverable."""
    errors = []

    if "## Findings" not in content:
        errors.append("Missing required section: ## Findings")
        return errors

    finding_pattern = r"### Finding \d+"
    findings = re.findall(finding_pattern, content)
    if not findings:
        errors.append("Must contain at least one '### Finding N' sub-heading")
        return errors

    required_fields = ["**Vulnerability:**", "**Proof:**", "**Severity:**"]
    finding_sections = re.split(r"### Finding \d+", content)[1:]
    for i, section in enumerate(finding_sections, 1):
        for field in required_fields:
            if field not in section:
                errors.append(f"Finding {i} missing required field: {field}")

        # Anti-hallucination: check proof is specific
        # Match proof text until the next known field marker, section heading, or end-of-string.
        # Using a simple \*\*|\Z lookahead would truncate proofs containing bold markdown.
        proof_match = re.search(
            r"\*\*Proof:\*\*\s*(.*?)(?=\*\*(?:Vulnerability|Severity|Evidence):\*\*|###\s|\Z)",
            section,
            re.DOTALL,
        )
        if proof_match:
            proof_text = proof_match.group(1).strip()
            generic_proofs = [
                "sql injection found",
                "xss found",
                "vulnerability found",
                "injection successful",
                "xss successful",
            ]
            if not proof_text:
                errors.append(
                    f"Finding {i}: **Proof:** is empty — must contain specific evidence"
                )
            elif proof_text.lower() in generic_proofs:
                errors.append(
                    f"Finding {i}: **Proof:** is too generic ('{proof_text}') — "
                    "must contain actual HTTP response data, extracted records, or DOM content"
                )

    # Cross-cutting: target URL consistency, evidence authenticity, deduplication
    errors.extend(_check_target_url_consistency(content))
    errors.extend(_check_evidence_authenticity(content))
    errors.extend(_check_finding_deduplication(content))

    return errors


def validate_pentest_report(content: str) -> list[str]:
    """Validate a pentest_report.md deliverable."""
    errors = []

    required_sections = [
        "## Executive Summary",
        "## Findings",
        "## Recommendations",
    ]
    for section in required_sections:
        if section not in content:
            errors.append(f"Missing required section: {section}")

    # Cross-cutting: target URL consistency and evidence checks
    errors.extend(_check_target_url_consistency(content))
    errors.extend(_check_evidence_authenticity(content))
    errors.extend(_check_finding_deduplication(content))

    return errors


VALIDATORS = {
    "recon_report": validate_recon_report,
    "hypotheses": validate_hypotheses,
    "findings": validate_findings,
    "pentest_report": validate_pentest_report,
}


def main() -> None:
    if len(sys.argv) < 3:
        print(
            "Usage: validate_response.py <deliverable_path> <schema_type>",
            file=sys.stderr,
        )
        print(f"Schema types: {', '.join(VALIDATORS.keys())}", file=sys.stderr)
        sys.exit(1)

    deliverable_path = sys.argv[1]
    schema_type = sys.argv[2]

    if schema_type not in VALIDATORS:
        print(
            f"Unknown schema type: {schema_type}. "
            f"Valid types: {', '.join(VALIDATORS.keys())}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        with open(deliverable_path, "r") as f:
            content = f.read()
    except FileNotFoundError:
        result = {
            "deliverable": deliverable_path,
            "schema_type": schema_type,
            "valid": False,
            "errors": [f"File not found: {deliverable_path}"],
            "error_count": 1,
        }
        print(json.dumps(result, indent=2))
        sys.exit(1)

    errors = VALIDATORS[schema_type](content)

    result = {
        "deliverable": deliverable_path,
        "schema_type": schema_type,
        "valid": len(errors) == 0,
        "errors": errors,
        "error_count": len(errors),
    }

    print(json.dumps(result, indent=2))
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
