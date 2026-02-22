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

        # CVSS check: findings should include a CVSS score
        if "CVSS" not in section and "cvss" not in section.lower():
            errors.append(
                f"Finding {i}: Missing CVSS score — each finding should include "
                "a CVSS v3.1 score in the Severity field"
            )

    # Cross-cutting: target URL consistency, evidence authenticity, deduplication
    errors.extend(_check_target_url_consistency(content))
    errors.extend(_check_evidence_authenticity(content))
    errors.extend(_check_finding_deduplication(content))

    return errors


# ---------------------------------------------------------------------------
# Category-specific hypothesis validators (Phase E — Validation & Quality)
# ---------------------------------------------------------------------------

def validate_hypotheses_auth(content: str) -> list[str]:
    """Validate a hypotheses_auth.md deliverable (Broken Authentication)."""
    errors = validate_hypotheses(content)

    # Auth-specific: at least one hypothesis should reference auth-related endpoints
    auth_keywords = [
        "login", "jwt", "token", "password", "session", "cookie",
        "authentication", "credential", "brute.?force", "rate.?limit",
        "security.?question", "reset", "hsts", "alg.*none",
    ]
    if "## Hypotheses" in content:
        hyp_block = content.split("## Hypotheses", 1)[1]
        found_auth = any(
            re.search(kw, hyp_block, re.IGNORECASE) for kw in auth_keywords
        )
        if not found_auth:
            errors.append(
                "Auth hypotheses should reference at least one authentication "
                "concept (login, JWT, token, password, session, credential, "
                "brute-force, rate-limit, security-question, reset, HSTS)"
            )
    return errors


def validate_hypotheses_authz(content: str) -> list[str]:
    """Validate a hypotheses_authz.md deliverable (Broken Authorization / IDOR)."""
    errors = validate_hypotheses(content)

    # Authz-specific: at least one hypothesis should reference authorization concepts
    authz_keywords = [
        "idor", "authorization", "privilege", "escalation", "access.?control",
        "basket", "admin", "role", "mass.?assignment", "/api/Users",
        "/api/Feedbacks", "/rest/basket", "cross.?user",
    ]
    if "## Hypotheses" in content:
        hyp_block = content.split("## Hypotheses", 1)[1]
        found_authz = any(
            re.search(kw, hyp_block, re.IGNORECASE) for kw in authz_keywords
        )
        if not found_authz:
            errors.append(
                "Authorization hypotheses should reference at least one authz "
                "concept (IDOR, privilege escalation, access control, basket, "
                "admin role, mass assignment, cross-user access)"
            )
    return errors


def validate_hypotheses_ssrf(content: str) -> list[str]:
    """Validate a hypotheses_ssrf.md deliverable (SSRF)."""
    errors = validate_hypotheses(content)

    # SSRF-specific: hypotheses should reference SSRF-related concepts
    ssrf_keywords = [
        "ssrf", "server.?side", "request.?forgery", "url", "localhost",
        "internal", "profile.?image", "imageUrl", "method.?bypass",
        "/profile/image/url",
    ]
    if "## Hypotheses" in content:
        hyp_block = content.split("## Hypotheses", 1)[1]
        found_ssrf = any(
            re.search(kw, hyp_block, re.IGNORECASE) for kw in ssrf_keywords
        )
        if not found_ssrf:
            errors.append(
                "SSRF hypotheses should reference at least one SSRF concept "
                "(SSRF, server-side request forgery, URL, localhost, internal "
                "resource, profile image URL, method bypass)"
            )

    # Safety: flag hypotheses that target cloud metadata in production scope
    if re.search(r"169\.254\.169\.254", content):
        errors.append(
            "WARNING: Hypothesis references cloud metadata endpoint "
            "(169.254.169.254). This is prohibited in production environments "
            "per safety-rails.md — ensure this is only used in controlled lab "
            "environments."
        )
    return errors


# ---------------------------------------------------------------------------
# Category-specific findings validators (Phase E — Validation & Quality)
# ---------------------------------------------------------------------------

def validate_findings_auth(content: str) -> list[str]:
    """Validate a findings_auth.md deliverable (Broken Authentication)."""
    errors = validate_findings(content)

    # Auth findings should reference authentication-specific vulnerability types
    auth_vuln_types = [
        "authentication", "credential", "jwt", "token", "password",
        "session", "brute.?force", "login", "cookie",
    ]
    if "## Findings" in content:
        findings_block = content.split("## Findings", 1)[1]
        finding_sections = re.split(r"### Finding \d+", findings_block)[1:]
        for i, section in enumerate(finding_sections, 1):
            vuln_match = re.search(
                r"\*\*Vulnerability:\*\*\s*(.+?)(?=\n|\*\*)", section
            )
            if vuln_match:
                vuln_text = vuln_match.group(1)
                is_auth_related = any(
                    re.search(kw, vuln_text, re.IGNORECASE)
                    for kw in auth_vuln_types
                )
                if not is_auth_related:
                    errors.append(
                        f"Finding {i}: Vulnerability type '{vuln_text.strip()}' "
                        "does not appear to be authentication-related — "
                        "auth findings should describe credential, JWT, session, "
                        "or login-related vulnerabilities"
                    )
    return errors


def validate_findings_authz(content: str) -> list[str]:
    """Validate a findings_authz.md deliverable (Broken Authorization / IDOR)."""
    errors = validate_findings(content)

    # Authz findings should reference authorization-specific vulnerability types
    authz_vuln_types = [
        "idor", "authorization", "privilege", "escalation", "access.?control",
        "direct.?object", "mass.?assignment", "role",
    ]
    if "## Findings" in content:
        findings_block = content.split("## Findings", 1)[1]
        finding_sections = re.split(r"### Finding \d+", findings_block)[1:]
        for i, section in enumerate(finding_sections, 1):
            vuln_match = re.search(
                r"\*\*Vulnerability:\*\*\s*(.+?)(?=\n|\*\*)", section
            )
            if vuln_match:
                vuln_text = vuln_match.group(1)
                is_authz_related = any(
                    re.search(kw, vuln_text, re.IGNORECASE)
                    for kw in authz_vuln_types
                )
                if not is_authz_related:
                    errors.append(
                        f"Finding {i}: Vulnerability type '{vuln_text.strip()}' "
                        "does not appear to be authorization-related — "
                        "authz findings should describe IDOR, privilege escalation, "
                        "access control, or role-related vulnerabilities"
                    )

    # Authz-specific: check that IDOR findings include the resource ID tested
    if "## Findings" in content:
        findings_block = content.split("## Findings", 1)[1]
        finding_sections = re.split(r"### Finding \d+", findings_block)[1:]
        for i, section in enumerate(finding_sections, 1):
            if re.search(r"idor", section, re.IGNORECASE):
                if not re.search(r"/:?\d+|:id|user_?id|basket_?id|BasketId", section, re.IGNORECASE):
                    errors.append(
                        f"Finding {i}: IDOR finding should reference the "
                        "specific resource ID or ID parameter that was accessed"
                    )
    return errors


def validate_findings_ssrf(content: str) -> list[str]:
    """Validate a findings_ssrf.md deliverable (SSRF)."""
    errors = validate_findings(content)

    # SSRF findings should reference SSRF-specific vulnerability types
    ssrf_vuln_types = [
        "ssrf", "server.?side", "request.?forgery", "url",
        "internal", "redirect",
    ]
    if "## Findings" in content:
        findings_block = content.split("## Findings", 1)[1]
        finding_sections = re.split(r"### Finding \d+", findings_block)[1:]
        for i, section in enumerate(finding_sections, 1):
            vuln_match = re.search(
                r"\*\*Vulnerability:\*\*\s*(.+?)(?=\n|\*\*)", section
            )
            if vuln_match:
                vuln_text = vuln_match.group(1)
                is_ssrf_related = any(
                    re.search(kw, vuln_text, re.IGNORECASE)
                    for kw in ssrf_vuln_types
                )
                if not is_ssrf_related:
                    errors.append(
                        f"Finding {i}: Vulnerability type '{vuln_text.strip()}' "
                        "does not appear to be SSRF-related — "
                        "SSRF findings should describe server-side request forgery, "
                        "URL injection, or internal resource access vulnerabilities"
                    )

    # Safety: flag findings that accessed cloud metadata
    if re.search(r"169\.254\.169\.254", content):
        errors.append(
            "SAFETY VIOLATION: Findings reference cloud metadata endpoint "
            "(169.254.169.254). This is prohibited per safety-rails.md. "
            "SSRF testing must be scoped to the target Juice Shop only."
        )

    # SSRF-specific: localhost/127.0.0.1 in proof should reference the target app,
    # not arbitrary external services
    if "## Findings" in content:
        findings_block = content.split("## Findings", 1)[1]
        proof_blocks = re.findall(
            r"\*\*Proof:\*\*\s*(.*?)(?=\*\*(?:Vulnerability|Severity|Evidence):\*\*|###\s|\Z)",
            findings_block, re.DOTALL,
        )
        for i, proof in enumerate(proof_blocks, 1):
            # Localhost in SSRF proofs is expected (it's the SSRF payload target),
            # but ensure it targets the app port, not arbitrary services
            non_app_localhost = re.findall(
                r"https?://(?:localhost|127\.0\.0\.1):(\d+)", proof
            )
            for port in non_app_localhost:
                if int(port) not in (3000, 3001, 80, 443):
                    errors.append(
                        f"Finding {i}: SSRF proof targets localhost:{port} — "
                        "only Juice Shop ports (3000/3001) are in scope"
                    )
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

    # Enhanced: check for Scope Limitations section
    if "## Scope Limitations" not in content and "## Scope & Methodology" not in content:
        errors.append(
            "Missing recommended section: ## Scope Limitations — "
            "report should explicitly note which vulnerability classes were NOT tested"
        )

    # Enhanced: check for CVSS scores in findings
    if "## Findings" in content:
        findings_section = content.split("## Findings", 1)[1]
        # Split at the next level-2 heading to isolate findings
        findings_only = re.split(r"(?m)^## (?!#)", findings_section, maxsplit=1)[0]
        finding_sections = re.split(r"### Finding \d+", findings_only)[1:]

        if not finding_sections:
            # Also try "### Finding N:" format (with title after colon)
            finding_sections = re.split(r"### Finding \d+[:\s]", findings_only)[1:]

        for i, section in enumerate(finding_sections, 1):
            # Check CVSS score presence
            if not re.search(r"CVSS[:\s]*\d+\.\d+", section, re.IGNORECASE):
                errors.append(
                    f"Finding {i} in report: Missing CVSS v3.1 score — "
                    "each finding must include a numeric CVSS score"
                )
            # Check for proof of concept
            if "**Proof" not in section and "Proof of Concept" not in section:
                errors.append(
                    f"Finding {i} in report: Missing proof of concept — "
                    "each finding must include actual evidence"
                )
            # Check for CWE
            if "CWE" not in section:
                errors.append(
                    f"Finding {i} in report: Missing CWE identifier — "
                    "each finding should reference the relevant CWE"
                )

    # Enhanced: check for severity summary or count
    has_severity_summary = (
        "## Severity Summary" in content
        or "severity" in content.lower() and "|" in content.split("## Executive Summary")[1].split("##")[0]
        if "## Executive Summary" in content
        else False
    )
    # Not a hard error, just informational — the executive summary should mention counts

    # Check that Executive Summary mentions vulnerability counts
    if "## Executive Summary" in content:
        exec_summary = content.split("## Executive Summary", 1)[1]
        exec_summary = re.split(r"(?m)^## (?!#)", exec_summary, maxsplit=1)[0]
        if not re.search(r"\d+\s*(?:vulnerabilit|finding|flaw)", exec_summary, re.IGNORECASE):
            errors.append(
                "Executive Summary should mention the number of vulnerabilities found"
            )

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
    # Category-specific validators (Phase E)
    "hypotheses_auth": validate_hypotheses_auth,
    "hypotheses_authz": validate_hypotheses_authz,
    "hypotheses_ssrf": validate_hypotheses_ssrf,
    "findings_auth": validate_findings_auth,
    "findings_authz": validate_findings_authz,
    "findings_ssrf": validate_findings_ssrf,
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
