# Validation Schemas Reference

## Schema Definitions

Each deliverable type has a set of required structural elements. The `validate_response.py`
script checks for these patterns using regex-based parsing.

## recon_report

**File:** `deliverables/recon_report.md`

Required markdown sections:
```
## Technology Stack
## Endpoints
## Identified Sinks
## Network Scan
```

The `## Endpoints` section must contain a markdown table with these columns:

```markdown
| Route | Method | Parameters | Source File |
|-------|--------|------------|-------------|
| /rest/products/search | GET | q | routes/search.ts |
```

Optional sections (validated if present but not required):
- `## Authentication Architecture`
- `## Traffic Baseline`
- `## Prioritized Attack Surface`

## hypotheses

**Files:** `deliverables/hypotheses_injection.md`, `deliverables/hypotheses_xss.md`

Required structure:
```markdown
## Hypotheses

### Hypothesis 1
**Endpoint:** /rest/products/search
**Parameter:** q
**Payload:** ' OR 1=1--
**Expected Result:** Returns all products instead of search results

### Hypothesis 2
...
```

Each hypothesis MUST include all four fields. The numbering must be sequential.

## findings

**Files:** `deliverables/findings_injection.md`, `deliverables/findings_xss.md`

Required structure:
```markdown
## Findings

### Finding 1
**Vulnerability:** SQL Injection in product search
**Proof:** HTTP response contained all 37 product records when injecting...
**Severity:** Critical (CVSS 9.8)

### Finding 2
...
```

### Anti-Hallucination Rules for Proof

The `**Proof:**` field is subjected to additional checks:

1. **Must not be empty**
2. **Must not match generic patterns** like:
   - "SQL injection found"
   - "XSS found"
   - "vulnerability found"
   - "injection successful"
   - "xss successful"
3. **Should contain** at least one of:
   - Actual HTTP response content or status codes
   - Extracted database records or data
   - DOM content showing injected payload
   - Screenshot reference
   - Specific error messages from the application

## pentest_report

**File:** `deliverables/pentest_report.md`

Required sections:
```
## Executive Summary
## Findings
## Recommendations
```

Optional sections (enhance report quality but not required for validation):
- `## Scope & Methodology`
- `## Evidence & Proof`
- `## CVSS Scoring`
- `## Scope Limitations`

## Retry Error Message Templates

When validation fails, inject these error messages into the retry prompt:

### Missing Section Error
```
VALIDATION ERROR: Missing required section "## Endpoints" in recon_report.md.
Your output must contain a "## Endpoints" section with a markdown table listing
discovered routes. Format: | Route | Method | Parameters | Source File |
```

### Empty Proof Error
```
VALIDATION ERROR: Finding N has an empty **Proof:** field. You must provide specific
evidence: actual HTTP response data, extracted records, or DOM content that proves
the vulnerability exists. Generic statements like "SQL injection found" are not accepted.
```

### Missing Field Error
```
VALIDATION ERROR: Hypothesis N is missing the **Payload:** field. Each hypothesis
must include **Endpoint:**, **Parameter:**, **Payload:**, and **Expected Result:**.
```
