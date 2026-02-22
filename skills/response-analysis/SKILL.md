---
name: response-analysis
description: >
  Validate agent deliverables and HTTP responses against expected schemas with retry logic.
  Implements PenteraX §5.9 retry validation to close the hallucination risk loop. Use when:
  (1) validating that an agent's deliverable matches the expected markdown schema,
  (2) verifying HTTP responses contain evidence of successful exploitation (not hallucinated),
  (3) retrying agent execution when output validation fails (up to 3 attempts),
  (4) classifying exploitation responses as confirmed/unconfirmed/error.
---

# ResponseAnalysisSkill

Validate agent outputs and HTTP exploitation responses to prevent hallucinated findings
from propagating through the pipeline. Implements the retry validation pattern from
PenteraX §5.9 without requiring pipeline architecture changes.

## Workflow

1. Agent produces a deliverable (e.g., `findings_injection.md`)
2. Run validation: `python3 skills/response-analysis/scripts/validate_response.py <deliverable_path> <schema_type>`
3. If validation fails → inject error context and retry the agent (up to 3 attempts)
4. If validation passes → proceed to next pipeline phase
5. After 3 failures → write a partial deliverable with `[UNCONFIRMED]` tags and continue

## Deliverable Schema Types

### `recon_report`

Required sections (each as `## Heading`):
- `## Technology Stack`
- `## Endpoints` — must contain a markdown table with columns: Route, Method, Parameters, Source File
- `## Identified Sinks`
- `## Network Scan`

### `hypotheses`

Required structure:
- `## Hypotheses` heading
- At least one `### Hypothesis N` sub-heading
- Each hypothesis must contain: `**Endpoint:**`, `**Parameter:**`, `**Payload:**`, `**Expected Result:**`

### `findings`

Required structure:
- `## Findings` heading
- At least one `### Finding N` sub-heading
- Each finding must contain: `**Vulnerability:**`, `**Proof:**`, `**Severity:**`
- `**Proof:**` must NOT be empty or contain only generic text like "SQL injection found"

### `pentest_report`

Required sections:
- `## Executive Summary`
- `## Findings`
- `## Recommendations`

## Retry Protocol (PenteraX §5.9)

When validation fails, retry the agent with error context injected into the prompt:

```
RETRY CONTEXT (attempt {{ATTEMPT}}/3):
Your previous output failed validation. Errors:
{{VALIDATION_ERRORS}}

Fix these specific issues in your next attempt. Do not reproduce the same errors.
```

Retry schedule:
| Attempt | Action |
|---------|--------|
| 1 | Original execution |
| 2 | Re-run with validation errors injected as context |
| 3 | Re-run with accumulated errors + simplified instructions |
| Fallback | Accept partial output, tag unconfirmed findings with `[UNCONFIRMED]` |

## HTTP Response Classification

When validating exploitation evidence, classify HTTP responses:

| Classification | Criteria | Action |
|---------------|----------|--------|
| **Confirmed** | Response contains extracted data, altered state, or injected content matching the payload | Accept as proven finding |
| **Likely** | Response status/behavior differs from baseline but payload reflection not confirmed | Mark as `[LIKELY]`, include in report with caveat |
| **Unconfirmed** | Response matches normal behavior, no evidence of payload execution | Mark as `[UNCONFIRMED]`, do not include as proven |
| **Error** | HTTP error, timeout, or connection failure | Retry with alternate payload before classifying |

## Anti-Hallucination Checks

Apply these checks to every exploitation finding:

1. **Proof is specific** — `**Proof:**` contains actual HTTP response data, extracted records, or DOM content (not a generic description)
2. **Payload matches context** — The reported payload is syntactically valid for the claimed vulnerability type
3. **Evidence is reproducible** — The finding includes the exact request (URL, method, headers, body) needed to reproduce
4. **Severity is justified** — CVSS score or severity label matches the actual impact demonstrated

## Integration with Pipeline

This skill operates at the boundary between pipeline phases in `pipeline.ts`:

```
Phase N agent produces deliverable
  → validate_response.py checks schema
  → PASS: inject deliverable content into Phase N+1 prompt
  → FAIL: retry Phase N agent with error context (up to 3×)
  → 3× FAIL: continue with partial deliverable + [UNCONFIRMED] tags
```

No changes to the pipeline orchestrator are required — validation runs as a shell command
between agent invocations within the existing sequential flow.

## References

- **Validation schemas and regex patterns**: See [references/validation-schemas.md](references/validation-schemas.md)
