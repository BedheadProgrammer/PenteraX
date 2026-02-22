# Output Format — Deliverable Standards

All pipeline deliverables MUST follow these formatting rules to pass automated validation (via `response-analysis` skill).

## General Rules

1. **Markdown only** — all deliverables are `.md` files.
2. **Section headings** use `##` (H2) as top-level within each deliverable. Do not use `#` (H1) except for the final report title.
3. **Tables** must use standard markdown pipe syntax with a header separator row.
4. **Code blocks** must use triple-backtick fences with a language identifier when applicable.
5. **No HTML tags** in deliverables except when demonstrating XSS payloads inside code blocks.

## Deliverable-Specific Schemas

### `recon_report.md`

Required sections (each as `## Heading`):
- `## Technology Stack` — table with Component, Product, Version, Source columns
- `## Endpoints` — table with Route, Method, Parameters, Auth Required columns
- `## Identified Sinks` — grouped by vulnerability class (SQL injection, XSS, etc.)
- `## Network Scan` — structured nmap output (JSON or markdown table)

Optional sections (enhance quality but not required for validation):
- `## Authentication Architecture`
- `## Traffic Baseline`
- `## Prioritized Attack Surface`

### `hypotheses_injection.md` and `hypotheses_xss.md`

Required structure:
- `## Hypotheses` heading
- At least one `### Hypothesis N` sub-heading (sequential numbering)
- Each hypothesis MUST contain all four fields:
  - `**Endpoint:**` — HTTP method + URL path
  - `**Parameter:**` — the injectable parameter name
  - `**Payload:**` — the specific attack payload
  - `**Expected Result:**` — what a successful attack produces

### `findings_injection.md` and `findings_xss.md`

Required structure:
- `## Findings` heading
- At least one `### Finding N` sub-heading (sequential numbering)
- Each finding MUST contain:
  - `**Vulnerability:**` — vulnerability type and affected component
  - `**Proof:**` — actual HTTP request/response evidence (NOT empty, NOT generic)
  - `**Severity:**` — CRITICAL/HIGH/MEDIUM/LOW with CVSS score

Anti-hallucination: `**Proof:**` must NOT match generic patterns like "SQL injection found" or "XSS successful". It must contain specific HTTP response data, extracted records, or DOM content.

### `pentest_report.md`

Required sections:
- `## Executive Summary`
- `## Findings` — with individual finding sub-sections
- `## Recommendations`

Optional sections:
- `## Scope & Methodology`
- `## Evidence & Proof`
- `## Scope Limitations`
