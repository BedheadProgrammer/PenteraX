# Phase 0 — Reconnaissance

CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests and scans.

## Objective

Perform comprehensive reconnaissance against the OWASP Juice Shop instance at **{{TARGET_URL}}**. Produce a structured `recon_report.md` deliverable that downstream analysis agents will consume.

You have access to skill tools — use them to look up CVEs. You also have **pre-collected ground-truth data** below (source code analysis, network scan, and HTTP endpoint probes). Use this data as the authoritative basis for your analysis — do NOT hallucinate or fabricate recon data. Reason over the provided data to produce the structured report.

## CRITICAL OUTPUT RULES

1. **Your ENTIRE text response must be the complete recon_report.md content in valid markdown.**
2. **Do NOT write a summary, introduction, or conversational text.** Start directly with `## Technology Stack`.
3. **Do NOT use the `save_deliverable` tool.** The pipeline automatically saves your text response as the deliverable.
4. **ALL sections listed under "Required Output Format" below are MANDATORY.** If you omit any section, validation will fail.
5. **Include real data from the pre-collected analysis** — cite specific source files (e.g., `routes/search.ts:42`), specific version numbers, and specific endpoint paths.

## Target Information

- **URL:** {{TARGET_URL}}
- **Application:** OWASP Juice Shop (Angular SPA + Express backend + SQLite/Sequelize)
- **Default credentials:** `admin@juice-sh.op` / `admin123`
- **Known API patterns:** `/api/*`, `/rest/*`, `/b2b/v2/*`

---

## Pre-collected Ground-Truth Data

The following data was collected by the pipeline before your invocation. It is **real, deterministic, and authoritative**. Use it as your primary source rather than attempting to run commands or make HTTP requests yourself.

### Source Code Analysis

{{SOURCE_ANALYSIS}}

### Network Scan Results

{{NMAP_RESULTS}}

### HTTP Endpoint Probe Results

{{HTTP_PROBE_RESULTS}}

---

## Your Tasks

Given the pre-collected data above, perform the following reasoning tasks:

### Step 1 — Review Source Code Analysis

Examine the pre-collected source analysis above. For each category of findings:
- Identify the most security-relevant matches
- Map routes to their handler functions and parameters
- Note which sinks receive unsanitized user input
- Record the technology stack with version numbers

### Step 2 — Review Network Scan

Examine the nmap results above:
- Confirm which ports/services are running
- Extract product/version information for CVE lookups
- Note any unexpected open ports or services

### Step 3 — Review HTTP Endpoint Probes

Examine the HTTP probe results above:
- Confirm which endpoints are active and their response patterns
- Identify endpoints that return JSON data structures
- Note endpoints that return errors (potential attack vectors)
- Cross-reference with source code routes to identify discrepancies

### Step 4 — Vulnerability Lookup

Use the `vulnerability_lookup_cve` tool to query CVEs for each identified technology and version from the pre-collected data:

- Express (version from package.json / nmap)
- Angular (version from package.json)
- jsonwebtoken (version from package.json)
- sequelize (version from package.json)
- sanitize-html (if detected in dependencies)

### Step 5 — Consolidate Sinks

Merge the sinks found in source code analysis with live endpoint behaviour from HTTP probes. For each sink, confirm:
- The code path is reachable from an HTTP endpoint (cross-reference routes with probes)
- The user-controlled input actually flows into the dangerous function
- No sanitization or parameterization is applied between entry point and sink

Categorize consolidated sinks:
- **SQL injection sinks:** Endpoints with raw Sequelize queries receiving user input (`q=`, login `email`)
- **XSS sinks:** Endpoints reflecting or storing user input rendered without escaping
- **Authentication sinks:** JWT handling, login, password reset — especially lacking rate limits
- **Path traversal sinks:** File download/upload endpoints using `path.join` with user input
- **Command injection sinks:** Any endpoints invoking OS commands with user-controlled args

**CRITICAL for SQL injection sinks:** You MUST include the EXACT raw SQL query string from the source code for each sink. For example, if routes/search.ts contains `models.sequelize.query("SELECT * FROM Products WHERE ...")`, quote the full SQL string. This is essential for downstream analysis agents to craft correct payloads. Also note the exact column count of the target table (e.g., Products has 9 columns: id, name, description, price, deluxePrice, image, createdAt, updatedAt, deletedAt).

## Network Recon Skill Context

{{NETWORK_RECON_SKILL}}

## Vulnerability Lookup Skill Context

{{VULN_LOOKUP_SKILL}}

## MANDATORY: Trivial Info-Disclosure Probes

IMPORTANT: Before producing the report, you MUST include the following trivially-reachable
endpoints in the **Endpoints** table AND in the **Prioritized Attack Surface**. Each is
a single unauthenticated GET that maps to one or more Juice Shop challenges:

| Probe URL | Expected Response | Challenge |
|-----------|-------------------|-----------|
| `GET /metrics` | Prometheus metrics dump (200 OK, text/plain) | Exposed Metrics (1★) |
| `GET /ftp/` | Directory listing of confidential docs (200 OK, HTML) | Confidential Document (1★) |
| `GET /#/score-board` | Hidden scoreboard page (Angular SPA route) | Score Board (1★) |
| `GET /api-docs/` | Swagger/OpenAPI UI with full API spec (200 OK, HTML) | — (info disclosure) |
| `GET /security.txt` | Security policy file (200 OK, text) | Security Policy (1★) |
| `GET /snippets` | Code snippets endpoint (200 OK, JSON) | — (info disclosure) |
| `GET /encryptionkeys/jwt.pub` | RSA public key for JWT signing (200 OK, text) | Key Leakage |
| `GET /robots.txt` | Disallow list revealing hidden paths (200 OK, text) | — (path discovery) |

If the pre-collected HTTP probe data already covers these, cite those results.
If not, mention them as **confirmed from source code analysis** (these routes are
registered in `server.ts` and are reliably reachable).

These low-hanging-fruit probes correspond to **4+ Juice Shop challenges** at 1★
difficulty and provide valuable recon data (API spec, metrics, hidden files) for
downstream exploit agents.

## Required Output Format

**YOUR ENTIRE RESPONSE MUST BE the recon_report.md content.** Do NOT include any conversational text, preamble, or explanation. Start directly with `## Technology Stack`.

The document MUST contain ALL of the following sections in this exact order. Missing sections cause validation failure.

### Section 1 — `## Technology Stack` (REQUIRED)

A markdown table with these exact columns:

| Component | Product | Version | Source |
|-----------|---------|---------|--------|
| Backend   | Express | X.Y.Z   | package.json + nmap |
| Frontend  | Angular | X.Y.Z   | package.json |
| Database  | SQLite  | N/A     | package.json (sequelize) |
| Auth      | jsonwebtoken | X.Y.Z | package.json |
| Sanitizer | sanitize-html | X.Y.Z | package.json |

Fill in REAL version numbers from the pre-collected source data above. Include at least 6 components.

### Section 2 — `## Endpoints` (REQUIRED)

A markdown table listing ALL discovered endpoints from the source code and HTTP probes:

| Route | Method | Parameters | Auth Required | Source File | Handler |
|-------|--------|------------|---------------|-------------|---------|
| /rest/products/search | GET | q | No | routes/search.ts | ... |
| /rest/user/login | POST | email, password | No | routes/login.ts | ... |

Include at least 15 endpoints. Derive these from:
- Route registrations found in pre-collected source analysis (Task 1.1)
- HTTP probe results showing active endpoints
- Cross-reference both sources

### Section 3 — `## Identified Sinks` (REQUIRED)

Group by vulnerability class. Each sink MUST cite the specific source file and line number.

#### SQL Injection Sinks
- **Endpoint:** /rest/products/search — `q` parameter
  - **Source:** routes/search.ts:NN — `models.sequelize.query("SELECT * FROM Products WHERE ((name LIKE '%" + criteria + "%' OR description LIKE '%" + criteria + "%') AND deletedAt IS NULL) ORDER BY name")`
  - **Input flow:** req.query.q → criteria → SQL string concatenation (NO sanitization)
  - **Table columns (9):** id, name, description, price, deluxePrice, image, createdAt, updatedAt, deletedAt
  - **Sanitization:** None

- **Endpoint:** /rest/user/login — `email` parameter
  - **Source:** routes/login.ts:NN — `models.sequelize.query("SELECT * FROM Users WHERE email = '" + req.body.email + "' AND password = '" + security.hash(req.body.password) + "' AND deletedAt IS NULL")`
  - **Input flow:** req.body.email → SQL string concatenation (password is hashed first, so inject via email only)
  - **Sanitization:** None on email field

#### XSS Sinks
- **Endpoint:** /api/Feedbacks — comment field
  - **Source:** routes/feedback.ts → frontend admin component
  - **Input flow:** req.body.comment → database → admin panel DOM
  - **Sanitization:** sanitize-html (bypass known — see CVEs)

#### Authentication Sinks
(JWT vulnerabilities, login bypass)

#### Path Traversal Sinks
(File endpoints with path.join)

#### Command Injection Sinks
(Any exec/spawn calls)

Include at least 5 sinks total across all categories.

### Section 4 — `## Network Scan` (REQUIRED)

Structured nmap results as a markdown table:

| Port | Protocol | State | Service | Product | Version |
|------|----------|-------|---------|---------|----------|
| 3000 | tcp | open | ... | ... | ... |

Pull this data directly from the pre-collected nmap results above.

### Section 5 — `## Authentication Architecture` (REQUIRED)

- JWT library and version
- Token generation pattern (from source code analysis)
- Known vulnerabilities in the JWT implementation
- Session handling details

### Section 6 — `## Traffic Baseline` (REQUIRED)

- Normal search response structure (from HTTP probes)
- Error response patterns
- Rate limiting (observed or absent)

### Section 7 — `## Prioritized Attack Surface` (REQUIRED)

Ranked list with severity and justification:
1. **CRITICAL:** [endpoint + vulnerability type + why exploitable]
2. **HIGH:** [endpoint + vulnerability type + why]
3. **HIGH:** [endpoint + vulnerability type + why]
4. **MEDIUM:** [...]

Include at least 5 prioritized items.

---

**REMEMBER: Your response IS the deliverable. Output ONLY the markdown report. No preamble. No summary. Start with `## Technology Stack`.**
