# Phase 0 — Reconnaissance

CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests and scans.

## Objective

Perform comprehensive reconnaissance against the OWASP Juice Shop instance at **{{TARGET_URL}}**. Produce a structured `recon_report.md` deliverable that downstream analysis agents will consume.

You have access to skill tools — use them to run nmap scans and look up CVEs. Do NOT skip tool usage; the structured data they return is critical for accurate analysis.

## Target Information

- **URL:** {{TARGET_URL}}
- **Application:** OWASP Juice Shop (Angular SPA + Express backend + SQLite/Sequelize)
- **Default credentials:** `admin@juice-sh.op` / `admin123`
- **Known API patterns:** `/api/*`, `/rest/*`, `/b2b/v2/*`

## Step-by-Step Instructions

### Step 1 — Network Scan

Run nmap against the **IP/hostname extracted from {{TARGET_URL}}** (NOT localhost):

```bash
nmap -sV -p 80,443,8080,8443,3000,5000,8000,9000 \
  --script http-enum,http-title,http-headers,http-methods,ssl-cert \
  -Pn --host-timeout 120s \
  -oX /tmp/nmap_scan.xml <TARGET_HOST>
```

**IMPORTANT for AWS targets:**
- Always use `-Pn` (skip host discovery — AWS security groups may block ICMP)
- Always use `--host-timeout 120s` (AWS latency can be higher than local)
- Extract the hostname/IP from {{TARGET_URL}} — do NOT scan 127.0.0.1 or localhost

After the scan completes, use the `network_recon_parse_nmap` tool to parse the XML into structured JSON.

### Step 2 — HTTP Endpoint Discovery

Enumerate the Juice Shop API surface by sending HTTP requests to {{TARGET_URL}}:

1. Fetch the main page and extract Angular routes from the JavaScript bundle
2. Probe known Juice Shop API endpoints:
   - `GET {{TARGET_URL}}/api/Products` — product listing
   - `GET {{TARGET_URL}}/rest/products/search?q=test` — search endpoint
   - `POST {{TARGET_URL}}/rest/user/login` — authentication
   - `GET {{TARGET_URL}}/api/Feedbacks` — feedback/review system
   - `GET {{TARGET_URL}}/api/Complaints` — complaint submission
   - `GET {{TARGET_URL}}/api/Recycles` — recycle endpoint
   - `GET {{TARGET_URL}}/rest/basket/1` — shopping basket
   - `GET {{TARGET_URL}}/api/Challenges` — challenge listing (meta)
   - `GET {{TARGET_URL}}/api/SecurityQuestions` — security questions
   - `POST {{TARGET_URL}}/api/Users` — user registration
   - `GET {{TARGET_URL}}/b2b/v2/orders` — B2B API
3. Record HTTP method, response status, content-type, and notable response patterns

### Step 3 — Vulnerability Lookup

Use the `vulnerability_lookup_cve` tool to query CVEs for each identified technology and version:

- Express (version from nmap/headers)
- Angular (version from JavaScript source)
- jsonwebtoken (check JWT tokens for library version clues)
- sequelize (inferred from SQL error messages or known Juice Shop stack)
- sanitize-html (if detected)

### Step 4 — Identify Sinks

Based on the endpoint enumeration and known Juice Shop architecture, identify:
- **SQL injection sinks:** Endpoints that accept search/filter parameters (`q=`, `id=`)
- **XSS sinks:** Endpoints that reflect user input (search results, user profiles, feedback)
- **Authentication sinks:** JWT handling, login, password reset
- **Path traversal sinks:** File download/upload endpoints
- **Command injection sinks:** Any endpoints that might invoke OS commands

## Network Recon Skill Context

{{NETWORK_RECON_SKILL}}

## Vulnerability Lookup Skill Context

{{VULN_LOOKUP_SKILL}}

## Required Output Format

Produce a single markdown document with ALL of the following sections. Each section is REQUIRED — do not omit any.

```markdown
## Technology Stack

| Component | Product | Version | Source |
|-----------|---------|---------|--------|
| Backend   | Express | X.Y.Z   | nmap / HTTP headers |
| Frontend  | Angular | X.Y.Z   | JS bundle analysis  |
| ...       | ...     | ...     | ...                  |

## Endpoints

| Route | Method | Parameters | Auth Required |
|-------|--------|------------|---------------|
| /rest/products/search | GET | q | No |
| ...   | ...    | ...        | ...           |

## Identified Sinks

### SQL Injection Sinks
- **Endpoint:** /rest/products/search — `q` parameter concatenated into SQL query
- ...

### XSS Sinks
- **Endpoint:** /api/Products — product name reflected in search results
- ...

### Other Sinks
- ...

## Network Scan

[Paste the structured nmap output here — JSON or markdown table from parse_nmap tool]

## Authentication Architecture

- JWT-based authentication
- Token structure: [describe header/payload if observable]
- Session handling: [describe]

## Traffic Baseline

- Normal search response: [describe typical response structure]
- Error response pattern: [describe]
- Rate limiting: [describe if observed]

## Prioritized Attack Surface

1. **HIGH:** [Most exploitable endpoint + why]
2. **HIGH:** [Second most exploitable + why]
3. **MEDIUM:** [...]
4. ...
```

Save the final output as `recon_report.md` using the `save_deliverable` tool.
