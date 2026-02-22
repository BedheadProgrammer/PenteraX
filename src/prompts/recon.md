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

### Step 1 — Source Code Analysis (CRITICAL — do this FIRST)

Read the application source code at `{{REPO_PATH}}`. This gives you ground-truth knowledge that network scanning cannot provide. Perform ALL FIVE tasks below — do NOT skip any.

#### Task 1.1 — Route Mapping
Find every HTTP endpoint, URL pattern, and handler function:
```bash
# Express route registrations
grep -rn "app\.\(get\|post\|put\|delete\|patch\|use\)" {{REPO_PATH}}/routes/ {{REPO_PATH}}/server.ts
grep -rn "router\.\(get\|post\|put\|delete\|patch\)" {{REPO_PATH}}/routes/
# Angular client-side routes
grep -rn "path:" {{REPO_PATH}}/frontend/src/app/app-routing.module.ts 2>/dev/null || true
grep -rn "RouterModule\|Routes" {{REPO_PATH}}/frontend/src/ 2>/dev/null | head -30
```
Record: route path, HTTP method, handler file, handler function name.

#### Task 1.2 — Sink Identification
Find dangerous function calls that could lead to vulnerabilities:
```bash
# SQL injection sinks
grep -rn "sequelize\.query\|\.query(" {{REPO_PATH}}/routes/ {{REPO_PATH}}/models/
grep -rn "raw:\s*true\|replacements" {{REPO_PATH}}/routes/
# XSS sinks
grep -rn "innerHTML\|outerHTML\|document\.write\|eval(" {{REPO_PATH}}/frontend/src/
grep -rn "dangerouslySetInnerHTML\|v-html\|\\[innerHTML\\]" {{REPO_PATH}}/frontend/src/
# Command injection sinks
grep -rn "child_process\|exec(\|spawn(\|execFile(" {{REPO_PATH}}/routes/ {{REPO_PATH}}/lib/
# Path traversal sinks
grep -rn "path\.join\|path\.resolve\|readFile\|createReadStream" {{REPO_PATH}}/routes/
```
For each sink: record the file, line number, function name, and which user input reaches it.

#### Task 1.3 — Auth Mechanism Analysis
```bash
# JWT and auth middleware
grep -rn "jwt\|jsonwebtoken\|verify\|sign(" {{REPO_PATH}}/routes/ {{REPO_PATH}}/lib/
grep -rn "middleware\|authorize\|authenticate\|isAuthed" {{REPO_PATH}}/
cat {{REPO_PATH}}/routes/verify.ts 2>/dev/null || true
```
Document: token format, signing algorithm, which routes enforce auth, any auth bypass patterns.

#### Task 1.4 — Input Entry Point Mapping
```bash
# Request parameter access
grep -rn "req\.query\|req\.params\|req\.body\|req\.headers\|req\.cookies" {{REPO_PATH}}/routes/
# Form/body parsing configuration
grep -rn "bodyParser\|express\.json\|express\.urlencoded\|multer\|busboy" {{REPO_PATH}}/server.ts {{REPO_PATH}}/routes/
```
For each entry point: record parameter name, source (query/body/header/cookie), and which handler consumes it.

#### Task 1.5 — Technology Stack Identification
```bash
cat {{REPO_PATH}}/package.json | head -60
# Look for specific framework versions
grep -n "express\|angular\|sequelize\|sqlite\|jsonwebtoken\|sanitize-html" {{REPO_PATH}}/package.json
```
Record: framework, ORM, template engine, auth library — with version numbers.

### Step 2 — Network Scan

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

### Step 3 — Live HTTP Endpoint Discovery

Verify and extend the endpoints found in source code by sending live HTTP requests to {{TARGET_URL}}:

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

### Step 4 — Vulnerability Lookup

Use the `vulnerability_lookup_cve` tool to query CVEs for each identified technology and version:

- Express (version from nmap/headers)
- Angular (version from JavaScript source)
- jsonwebtoken (check JWT tokens for library version clues)
- sequelize (inferred from SQL error messages or known Juice Shop stack)
- sanitize-html (if detected)

### Step 5 — Consolidate Sinks

Merge the sinks found in source code (Step 1.2) with live endpoint behaviour (Step 3). For each sink, confirm:
- The code path is reachable from an HTTP endpoint
- The user-controlled input actually flows into the dangerous function
- No sanitization or parameterization is applied between entry point and sink

Categorize consolidated sinks:
- **SQL injection sinks:** Endpoints with raw Sequelize queries receiving user input (`q=`, login `email`)
- **XSS sinks:** Endpoints reflecting or storing user input rendered without escaping
- **Authentication sinks:** JWT handling, login, password reset — especially lacking rate limits
- **Path traversal sinks:** File download/upload endpoints using `path.join` with user input
- **Command injection sinks:** Any endpoints invoking OS commands with user-controlled args

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
| Backend   | Express | X.Y.Z   | package.json + nmap |
| Frontend  | Angular | X.Y.Z   | package.json + JS bundle |
| Database  | SQLite  | N/A     | package.json (sequelize) |
| Auth      | jsonwebtoken | X.Y.Z | package.json |
| ...       | ...     | ...     | ...                  |

## Endpoints

| Route | Method | Parameters | Auth Required | Source File | Handler |
|-------|--------|------------|---------------|-------------|---------|
| /rest/products/search | GET | q | No | routes/search.ts | searchProducts() |
| ...   | ...    | ...        | ...           | ...         | ...     |

## Identified Sinks

### SQL Injection Sinks
- **Endpoint:** /rest/products/search — `q` parameter concatenated into raw Sequelize query
  - **Source:** routes/search.ts:NN — `models.sequelize.query("SELECT ... '" + criteria + "'")`
  - **Input flow:** req.query.q → criteria variable → SQL string concatenation
- ...

### XSS Sinks
- **Endpoint:** /api/Feedbacks — comment field rendered in admin panel without escaping
  - **Source:** routes/feedback.ts → frontend admin component
  - **Input flow:** req.body.comment → database → admin panel DOM
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
