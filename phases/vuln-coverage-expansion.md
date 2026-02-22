# Plan: Expand PenteraX Vuln Coverage to Match/Exceed Shannon

## TL;DR

PenteraX currently covers only **2 vulnerability categories** (SQL injection + XSS) with **~8 confirmed findings**. Shannon finds **20+** across **5 categories**. The Juice Shop Write-up documents **80+ challenges** across 6 difficulty tiers.

This plan adds **3 new parallel vulnerability categories** (Broken Auth, Broken Authz/IDOR, SSRF), expands payload depth in existing categories (NoSQL, XXE, YAML, JWT, path traversal), and wires them into the existing pipeline's parallel execution model — all without structural redesign.

---

## Steps

### Phase A: Add 3 New Vulnerability Categories (Auth, Authz, SSRF)

Each new category needs: an **analysis prompt**, an **exploit prompt**, **pipeline wiring**, and **hypothesis/findings deliverables**.

#### 1. `src/prompts/analysis-auth.md` — Broken Authentication analysis prompt

Hypothesis targets from Shannon's report + Juice Shop Write-up:

| # | Hypothesis | Source |
|---|-----------|--------|
| 1 | Brute force on `/rest/user/login` (no rate limiting) | Shannon AUTH-VULN-05 |
| 2 | MD5 password cracking after DB extraction | Shannon AUTH-VULN-07 |
| 3 | nOAuth predictable password via `btoa(email.reverse())` | Shannon AUTH-VULN-08, Write-up 4-star `login_bender`/`login_bjoern` |
| 4 | Account enumeration via `/rest/user/security-question?email=` (response size differential) | Shannon AUTH-VULN-09 |
| 5 | Token replay after logout (no server-side invalidation) | Shannon AUTH-VULN-10 |
| 6 | JWT `alg:none` bypass | Write-up 5-star `unsigned_jwt` |
| 7 | Forged Signed JWT via leaked `jwt.pub` key | Write-up 6-star `forged_signed_jwt` |
| 8 | Two-Factor Authentication bypass | Write-up 5-star `two_factor_authentification` |
| 9 | Change Bender's password via CSRF on `/rest/user/change-password` | Write-up 5-star |
| 10 | Reset Jim/Bjoern/Morty's password via OSINT security questions | Write-up 3-star/5-star |
| 11 | HTTP credential interception (no HTTPS) | Shannon AUTH-VULN-01 |
| 12 | Missing HSTS headers | Shannon AUTH-VULN-02 |
| 13 | Non-secure cookie flags | Shannon AUTH-VULN-03 |

#### 2. `src/prompts/exploit-auth.md` — Exploitation prompt

Exploitation prompt with curl+Playwright workflow for each auth hypothesis. Include retry envelopes for JWT forgery and password cracking scripts.

#### 3. `src/prompts/analysis-authz.md` — Broken Authorization / IDOR analysis prompt

Targets:

| # | Hypothesis | Source |
|---|-----------|--------|
| 1 | IDOR on `GET /api/Users/:id` — any auth token reads any user profile | Shannon AUTHZ-VULN-01 |
| 2 | IDOR on `GET /rest/basket/:id` — cross-user basket access | Shannon AUTHZ-VULN-02 |
| 3 | IDOR on `GET /api/Feedbacks/:id` — cross-user feedback access | Shannon AUTHZ-VULN-03 |
| 4 | Basket item modification `PUT /api/BasketItems/:id` | Shannon AUTHZ-VULN-05 |
| 5 | Admin role injection during `POST /api/Users` (add `"role":"admin"`) | Shannon AUTHZ-VULN-06, Write-up 3-star `admin_registration` |
| 6 | Regular user creating products `POST /api/Products` | Shannon AUTHZ-VULN-07 |
| 7 | Cross-user basket checkout `POST /rest/basket/:id/checkout` | Shannon AUTHZ-VULN-08 |
| 8 | Deluxe membership payment bypass `POST /rest/deluxe-membership` | Shannon AUTHZ-VULN-09, Write-up 3-star `deluxe_fraud` |
| 9 | Anonymous access to `/rest/memories` | Shannon AUTHZ-VULN-04 |
| 10 | View Basket IDOR | Write-up 2-star `view_basket` |
| 11 | Forged Feedback/Review `POST /api/Feedbacks` with spoofed `UserId` | Write-up 3-star |
| 12 | Product tampering `PUT /api/Products/:id` | Write-up 3-star `product_tampering` |
| 13 | Manipulate Basket (add items to other users' baskets) | Write-up 3-star `manipulate_basket` |

#### 4. `src/prompts/exploit-authz.md` — Exploitation prompt

Exploitation prompt with systematic IDOR enumeration workflow using curl + admin JWT from auth bypass.

#### 5. `src/prompts/analysis-ssrf.md` — SSRF analysis prompt

Targets:

| # | Hypothesis | Source |
|---|-----------|--------|
| 1 | Profile image URL upload `POST /profile/image/url` with HTTP method bypass (PUT) | Shannon SSRF-VULN-01 |
| 2 | Internal service access via `http://localhost:3001/...` URLs | — |
| 3 | Cloud metadata endpoint `http://169.254.169.254/latest/meta-data/` | — |
| 4 | Encryption key exfiltration via `http://localhost:3001/encryptionkeys/jwt.pub` | — |
| 5 | Internal endpoint access via `http://localhost:3001/rest/admin/application-configuration` | — |
| 6 | Write-up 6-star SSRF challenge | Write-up 6-star |

#### 6. `src/prompts/exploit-ssrf.md` — SSRF exploitation prompt

SSRF exploitation prompt with method bypass technique and internal enumeration.

---

### Phase B: Expand Existing Injection Payloads

#### Enhance `analysis-injection.md`

Add mandatory hypotheses for:

| # | Hypothesis | Source |
|---|-----------|--------|
| 1 | NoSQL operator injection on `PATCH /rest/products/reviews` using `{"id":{"$ne":-1}}` | Shannon INJ-VULN-04 |
| 2 | XXE file disclosure via XML upload to `/file-upload` with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Shannon INJ-VULN-06 |
| 3 | YAML injection DoS via YAML bomb upload to `/file-upload` | Shannon INJ-VULN-07 |
| 4 | Christmas Special SQLi — `')) UNION SELECT ... WHERE deletedAt IS NOT NULL--` to find hidden/deleted products | Write-up 4-star |
| 5 | Ephemeral Accountant — SQLi to INSERT then DELETE a temporary admin user | Write-up 4-star |
| 6 | User Credentials extraction via UNION with all users | Write-up 4-star `user_credentials` |
| 7 | Poison Null Bytes — `%00` in file paths on `/ftp/` to bypass extension filters | Write-up 4-star |
| 8 | Path traversal on `/ftp/:file` using `../` or null byte | Write-up (existing in hypotheses but needs concrete payload) |
| 9 | NoSQL exfiltration | Write-up 5-star |
| 10 | NoSQL DoS | Write-up 4-star |
| 11 | SSTI on `/b2b/v2/orders` (Pug/Jade template) | Write-up 6-star `ssti` |
| 12 | Blocked RCE DoS via insecure deserialization | Write-up 5-star |
| 13 | Successful RCE DoS via VM sandbox escape | Write-up 6-star |

#### Enhance `exploit-injection.md`

Add exploitation workflows for each new hypothesis, with payload retry envelopes.

---

### Phase C: Expand XSS Payloads

#### Enhance `analysis-xss.md`

Add mandatory hypotheses for:

| # | Hypothesis | Source |
|---|-----------|--------|
| 1 | JSONP callback XSS on `/rest/user/whoami?callback=alert` | Shannon XSS-VULN-02 |
| 2 | Server-side XSS protection bypass via `<img src="javascript:alert('xss')">` in feedback | Write-up 4-star `server_side_xss_protection` |
| 3 | X-Header XSS via HTTP `X-Forwarded-For` header injection | Write-up 4-star `x_header_xss` |
| 4 | Video XSS via subtitles/media upload | Write-up 6-star `video_xss` |
| 5 | `sanitize-html` nested tag bypass (CVE-2016-1000237): `<<b>script>alert(1)<</b>/script>` | Already in prompt but not mandatory |
| 6 | Bonus Payload — Write-up 1-star challenge-specific payload | Write-up 1-star |
| 7 | CSP bypass via `<base>` tag injection or `data:` URI | — |

#### Enhance `exploit-xss.md`

Add Playwright workflows for JSONP and header-based XSS, extend retry envelope with more payloads.

---

### Phase D: Pipeline Wiring

#### Modify `pipeline.py`

Extend `run_phase_analysis()` and `run_phase_exploit()` to run **5 sub-phases in parallel** instead of 2:

- Change `ThreadPoolExecutor(max_workers=2)` → `ThreadPoolExecutor(max_workers=5)`
- Add `run_analysis_auth()`, `run_analysis_authz()`, `run_analysis_ssrf()` alongside existing injection/XSS
- Add `run_exploit_auth()`, `run_exploit_authz()`, `run_exploit_ssrf()`
- Add corresponding deliverable filenames:
  - `hypotheses_auth.md`
  - `hypotheses_authz.md`
  - `hypotheses_ssrf.md`
  - `findings_auth.md`
  - `findings_authz.md`
  - `findings_ssrf.md`
- Update `validate_phase_output()` to check new deliverables

#### Modify `agent_runner.py`

Adjust budget: increase default global budget from **$10 → $20** and per-agent from **$4 → $3.50** (more agents, slightly less each) to accommodate 5 parallel agents instead of 2.

#### Update `target-context.md`

Add the new endpoints/attack surface discovered from Shannon's report:

- `PATCH /rest/products/reviews` (NoSQL injection)
- `POST /profile/image/url` (SSRF)
- `POST /rest/deluxe-membership` (authz bypass)
- `GET /rest/memories` (unauthenticated access)
- `GET /rest/user/whoami?callback=` (JSONP XSS)
- `POST /rest/basket/:id/checkout` (cross-user checkout)
- `GET /rest/user/security-question?email=` (account enumeration)
- `GET /encryptionkeys/jwt.pub` (JWT key leakage)
- `POST /b2b/v2/orders` (XXE/SSTI)

#### Update `tool-usage.txt`

Add examples for JWT forgery tools, NoSQL injection payloads with curl, and SSRF testing patterns.

#### Update `report.md`

Extend the report template to include sections for **Auth**, **Authz**, and **SSRF** findings alongside existing Injection and XSS sections. Add the "Summary by Vulnerability Type" pattern from Shannon's report format.

---

### Phase E: Enhance Validation & Quality

#### Update `validate_response.py`

Add schema validation for the 3 new hypothesis/findings document types:

- `hypotheses_auth`
- `hypotheses_authz`
- `hypotheses_ssrf`
- `findings_auth`
- `findings_authz`
- `findings_ssrf`

#### Update `safety-rails.md`

Add SSRF scope constraints:

- **Allow** `localhost` / `127.0.0.1` only for SSRF payloads targeting the Juice Shop itself
- **Prohibit** `169.254.169.254` in production environments

---

## Verification

1. Run `python -m pytest test_phase1.py test_phase2.py` to confirm pipeline wiring
2. Run `python test_precollect.py` to verify pre-collection still works
3. Run `python -c "from src.pipeline import run_pipeline"` to check import integrity
4. Manually verify each new prompt file has the required `{{TEMPLATE_VARS}}` placeholders and mandatory hypothesis sections
5. Run a full pipeline against a Juice Shop instance and compare finding count (**target: 15+ confirmed findings** vs current ~8)

---

## Decisions

| Decision | Rationale |
|----------|-----------|
| **5 parallel categories over 2** | Matches Shannon's architecture of running analysis+exploit per OWASP category concurrently. The `ThreadPoolExecutor` already supports this — just increase `max_workers`. |
| **Budget increase ($10 → $20)** | More agents means more API calls. Shannon reportedly costs ~$50/run; we aim to stay under $20 while increasing coverage 2.5×. |
| **No new tool dependencies** | All new attacks (IDOR, auth bypass, SSRF) use existing tools (`curl`, Playwright, `http_request`). No `sqlmap` dependency for NoSQL/XXE — manual curl is sufficient and produces cleaner evidence. |
| **Keep atomic phase gates** | Each new deliverable goes through the same `validate_phase_output()` → retry-3× pipeline as existing ones. No special-casing. |
| **Maintain safety rails** | SSRF testing is scoped to the target Juice Shop only. No cloud metadata exploration in default mode. |
