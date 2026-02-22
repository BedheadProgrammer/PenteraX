# Phase 1c — Broken Authentication Analysis

CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests.

## Objective

Analyse the reconnaissance data and known vulnerabilities to produce **Broken Authentication attack hypotheses** targeting the OWASP Juice Shop at {{TARGET_URL}}. Focus on **credential attacks, session management flaws, JWT manipulation, password reset abuse, and transport-layer security weaknesses**.

Each hypothesis must be specific, actionable, and grounded in evidence from the recon phase. Do NOT guess — cite specific endpoints, parameters, and evidence.

## Input Data

### Recon Report

{{RECON_DATA}}

### Known Vulnerabilities

{{KNOWN_VULNS}}

## Analysis Instructions

1. **Review all authentication-related endpoints** from the recon report — login, registration, password change, password reset, security questions, JWT issuance.
2. **Assess rate limiting:** Determine if `/rest/user/login` has any rate limiting or account lockout mechanism. Lack of rate limiting enables credential brute-force.
3. **Analyse JWT implementation:** Check the `alg` field in issued JWTs. If `none` or `HS256` with a guessable/leaked secret, token forgery is possible.
4. **Check for credential leakage:** Are password hashes extractable (e.g., via SQL injection from the injection phase)? Are they weak (MD5 without salt)?
5. **Evaluate password reset flow:** Does `/rest/user/security-question?email=` reveal whether an account exists? Are security question answers guessable via OSINT?
6. **Check transport security:** Are cookies marked `Secure` and `HttpOnly`? Is HSTS enabled? Is the login form served over HTTPS?
7. **Cross-reference with known CVEs** — especially JWT-related issues in the `jsonwebtoken` library.

## Juice Shop Authentication-Specific Context

### JWT Structure
- Tokens are issued by `/rest/user/login` upon successful authentication
- The JWT payload contains: `id`, `email`, `role`, `iat`, `exp`
- The signing algorithm and secret are critical — check for `alg:none` acceptance and leaked keys at `/encryptionkeys/jwt.pub`

### Password Reset Flow
- `GET /rest/user/security-question?email=<email>` — returns the user's security question (and reveals account existence)
- `POST /rest/user/reset-password` — accepts `{email, answer, new, repeat}`
- Known OSINT-answerable questions for Juice Shop characters (Jim = Star Trek, Bjoern = pets, Morty = Rick & Morty)

### Password Storage
- Passwords are hashed with MD5 (no salt) — trivially crackable if hashes are extracted
- The `nOAuth` variant uses `btoa(email.split('').reverse().join(''))` as the password — predictable for any known email

### CSRF on Password Change
- `GET /rest/user/change-password?current=X&new=Y&repeat=Y` — may not validate the `current` parameter or may accept GET requests

## MANDATORY Hypotheses

Your output MUST include hypotheses for ALL of the following (at minimum):

1. **Brute force on `/rest/user/login`** — no rate limiting allows credential stuffing/dictionary attacks
2. **MD5 password cracking** — after extracting hashes via SQL injection, crack them with known MD5 rainbow tables
3. **nOAuth predictable password** — login as Bender/Bjoern using `btoa(email.reverse())` as password
4. **Account enumeration** — `GET /rest/user/security-question?email=` response size differential reveals valid accounts
5. **Token replay after logout** — JWT remains valid server-side after logout (no token blacklist)
6. **JWT `alg:none` bypass** — forge a JWT with `"alg":"none"` and no signature to impersonate any user
7. **Forged Signed JWT** — use the leaked `jwt.pub` key from `/encryptionkeys/jwt.pub` to forge tokens
8. **Two-Factor Authentication bypass** — bypass 2FA if present by manipulating the TOTP flow
9. **CSRF password change** — change another user's password via `GET /rest/user/change-password` without `current` parameter validation
10. **Password reset via OSINT** — reset Jim/Bjoern/Morty's password by guessing security question answers from public knowledge (Jim: "Samuel" from Star Trek, Bjoern: "Zaya" his cat)
11. **HTTP credential interception** — login form transmits credentials without TLS
12. **Missing HSTS header** — `Strict-Transport-Security` header not present
13. **Non-secure cookie flags** — session cookies lack `Secure` and/or `HttpOnly` flags

## Hypothesis Format

For EACH hypothesis, use this EXACT format:

```markdown
### Hypothesis N
**Endpoint:** <METHOD> <full URL path>
**Parameter:** <parameter name or header/cookie>
**Attack Type:** <brute force / credential cracking / token forgery / session fixation / CSRF / OSINT / transport security>
**Payload/Technique:** <specific attack payload or technique description>
**Expected Result:** <what a successful attack would produce — be specific>
**Evidence from recon:** <reference to specific endpoint/finding from recon_report.md>
**Prerequisites:** <any data needed from other phases, e.g., "requires password hashes from injection phase">
```

## Required Output

Produce a markdown document with the heading `## Hypotheses` followed by at least 10 numbered hypotheses. Example structure:

```markdown
## Hypotheses

### Hypothesis 1
**Endpoint:** POST /rest/user/login
**Parameter:** email, password (JSON body)
**Attack Type:** brute force
**Payload/Technique:** Attempt login with common password list against known email addresses (admin@juice-sh.op, jim@juice-sh.op, bender@juice-sh.op). No rate limiting expected.
**Expected Result:** Valid JWT returned for at least one account. Response status 200 with `"authentication"` key present.
**Evidence from recon:** Login endpoint identified at /rest/user/login; no rate-limiting headers observed in recon.
**Prerequisites:** List of valid email addresses (from account enumeration or SQL injection user extraction)

### Hypothesis 2
**Endpoint:** GET /rest/user/security-question?email=
**Parameter:** email (query string)
**Attack Type:** account enumeration
**Payload/Technique:** Send requests with known emails (admin@juice-sh.op, jim@juice-sh.op) vs non-existent emails. Compare response size and content.
**Expected Result:** Valid emails return a security question JSON object; invalid emails return an error or empty response. Response size differential confirms account existence.
**Evidence from recon:** Endpoint identified in API surface enumeration.
**Prerequisites:** None

### Hypothesis 3
...
```

## Payload Guidelines for Juice Shop Authentication Attacks

### Brute Force
- Target emails: `admin@juice-sh.op`, `jim@juice-sh.op`, `bender@juice-sh.op`, `bjoern@juice-sh.op`, `morty@juice-sh.op`
- Common passwords: `admin123`, `password`, `Password1`, `12345`, specific OSINT-derived passwords
- Use curl with JSON body: `curl -X POST "{{TARGET_URL}}/rest/user/login" -H "Content-Type: application/json" -d '{"email":"<EMAIL>","password":"<PASS>"}'`

### JWT Forgery
- Decode existing JWT: `echo "<token>" | cut -d. -f2 | base64 -d`
- `alg:none` payload: `{"alg":"none","typ":"JWT"}` . `{"id":1,"email":"admin@juice-sh.op","role":"admin"}` . `` (empty signature)
- RSA key confusion: if server uses RS256, try HS256 with the public key as the HMAC secret

### nOAuth Password Derivation
- For `bender@juice-sh.op`: reverse the email → `po.hs-eciuj@redneb` → base64 encode → password
- For `bjoern@juice-sh.op`: same process
- Test with: `curl -X POST "{{TARGET_URL}}/rest/user/login" -H "Content-Type: application/json" -d '{"email":"bender@juice-sh.op","password":"<derived_password>"}'`

### Password Reset via OSINT
- Jim's security question answer: "Samuel" (Jim Kirk's middle name from Star Trek: Tiberius, or his brother: Samuel)
- Bjoern's security question answer: "Zaya" (his pet's name)
- Morty's security question answer: related to Rick & Morty show

Save the output as `hypotheses_auth.md` using the `save_deliverable` tool.
