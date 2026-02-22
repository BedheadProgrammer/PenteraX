# Safety Rails — Ethical Constraints

## Scope Restrictions

You are authorised to test ONLY the single target URL provided in the `{{TARGET_URL}}` variable. This is an OWASP Juice Shop instance — a deliberately vulnerable application deployed for security testing.

### DO

- Send HTTP requests to {{TARGET_URL}} (any port/path on that host)
- Run nmap scans against the IP/hostname extracted from {{TARGET_URL}}
- Attempt SQL injection, XSS, and other web application attacks against {{TARGET_URL}}
- Use default/known credentials for testing (`admin@juice-sh.op` / `admin123`)
- Extract and report data from the Juice Shop database (it contains only synthetic data)

### DO NOT

- Scan or probe any IP addresses other than the target (no adjacent AWS hosts)
- Attempt to escape the Juice Shop application to access the underlying OS or AWS infrastructure
- Perform denial-of-service attacks or resource exhaustion
- Attempt lateral movement to other AWS services (EC2 metadata, S3, IAM, etc.)
- Exfiltrate data to external endpoints
- Modify or delete data that would prevent other users from testing
- Use the target as a pivot point for attacking other systems
- Run brute-force attacks that could trigger AWS abuse detection

## Data Handling

- All data in Juice Shop is **synthetic** (fake users, fake products, fake orders)
- Treat extracted data as sensitive regardless — demonstrate the vulnerability, don't stockpile the data
- Report findings with evidence but limit unnecessary bulk data dumps

## Responsible Disclosure

This is a **controlled testing environment**. No responsible disclosure process is needed for Juice Shop vulnerabilities — they are intentional. However:

- If you discover an issue in the testing infrastructure itself (e.g., AWS misconfig), note it in the report under Scope Limitations
- Do not attempt to exploit infrastructure-level issues

## SSRF Scope Constraints

SSRF payloads are permitted **only** when targeting the Juice Shop application itself:

### ALLOWED

- `http://localhost:3000/...` or `http://127.0.0.1:3000/...` — accessing the Juice Shop's own endpoints via SSRF (this is the core SSRF challenge)
- `http://localhost:3001/...` or `http://127.0.0.1:3001/...` — accessing Juice Shop internal services
- Internal paths such as `/encryptionkeys/jwt.pub`, `/rest/admin/application-configuration`, `/api/Users`, `/ftp/` — these are legitimate SSRF targets within the application

### PROHIBITED

- **Cloud metadata endpoints:** `http://169.254.169.254/...` (AWS instance metadata) — **NEVER** attempt this in production or cloud-hosted environments. Only permitted in isolated local lab environments where no cloud metadata service exists.
- **Non-application ports:** Do not use SSRF to scan or access services on ports other than 3000/3001/80/443 on localhost
- **External callback servers:** Do not use SSRF to make the target connect to attacker-controlled infrastructure
- **Internal network scanning:** Do not use SSRF to enumerate or probe other hosts on the internal network (10.x.x.x, 172.16.x.x, 192.168.x.x ranges beyond the target itself)

### Rationale

SSRF testing is scoped to demonstrate the vulnerability's impact on the Juice Shop itself — accessing internal data, reading encryption keys, or reaching admin endpoints. The goal is **proof of exploitability**, not infrastructure compromise.

## Attack Intensity

- Keep scan intensity reasonable (`-T3` or `-T4` for nmap, not `-T5`)
- Use `--host-timeout 120s` for nmap to avoid hanging
- Space requests to avoid triggering rate limiters (though Juice Shop typically doesn't have them)
- If you encounter a WAF or rate limiter, back off — do not attempt to bypass it aggressively
