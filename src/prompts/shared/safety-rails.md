# Safety Rails — Ethical Constraints

## Scope Restrictions

You are authorised to test ONLY the single target URL provided in the `{{TARGET_URL}}` variable. This is an OWASP Juice Shop instance — a deliberately vulnerable application deployed for security testing.

### DO

- Send HTTP requests to {{TARGET_URL}} (any port/path on that host)
- Run nmap scans against the IP/hostname extracted from {{TARGET_URL}}
- Attempt SQL injection, XSS, IDOR, authentication bypass, SSRF, and other web application attacks against {{TARGET_URL}}
- Use default/known credentials for testing (`admin@juice-sh.op` / `admin123`)
- Extract and report data from the Juice Shop database (it contains only synthetic data)

### DO NOT

- Scan or probe any IP addresses other than the target (no adjacent AWS hosts)
- Attempt to escape the Juice Shop application to access the underlying OS or AWS infrastructure
- Perform denial-of-service attacks or resource exhaustion
- Attempt lateral movement to other AWS services (EC2 metadata, S3, IAM, etc.)
- Use SSRF payloads to access cloud metadata endpoints (`169.254.169.254`) — this is prohibited even in testing
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

## Attack Intensity

- Keep scan intensity reasonable (`-T3` or `-T4` for nmap, not `-T5`)
- Use `--host-timeout 120s` for nmap to avoid hanging
- Space requests to avoid triggering rate limiters (though Juice Shop typically doesn't have them)
- If you encounter a WAF or rate limiter, back off — do not attempt to bypass it aggressively

## SSRF Safety Constraints

- **ALLOWED:** SSRF payloads targeting `localhost` / `127.0.0.1` / `[::1]` to access the Juice Shop's own internal services (e.g., `http://localhost:3001/...`)
- **PROHIBITED:** SSRF payloads targeting `169.254.169.254` (cloud metadata endpoint) — this is never allowed, even in a testing environment
- **PROHIBITED:** SSRF payloads targeting any IP address other than the target Juice Shop and its localhost interfaces
- SSRF testing is scoped exclusively to discovering internal endpoints and data exposure on the Juice Shop instance itself
