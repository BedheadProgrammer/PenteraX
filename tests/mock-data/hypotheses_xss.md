# XSS Attack Hypotheses

**Target:** http://54.146.141.88:3000

## Hypotheses

### Hypothesis 1
**Endpoint:** GET /#/search?q=
**Parameter:** q (reflected in search results via bypassSecurityTrustHtml)
**Payload:** `<img src=x onerror=alert('XSS')>`
**Expected Result:** JavaScript alert executes when search results display, confirming reflected XSS

### Hypothesis 2
**Endpoint:** POST /api/Feedbacks
**Parameter:** comment (JSON body field)
**Payload:** `<svg onload=alert('XSS-Stored')>`
**Expected Result:** Script executes when admin views feedback on administration panel, confirming stored XSS
