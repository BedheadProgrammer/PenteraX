# Phase 1d — Authorization / IDOR Analysis

CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests.

## Objective

Analyse the reconnaissance data and known vulnerabilities to produce **authorization and IDOR attack hypotheses** targeting the OWASP Juice Shop at {{TARGET_URL}}. Focus on **Insecure Direct Object Reference (IDOR), horizontal/vertical privilege escalation, broken object-level authorization, mass assignment, and missing function-level access control**.

Each hypothesis must be specific, actionable, and grounded in evidence from the recon phase. Do NOT guess — cite specific endpoints, parameters, and evidence.

## Input Data

### Recon Report

{{RECON_DATA}}

### Known Vulnerabilities

{{KNOWN_VULNS}}

## Analysis Instructions

1. **Identify all resource endpoints** from the recon report: user profiles, baskets, orders, products, feedbacks, memories. For each:
   - What identifier is used (numeric sequential ID, UUID, slug)?
   - Is the identifier in the URL path, query parameter, or request body?
   - What authorization check is performed (JWT role claim, ownership check, none)?
2. **Map object ownership boundaries** — determine which resources belong to which user:
   - Users own their profiles (`/api/Users/:id`)
   - Users own their baskets (`/rest/basket/:id`)
   - Users own their feedback (`/api/Feedbacks`)
   - Products are admin-managed (`/api/Products/:id`)
   - Basket items belong to a basket (`/api/BasketItems/:id`)
3. **Identify missing authorization checks** by cross-referencing source code sinks:
   - Does the endpoint verify `req.user.id === resource.UserId`?
   - Does the endpoint check admin role before allowing writes?
   - Are there endpoints that only check authentication (valid JWT) but not authorization (correct user)?
4. **Analyse mass assignment vectors:**
   - Can a user inject extra fields during registration (`POST /api/Users`) such as `"role":"admin"`?
   - Can a user modify fields they shouldn't own in PUT/PATCH requests?
5. **Identify vertical privilege escalation paths:**
   - Can a regular user access admin-only endpoints?
   - Can a regular user create/modify resources reserved for admins?
6. **Prioritise by exploitability:**
   - IDOR with sequential numeric IDs (highest — trivially enumerable)
   - Mass assignment / role injection during registration
   - Cross-user basket and order manipulation
   - Missing function-level access control on admin endpoints
   - Feedback/memory spoofing

## MANDATORY Hypotheses

Your output MUST include hypotheses for ALL of the following (at minimum):

1. **IDOR on `GET /api/Users/:id`** — any authenticated user can read any other user's profile by enumerating sequential user IDs with their own JWT token
2. **IDOR on `GET /rest/basket/:id`** — cross-user basket access; authenticate as user A and request user B's basket by changing the numeric basket ID
3. **Admin role injection during `POST /api/Users`** — register a new user with `"role":"admin"` in the JSON body to escalate privileges via mass assignment
4. **Product tampering `PUT /api/Products/:id`** — unauthorized product modification; a regular user sends a PUT request to modify product name, description, or price
5. **Forged Feedback `POST /api/Feedbacks`** with spoofed `UserId` — submit feedback on behalf of another user by setting a different `UserId` in the request body
6. **Basket item modification `PUT /api/BasketItems/:id`** — modify the quantity or ProductId of a basket item belonging to another user
7. **Cross-user basket checkout `POST /rest/basket/:id/checkout`** — checkout another user's basket by substituting the basket ID in the URL
8. **Deluxe membership payment bypass `POST /rest/deluxe-membership`** — obtain deluxe membership without valid payment by manipulating the request or accessing the endpoint with minimal authorization
9. **Anonymous access to `GET /rest/memories`** — access user-uploaded memories without any authentication token
10. **IDOR on `GET /api/Feedbacks/:id`** — read individual feedback entries by enumerating the feedback ID, potentially exposing other users' comments and ratings
11. **Manipulate Basket — add items to other users' baskets** via `POST /api/BasketItems` with a spoofed `BasketId` belonging to another user
12. **Regular user creating products `POST /api/Products`** — a non-admin user attempts to create new products, testing for missing function-level access control
13. **View Basket IDOR — view other users' baskets** via `GET /rest/basket/:id` by iterating through sequential basket IDs and comparing returned `UserId` against the authenticated user

## Hypothesis Format

For EACH hypothesis, use this EXACT format:

```markdown
### Hypothesis N
**Endpoint:** <METHOD> <full URL path>
**Parameter:** <parameter name — path ID, body field, or header>
**Attack Type:** <IDOR / horizontal privilege escalation / vertical privilege escalation / mass assignment / missing function-level access control>
**Payload:** <specific attack payload or manipulated request>
**Expected Result:** <what a successful attack would produce — other user's data, unauthorized modification, privilege escalation>
**Evidence from recon:** <reference to specific endpoint/sink from recon_report.md, including source file and line>
```

## Required Output

Produce a markdown document with the heading `## Hypotheses` followed by at least 5 numbered authz hypotheses. Example structure:

```markdown
## Hypotheses

### Hypothesis 1
**Endpoint:** GET /api/Users/2
**Parameter:** id (URL path)
**Attack Type:** IDOR — horizontal privilege escalation
**Payload:** Authenticate as user with id=1, then request GET /api/Users/2
**Expected Result:** Returns user 2's profile (email, username, role) despite being authenticated as user 1 — proves missing object-level authorization
**Evidence from recon:** routes/users.ts — GET /api/Users/:id handler does not verify req.user.id matches :id parameter

### Hypothesis 2
**Endpoint:** GET /rest/basket/2
**Parameter:** id (URL path)
**Attack Type:** IDOR — cross-user basket access
**Payload:** Authenticate as user with basket id=1, then request GET /rest/basket/2
**Expected Result:** Returns basket 2's contents (items, quantities, prices) belonging to another user
**Evidence from recon:** routes/basket.ts — basket retrieval uses path parameter without ownership validation

### Hypothesis 3
...
```

## Payload Guidelines for IDOR and Authz Testing

### Sequential ID Enumeration (HIGHEST PRIORITY):
- Authenticate as User A (e.g., id=10, basket=10)
- Request resources with IDs belonging to User B: `/api/Users/1`, `/rest/basket/1`, `/api/Feedbacks/1`
- Iterate IDs 1 through 10 systematically — Juice Shop uses auto-increment integer IDs
- Compare response to a request for your own resource to confirm schema match

### JWT Token Swapping:
- Register two users: `attacker@test.com` and `victim@test.com`
- Authenticate as attacker, capture JWT
- Use attacker's JWT to access victim's resources by ID
- If both succeed, the endpoint has no ownership check

### Role Injection / Mass Assignment:
- `{"email":"evil@test.com","password":"test123","role":"admin"}` — during registration
- `{"email":"evil@test.com","password":"test123","isAdmin":true}` — alternative field name
- `{"email":"evil@test.com","password":"test123","deluxeToken":"valid"}` — deluxe escalation
- After registration, decode the JWT to check if the injected role was accepted

### Cross-User Resource Manipulation:
- `POST /api/BasketItems` with `{"ProductId":1,"BasketId":<other_user_basket_id>,"quantity":1}` — add items to someone else's basket
- `PUT /api/BasketItems/:id` with `{"quantity":0}` — modify another user's basket item
- `POST /api/Feedbacks` with `{"comment":"hacked","rating":1,"UserId":<other_user_id>}` — forge feedback

### Missing Function-Level Access Control:
- `POST /api/Products` with a regular user JWT — attempt product creation
- `PUT /api/Products/1` with a regular user JWT — attempt product modification
- `DELETE /api/Users/2` with a regular user JWT — attempt user deletion
- `GET /api/Users` with a regular user JWT — attempt to list all users

Save the output as `hypotheses_authz.md` using the `save_deliverable` tool.
