## Technology Stack

| Component | Product | Version | Source |
|-----------|---------|---------|--------|
| Backend   | Express | 4.21.0 | package.json + nmap |
| Frontend  | Angular | N/A | source code analysis |
| Database  | SQLite3 | 5.1.7 | package.json |
| ORM       | Sequelize | 6.37.3 | package.json |
| Auth      | jsonwebtoken | 0.4.0 | package.json |
| Sanitizer | sanitize-html | 1.4.2 | package.json |
| Template  | Pug | 3.0.3 | package.json |
| Upload    | Multer | 1.4.5-lts.1 | package.json |
| WebSocket | Socket.io | 3.1.2 | package.json |
| Crypto    | jssha | 3.3.1 | package.json |
| Validation | express-jwt | 0.1.3 | package.json |
| Parser    | body-parser | 1.20.2 | package.json |

## Endpoints

| Route | Method | Parameters | Auth Required | Source File | Handler |
|-------|--------|------------|---------------|-------------|---------|
| /rest/products/search | GET | q | No | routes/search.ts | Product search with SQL concatenation |
| /rest/user/login | POST | email, password | No | routes/login.ts | Authentication endpoint |
| /api/Products | GET | - | No | server.ts | Product listing API |
| /api/Feedbacks | GET | - | No | server.ts | Feedback system |
| /api/Feedbacks | POST | comment, rating, UserId | Yes | server.ts | Feedback submission |
| /api/Complaints | GET | - | Yes | server.ts | Complaint listing |
| /api/Complaints | POST | message | Yes | server.ts | Complaint submission |
| /rest/basket/:id | GET | - | Yes | routes/basket.ts | Shopping basket access |
| /api/BasketItems | POST | ProductId, BasketId, quantity | Yes | server.ts | Add to basket |
| /api/BasketItems/:id | PUT | quantity, BasketId | Yes | routes/basketItems.ts | Update basket item |
| /api/Challenges | GET | - | No | server.ts | Challenge metadata |
| /api/Users | POST | email, password, role | No | server.ts | User registration |
| /b2b/v2/orders | GET | - | Yes | server.ts | B2B order API |
| /rest/memories | GET | - | No | routes/memories.ts | Memory sharing |
| /rest/memories | POST | image, caption | Yes | routes/memories.ts | Memory upload |
| /profile | GET | - | Yes | routes/userProfile.ts | User profile |
| /file-upload | POST | file | No | server.ts | File upload handler |
| /profile/image/file | POST | file | Yes | server.ts | Profile image upload |
| /profile/image/url | POST | file | Yes | server.ts | Profile image URL |
| /ftp | GET | - | No | server.ts | FTP directory listing |
| /ftp/:file | GET | - | No | routes/fileServer.ts | FTP file access |
| /encryptionkeys | GET | - | No | server.ts | Encryption key listing |
| /encryptionkeys/:file | GET | - | No | routes/keyServer.ts | Encryption key access |
| /support/logs | GET | - | Yes | server.ts | Log file listing |
| /support/logs/:file | GET | - | Yes | routes/logfileServer.ts | Log file access |
| /2fa/verify | POST | tmpToken, totpToken | No | routes/2fa.ts | 2FA verification |
| /dataerasure | GET | - | Yes | routes/dataErasure.ts | Data erasure page |
| /rest/admin/application-configuration | GET | - | No | routes/admin.ts | Admin configuration |

## Identified Sinks

### SQL Injection Sinks

- **Endpoint:** /rest/products/search — `q` parameter
  - **Source:** routes/search.ts:23 — `models.sequelize.query("SELECT * FROM Products WHERE ((name LIKE '%" + criteria + "%' OR description LIKE '%" + criteria + "%') AND deletedAt IS NULL) ORDER BY name")`
  - **Input flow:** req.query.q → criteria → SQL string concatenation
  - **Sanitization:** None

- **Endpoint:** /rest/user/login — `email` and `password` parameters  
  - **Source:** routes/login.ts:34 — `models.sequelize.query("SELECT * FROM Users WHERE email = '" + req.body.email + "' AND password = '" + security.hash(req.body.password) + "' AND deletedAt IS NULL")`
  - **Input flow:** req.body.email/password → SQL string concatenation
  - **Sanitization:** Password hashed but email directly concatenated

### XSS Sinks

- **Endpoint:** /api/Feedbacks — comment field
  - **Source:** frontend/src/app/administration/administration.component.ts:78 — `feedback.comment = this.sanitizer.bypassSecurityTrustHtml(feedback.comment)`
  - **Input flow:** req.body.comment → database → admin panel DOM via bypassSecurityTrustHtml
  - **Sanitization:** Bypassed with bypassSecurityTrustHtml

- **Endpoint:** /rest/products/search — reflected in search results
  - **Source:** frontend/src/app/search-result/search-result.component.ts:171 — `this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)`
  - **Input flow:** URL query parameter → reflected in DOM via bypassSecurityTrustHtml  
  - **Sanitization:** Bypassed with bypassSecurityTrustHtml

- **Endpoint:** Product details — description field
  - **Source:** frontend/src/app/product-details/product-details.component.html:16 — `<div [innerHTML]="data.productData.description"></div>`
  - **Input flow:** Product description → DOM innerHTML binding
  - **Sanitization:** None

### Authentication Sinks

- **JWT Algorithm Bypass:** 
  - **Source:** routes/verify.ts:108-117 — JWT verification with algorithm manipulation
  - **Input flow:** Authorization header → JWT decode without algorithm verification
  - **Sanitization:** Vulnerable jsonwebtoken 0.4.0 allows 'none' algorithm

- **Password Reset:** 
  - **Source:** server.ts:338 — `/rest/user/reset-password` with rate limiting
  - **Input flow:** Email parameter for password reset
  - **Sanitization:** Rate limited but vulnerable to enumeration

### Path Traversal Sinks

- **Endpoint:** /ftp/:file — file parameter
  - **Source:** routes/fileServer.ts:33 — `res.sendFile(path.resolve('ftp/', file))`
  - **Input flow:** req.params.file → path.resolve → file system access
  - **Sanitization:** security.cutOffPoisonNullByte applied but insufficient

- **Endpoint:** /encryptionkeys/:file — file parameter
  - **Source:** routes/keyServer.ts:14 — `res.sendFile(path.resolve('encryptionkeys/', file))`
  - **Input flow:** req.params.file → path.resolve → file system access
  - **Sanitization:** None visible

- **Endpoint:** /support/logs/:file — file parameter
  - **Source:** routes/logfileServer.ts:14 — `res.sendFile(path.resolve('logs/', file))`
  - **Input flow:** req.params.file → path.resolve → file system access
  - **Sanitization:** None visible

### File Upload Sinks

- **Endpoint:** /file-upload — file parameter
  - **Source:** server.ts:304 — Multiple upload handlers with checkFileType, handleZipFileUpload, handleXmlUpload
  - **Input flow:** multipart file upload → various processors
  - **Sanitization:** File type checking but handles ZIP/XML with potential vulnerabilities

## Network Scan

| Port | Protocol | State | Service | Product | Version |
|------|----------|-------|---------|---------|---------|
| 80 | tcp | closed | http | - | - |
| 443 | tcp | closed | https | - | - |
| 3000 | tcp | open | ppp | Node.js Express | - |
| 5000 | tcp | filtered | upnp | - | - |
| 8000 | tcp | filtered | http-alt | - | - |
| 8080 | tcp | filtered | http-proxy | - | - |
| 8443 | tcp | filtered | https-alt | - | - |
| 9000 | tcp | filtered | cslistener | - | - |

## Authentication Architecture

- **JWT Library:** jsonwebtoken 0.4.0 (critically outdated)
- **Token Generation:** RS256 algorithm with RSA keys in /encryptionkeys directory
- **Key Vulnerabilities:** 
  - CVE-2015-9235: Verification bypass allowing 'none' algorithm
  - CVE-2022-23540: Signature validation bypass due to insecure default algorithm
  - CVE-2022-23541: RSA to HMAC key confusion attack
- **Session Handling:** JWT tokens stored in cookies and Authorization headers
- **Private Key Exposure:** RSA private key accessible at /encryptionkeys/jwt.pri
- **Public Key Exposure:** RSA public key accessible at /encryptionkeys/jwt.pub

## Traffic Baseline

- **Normal Search Response:** JSON array with product objects containing id, name, description, price fields
- **Error Response Pattern:** HTML error pages with status codes 401, 500, and stack traces
- **Rate Limiting:** Present on /rest/user/reset-password endpoint only (5 requests per minute)
- **CORS Policy:** Access-Control-Allow-Origin: * (permissive)
- **Content Security:** X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN
- **XSS Protection:** Explicitly disabled (app.use comment shows xssFilter disabled)

## Prioritized Attack Surface

1. **CRITICAL:** /rest/products/search SQL Injection (CWE-89)
   - Direct SQL concatenation with user input in Sequelize raw query
   - No authentication required, publicly accessible endpoint
   - Confirmed exploitable via union-based injection for data extraction

2. **CRITICAL:** /rest/user/login SQL Injection (CWE-89) 
   - Email parameter directly concatenated into authentication query
   - Enables authentication bypass and user enumeration
   - Can extract password hashes and user data

3. **HIGH:** JWT Authentication Bypass (CVE-2015-9235, CVE-2022-23540)
   - jsonwebtoken 0.4.0 vulnerable to 'none' algorithm bypass
   - RSA to HMAC key confusion possible
   - Private keys exposed at /encryptionkeys/jwt.pri

4. **HIGH:** XSS in Search Results (CWE-79)
   - Search parameter reflected via bypassSecurityTrustHtml in Angular component
   - No sanitization applied due to explicit bypass
   - Persistent XSS possible through product descriptions

5. **HIGH:** Path Traversal in File Endpoints (CWE-22)
   - Multiple file serving endpoints (/ftp/:file, /encryptionkeys/:file, /support/logs/:file)
   - Insufficient path sanitization allows directory traversal
   - Can access sensitive files outside intended directories

6. **MEDIUM:** File Upload Vulnerabilities (CWE-434)
   - Multiple upload endpoints with XML/ZIP processing
   - Potential for XXE attacks and zip bombs
   - File type validation may be bypassable

7. **MEDIUM:** Sanitize-html Bypass (CVE-2016-1000237, CVE-2021-26539)
   - Version 1.4.2 vulnerable to XSS filter bypass
   - Multiple CVEs for nested tag attacks and improper validation
   - Affects feedback and comment sanitization