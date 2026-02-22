# Target Context — OWASP Juice Shop

## Application Architecture

OWASP Juice Shop is a deliberately insecure web application used for security training and CTF challenges.

| Layer | Technology | Notes |
|-------|-----------|-------|
| Frontend | AngularJS 1.x (SPA) | Client-side routing via `/#/` fragments. Known sandbox escape vulnerabilities. |
| Backend | Node.js + Express 4.x | RESTful API serving JSON. Middleware-based auth. |
| Database | SQLite via Sequelize ORM | Raw queries used in several endpoints. No query parameterisation in vulnerable paths. |
| Auth | JWT (jsonwebtoken) | Token issued on login, stored in browser. Known `none` algorithm vulnerability in older versions. |
| Sanitiser | sanitize-html | Used in some user-input rendering paths. Known bypass patterns exist. |

## Default Credentials

| Account | Email | Password | Role |
|---------|-------|----------|------|
| Admin | `admin@juice-sh.op` | `admin123` | Administrator |
| Demo User | `demo` | `demo` | Customer |

## API Surface

### REST API (`/rest/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rest/products/search?q=` | GET | Product search — **known SQL injection sink** |
| `/rest/user/login` | POST | Authentication — accepts `{email, password}` JSON |
| `/rest/user/change-password` | GET | Password change — query params `current`, `new`, `repeat` |
| `/rest/user/reset-password` | POST | Password reset |
| `/rest/user/whoami` | GET | Current user info (requires JWT) |
| `/rest/basket/:id` | GET | Shopping basket contents |
| `/rest/basket/:id/checkout` | POST | Basket checkout — **cross-user checkout target** |
| `/rest/saveLoginIp` | GET | Logs user IP from headers — **stored XSS sink via X-Forwarded-For/True-Client-IP headers** |
| `/rest/deluxe-membership` | GET/POST | Deluxe membership upgrade — **authz bypass target** |
| `/rest/memories` | GET/POST | Photo memories (file upload) — **unauthenticated access** |
| `/rest/user/security-question?email=` | GET | Security question lookup — **account enumeration** |
| `/rest/user/whoami?callback=` | GET | Current user info with JSONP — **JSONP callback XSS** |
| `/rest/products/reviews` | PATCH | Product reviews — **NoSQL injection sink** |

### CRUD API (`/api/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/Products` | GET/POST | Product CRUD |
| `/api/Products/:id` | GET/PUT/DELETE | Single product |
| `/api/Users` | GET/POST | User registration |
| `/api/Users/:id` | GET/PUT/DELETE | Single user |
| `/api/Feedbacks` | GET/POST | Feedback/reviews — **stored XSS sink** |
| `/api/Feedbacks/:id` | GET/PUT/DELETE | Single feedback |
| `/api/Complaints` | GET/POST | Complaints (file upload) |
| `/api/Recycles` | GET/POST | Recycle requests |
| `/api/SecurityQuestions` | GET | Security questions for password reset |
| `/api/BasketItems/:id` | GET/PUT/DELETE | Basket items — **IDOR target** |
| `/api/Challenges` | GET | List of Juice Shop challenges (meta) |
| `/api/Quantitys` | GET/POST | Product quantities |
| `/api/Addresss` | GET/POST | Delivery addresses |
| `/api/Cards` | GET/POST | Payment cards |

### B2B API (`/b2b/v2/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/b2b/v2/orders` | POST | B2B order processing — accepts XML (potential XXE) |

### Profile / File Upload (`/profile/*`, `/file-upload`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/profile/image/url` | POST | Profile image upload via URL — **SSRF sink** |
| `/file-upload` | POST | General file upload — **XXE / YAML injection sink** |

### FTP Directory (`/ftp/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ftp/:file` | GET | Serve files from ftp directory — **path traversal / null byte bypass** |
| `/encryptionkeys/jwt.pub` | GET | JWT public key — **key leakage** |

## Known Interesting Behaviours

1. **Search endpoint SQL injection:** `/rest/products/search?q=` passes the `q` parameter into a Sequelize raw query without parameterisation.
2. **Login SQL injection:** The email field in `/rest/user/login` may be injectable depending on version.
3. **Angular template injection:** AngularJS 1.x renders expressions in `{{ }}` — user input reaching an Angular expression context enables XSS.
4. **Feedback stored XSS:** Feedback comments may be rendered without escaping on the admin panel.
5. **JWT `none` algorithm:** Older Juice Shop versions accept JWT tokens with `alg: none`.
6. **File upload path traversal:** Complaint and memory upload endpoints may be vulnerable to path traversal.
7. **Admin section:** Accessible at `/#/administration` when logged in as admin.
8. **NoSQL injection on reviews:** `PATCH /rest/products/reviews` uses MongoDB-style query operators without sanitisation.
9. **SSRF via profile image:** `POST /profile/image/url` fetches external URLs server-side — potential SSRF vector.
10. **XXE via B2B orders:** `POST /b2b/v2/orders` accepts XML input — potential XXE vector.
11. **IDOR on baskets/users:** Predictable numeric IDs on `/rest/basket/:id` and `/api/Users/:id` enable cross-user access.
12. **Null byte bypass on FTP:** `/ftp/:file` endpoint extension filter can be bypassed with `%2500` (URL-encoded null byte).
13. **JSONP callback XSS:** `/rest/user/whoami?callback=` reflects callback parameter without sanitisation.
14. **SSTI on B2B orders:** `POST /b2b/v2/orders` uses Pug/Jade templating — potential SSTI via `orderLinesData`.
