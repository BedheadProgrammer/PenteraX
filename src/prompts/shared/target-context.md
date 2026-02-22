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
| `/rest/saveLoginIp` | GET | Logs user IP |
| `/rest/deluxe-membership` | GET/POST | Deluxe membership upgrade |
| `/rest/memories` | GET/POST | Photo memories (file upload) |
| `/rest/products/reviews` | GET/PATCH | Product reviews — **NoSQL injection sink** (`PATCH` accepts MongoDB operators) |
| `/rest/user/security-question` | GET | Security question lookup by `?email=` — **account enumeration** |

### Profile API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/profile` | GET | User profile page |
| `/profile/image/url` | POST | Profile image upload via URL — **SSRF sink** (server-side fetch) |

### Static / FTP
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ftp/:file` | GET | FTP file download — **path traversal + null-byte bypass** |
| `/encryptionkeys/jwt.pub` | GET | Exposed JWT public key — **enables JWT forgery** |

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
| `/api/Challenges` | GET | List of Juice Shop challenges (meta) |
| `/api/Quantitys` | GET/POST | Product quantities |
| `/api/Addresss` | GET/POST | Delivery addresses |
| `/api/Cards` | GET/POST | Payment cards |

### B2B API (`/b2b/v2/*`)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/b2b/v2/orders` | POST | B2B order processing — accepts XML (potential XXE) |

## Known Interesting Behaviours

1. **Search endpoint SQL injection:** `/rest/products/search?q=` passes the `q` parameter into a Sequelize raw query without parameterisation.
2. **Login SQL injection:** The email field in `/rest/user/login` may be injectable depending on version.
3. **Angular template injection:** AngularJS 1.x renders expressions in `{{ }}` — user input reaching an Angular expression context enables XSS.
4. **Feedback stored XSS:** Feedback comments may be rendered without escaping on the admin panel.
5. **JWT `none` algorithm:** Older Juice Shop versions accept JWT tokens with `alg: none`.
6. **File upload path traversal:** Complaint and memory upload endpoints may be vulnerable to path traversal.
7. **Admin section:** Accessible at `/#/administration` when logged in as admin.
8. **NoSQL injection on product reviews:** `PATCH /rest/products/reviews` accepts MongoDB-style operators like `{"id":{"$ne":-1}}`.
9. **SSRF via profile image URL:** `POST /profile/image/url` fetches user-supplied URLs server-side; HTTP method bypass (PUT) may bypass restrictions.
10. **Deluxe membership payment bypass:** `POST /rest/deluxe-membership` may allow upgrade without valid payment via parameter manipulation.
11. **Unauthenticated memory access:** `GET /rest/memories` may be accessible without authentication.
12. **JSONP callback XSS:** `GET /rest/user/whoami?callback=` reflects the callback parameter value, enabling script injection.
13. **Cross-user basket checkout:** `POST /rest/basket/:id/checkout` may allow checking out another user's basket via IDOR.
14. **Account enumeration:** `GET /rest/user/security-question?email=` returns different responses for valid vs invalid emails.
15. **JWT key leakage:** `GET /encryptionkeys/jwt.pub` exposes the public key used for JWT signing, enabling token forgery.
16. **XXE/SSTI on B2B orders:** `POST /b2b/v2/orders` accepts XML input (XXE) and uses Pug/Jade templates (SSTI).
