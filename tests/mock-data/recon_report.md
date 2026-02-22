# Reconnaissance Report — OWASP Juice Shop

**Target:** http://54.146.141.88:3000

## Technology Stack

| Component | Product | Version | Source |
|-----------|---------|---------|--------|
| Backend | Express | 4.21.0 | package.json |
| Frontend | Angular | N/A | source analysis |
| Database | SQLite3 | 5.1.7 | package.json |
| ORM | Sequelize | 6.37.3 | package.json |
| Auth | jsonwebtoken | 0.4.0 | package.json |
| Sanitizer | sanitize-html | 1.4.2 | package.json |

## Endpoints

| Route | Method | Parameters | Source File |
|-------|--------|------------|-------------|
| /rest/products/search | GET | q | routes/search.ts |
| /rest/user/login | POST | email, password | routes/login.ts |
| /api/Products | GET | - | server.ts |
| /api/Feedbacks | POST | comment, rating | server.ts |
| /api/Users | POST | email, password | server.ts |
| /#/search | GET | q | frontend routing |
| /ftp/:file | GET | file | routes/fileServer.ts |

## Identified Sinks

- **SQL Injection:** /rest/products/search — `q` parameter directly concatenated into SQL query (routes/search.ts:23)
- **SQL Injection:** /rest/user/login — `email` parameter concatenated into auth query (routes/login.ts:34)
- **XSS:** /api/Feedbacks — comment rendered via `bypassSecurityTrustHtml` (administration.component.ts:78)
- **XSS:** /#/search — query reflected via `bypassSecurityTrustHtml` (search-result.component.ts:171)

## Network Scan

| Port | Protocol | State | Service | Product | Version |
|------|----------|-------|---------|---------|---------|
| 3000 | tcp | open | http | Node.js Express | - |
| 80 | tcp | closed | http | - | - |
| 443 | tcp | closed | https | - | - |
