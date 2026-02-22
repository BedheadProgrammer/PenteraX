---
name: network-recon
description: >
  Parse nmap scan results into structured JSON for the SPAIDER pentesting pipeline.
  Use when an agent needs to run network reconnaissance against a target, convert raw
  nmap XML output into structured endpoint data, or feed scan results into downstream
  analysis agents. Triggers on: (1) running nmap scans with structured output,
  (2) parsing nmap XML into JSON, (3) mapping open ports/services/versions for a target,
  (4) generating the recon_report deliverable's network section.
---

# NetworkReconSkill

Produce structured JSON from nmap scans to feed the Pre-Recon Code Analysis phase and
downstream analysis agents. Raw nmap text is ambiguous and causes hallucinated endpoints;
structured JSON eliminates guesswork.

## Workflow

1. Select a scan profile based on the engagement context (see profiles below)
2. Run nmap with XML output: `nmap <profile-flags> -oX /tmp/nmap_scan.xml {{TARGET_URL}}`
3. Parse XML to JSON: `python3 skills/network-recon/scripts/parse_nmap.py /tmp/nmap_scan.xml`
4. Integrate the JSON output into the `recon_report.md` deliverable under `## Network Scan`
5. Use the structured `ports` array to correlate with source-code-identified endpoints

## Scan Profiles

| Profile | Flags | Use When |
|---------|-------|----------|
| Quick | `-sV -T4 --top-ports 100` | Initial triage, time-constrained |
| Standard | `-sV -sC -T3 -p-` | Default for hackathon demo targets |
| Stealth | `-sS -T2 -Pn --top-ports 1000 --randomize-hosts` | When IDS evasion matters |
| Web-focused | `-sV -p 80,443,8080,8443,3000,5000,8000,9000 --script http-enum,http-title,http-headers,http-methods,ssl-cert` | Known web application target |

For OWASP Juice Shop (default target), use the **Web-focused** profile:

```bash
nmap -sV -p 80,443,8080,8443,3000,5000,8000,9000 \
  --script http-enum,http-title,http-headers,http-methods,ssl-cert \
  -oX /tmp/nmap_scan.xml {{TARGET_URL}}
```

## Output Schema

`parse_nmap.py` produces JSON matching this structure:

```json
{
  "scan_info": {
    "target": "192.168.1.1",
    "timestamp": "2025-01-15T10:30:00Z",
    "args": "nmap -sV -sC -T3 -p- -oX /tmp/nmap_scan.xml 192.168.1.1",
    "scanner": "nmap",
    "version": "7.94"
  },
  "hosts": [
    {
      "address": "192.168.1.1",
      "hostname": "target.local",
      "state": "up",
      "ports": [
        {
          "port": 3000,
          "protocol": "tcp",
          "state": "open",
          "service": "http",
          "product": "Node.js Express framework",
          "version": "4.17.1",
          "scripts": [
            { "id": "http-title", "output": "OWASP Juice Shop" }
          ]
        }
      ]
    }
  ]
}
```

## Integration with Pipeline

The JSON output feeds two downstream consumers:

1. **Analysis agents** — iterate `hosts[].ports[]` to match source-code routes against live open ports
2. **VulnerabilityLookupSkill** — use `product` + `version` fields to query CVE databases for known exploits

When writing the `recon_report.md` deliverable, embed the JSON inside a fenced code block under `## Network Scan` and also produce a human-readable markdown table:

```markdown
## Network Scan

| Port | Protocol | State | Service | Product | Version |
|------|----------|-------|---------|---------|---------|
| 3000 | tcp | open | http | Node.js Express framework | 4.17.1 |
```

## Advanced: whatweb Supplementation

After nmap, run whatweb for additional technology fingerprinting:

```bash
whatweb --log-json=/tmp/whatweb.json {{TARGET_URL}}
```

Merge whatweb's technology identifications (frameworks, CMS, JS libraries) into the
`scan_info` section under a `technologies` key.

## References

- **Scan profiles and flag details**: See [references/nmap-options.md](references/nmap-options.md)
