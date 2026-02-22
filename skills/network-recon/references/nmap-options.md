# Nmap Options Reference

## Common Scan Types

| Flag | Name | Description |
|------|------|-------------|
| `-sS` | SYN scan | Stealthy half-open scan (default with root) |
| `-sT` | TCP connect | Full TCP handshake (default without root) |
| `-sV` | Version detection | Probe open ports for service/version info |
| `-sC` | Default scripts | Run default NSE scripts |
| `-sU` | UDP scan | Scan UDP ports (slow, combine with TCP) |

## Timing Templates

| Flag | Name | Use Case |
|------|------|----------|
| `-T0` | Paranoid | IDS evasion (very slow) |
| `-T1` | Sneaky | IDS evasion |
| `-T2` | Polite | Reduced bandwidth usage |
| `-T3` | Normal | Default timing |
| `-T4` | Aggressive | Fast scan on reliable networks |
| `-T5` | Insane | Very fast, may miss results |

## Port Specification

| Flag | Example | Description |
|------|---------|-------------|
| `-p` | `-p 80,443` | Specific ports |
| `-p-` | `-p-` | All 65535 ports |
| `--top-ports` | `--top-ports 100` | Most common N ports |
| `-p T:80,U:53` | | Mixed TCP/UDP |

## Output Formats

| Flag | Format | Pipeline Use |
|------|--------|-------------|
| `-oX` | XML | **Primary** — parsed by `parse_nmap.py` |
| `-oN` | Normal text | Human reference only |
| `-oG` | Grepable | Quick scripted parsing |
| `-oA` | All formats | Generates .nmap, .gnmap, .xml |

## NSE Script Categories for Web Pentesting

| Category | Useful Scripts | What They Find |
|----------|---------------|----------------|
| `http-*` | `http-enum`, `http-title`, `http-headers` | Web app metadata, directories |
| `ssl-*` | `ssl-enum-ciphers`, `ssl-cert` | TLS configuration issues |
| `auth-*` | `http-auth`, `http-form-brute` | Authentication weaknesses |
| `vuln-*` | `http-vuln-*`, `vulners` | Known CVEs for detected versions |

## SPAIDER Scan Profiles

### Quick Triage
```bash
nmap -sV -T4 --top-ports 100 -oX /tmp/nmap_quick.xml TARGET
```
Duration: ~30 seconds. Use for initial recon when time-constrained.

### Standard Full Scan
```bash
nmap -sV -sC -T3 -p- -oX /tmp/nmap_full.xml TARGET
```
Duration: 2-5 minutes. Comprehensive port and service detection.

### Web Application Focus
```bash
nmap -sV -p 80,443,8080,8443,3000,5000,8000,9000 \
  --script http-enum,http-title,http-headers,http-methods,ssl-cert \
  -oX /tmp/nmap_web.xml TARGET
```
Duration: ~1 minute. Optimized for web app targets like Juice Shop.

### Stealth Scan
```bash
nmap -sS -T2 -Pn --top-ports 1000 --randomize-hosts \
  -oX /tmp/nmap_stealth.xml TARGET
```
Duration: 1-3 minutes. Minimizes IDS detection.

## XML Output Structure Reference

The nmap XML output follows this structure (relevant elements for `parse_nmap.py`):

```xml
<nmaprun scanner="nmap" args="..." start="EPOCH" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="target.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open"/>
        <service name="http" product="Node.js Express" version="4.17.1"/>
        <script id="http-title" output="OWASP Juice Shop"/>
      </port>
    </ports>
  </host>
</nmaprun>
```
