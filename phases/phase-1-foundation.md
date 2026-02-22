# Phase 1: Foundation & Environment Setup

**Hours:** 0–2  
**Objective:** Project scaffolded, target environment running, development tools installed, research complete.  
**Status:** Not Started

---

## Gate Criteria (all must pass to advance to Phase 2)

- [ ] `npm install` succeeds without errors
- [ ] `npx tsc --noEmit` succeeds (TypeScript compiles)
- [ ] OWASP Juice Shop accessible at `http://54.146.141.88:3000`
- [ ] Juice Shop source code cloned into `repos/juice-shop/`
- [ ] External tools available: `nmap`, `whatweb`, `sqlmap`, `curl`
- [ ] `.env` file created with valid `ANTHROPIC_API_KEY`
- [x] XSS vulnerability research documented (E3 has attack surface knowledge)

---

## Work Streams (all parallel — zero file conflicts)

### Stream A — Project Scaffold [E1: Infrastructure]

> **Files created/modified:** `package.json`, `tsconfig.json`, `.env`, `.gitignore`, `src/` directory structure

- [ ] Run `npm init -y` to create `package.json`
- [ ] Install production dependencies: `@anthropic-ai/claude-agent-sdk`
- [ ] Install dev dependencies: `typescript`, `ts-node`, `@types/node`
- [ ] Create `tsconfig.json` with strict mode, ES2022 target, Node module resolution
- [ ] Create `.env` with `ANTHROPIC_API_KEY=<key>`
- [ ] Create `.gitignore` (include `node_modules/`, `.env`, `deliverables/`, `repos/`)
- [ ] Create directory structure:
  ```
  src/
  src/prompts/
  src/prompts/shared/
  deliverables/
  repos/
  ```
- [ ] Create placeholder `src/types.ts` with shared type definitions
- [ ] Verify `npx tsc --noEmit` passes

### Stream B — Target Environment & Tools [E2: Injection]

> **Files created/modified:** None in repo (AWS instance & system-level setup)

- [ ] Verify AWS Juice Shop instance is running at `http://54.146.141.88:3000`
- [ ] Ensure AWS Security Group allows inbound TCP on ports 22, 80, 443, 3000
- [ ] Ensure AWS Security Group allows nmap scan traffic (don't block SYN probes)
- [ ] Clone Juice Shop source code into `repos/juice-shop/`
- [ ] Install `nmap` (verify with `nmap --version`)
- [ ] Install `whatweb` (verify with `whatweb --version`)
- [ ] Install `sqlmap` via pip (verify with `sqlmap --version`)
- [ ] Verify `curl` is available (usually pre-installed)
- [ ] Test Playwright MCP connection: `npx @playwright/mcp@latest --headless` (verify init handshake)

### Stream C — Vulnerability Research [E3: XSS + Report]

> **Files created/modified:** None in repo (research notes only)

- [x] Research Juice Shop's known XSS vulnerabilities:
  - [x] DOM XSS in search (`/#/search?q=`)
  - [x] Reflected XSS in order tracking
  - [x] Stored XSS via feedback/review forms
- [x] Identify specific payloads for each XSS type
- [x] Research Juice Shop's endpoint structure for report template planning
- [x] Document Playwright interaction patterns needed for XSS proof capture (dialog events, DOM changes)
- [x] Identify Juice Shop default credentials: `admin@juice-sh.op` / `admin123`

---

## Notes

- **E1 is not a blocker** in this phase — all streams are independent
- E2 should prioritize verifying AWS target accessibility first (other engineers may need the running target to test against)
- E3's research output feeds directly into prompt writing in Phase 2
- If the AWS instance is unavailable, E2 can run Juice Shop locally via Docker as fallback: `docker run -d -p 3000:3000 bkimminich/juice-shop`
