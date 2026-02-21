# Phase 1: Foundation & Environment Setup

**Hours:** 0–2  
**Objective:** Project scaffolded, target environment running, development tools installed, research complete.  
**Status:** Not Started

---

## Gate Criteria (all must pass to advance to Phase 2)

- [ ] `npm install` succeeds without errors
- [ ] `npx tsc --noEmit` succeeds (TypeScript compiles)
- [ ] OWASP Juice Shop accessible at `http://localhost:3000`
- [ ] Juice Shop source code cloned into `repos/juice-shop/`
- [ ] External tools available: `nmap`, `whatweb`, `sqlmap`, `curl`
- [ ] `.env` file created with valid `ANTHROPIC_API_KEY`
- [ ] XSS vulnerability research documented (E3 has attack surface knowledge)

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

> **Files created/modified:** None in repo (Docker + system-level setup)

- [ ] Pull Juice Shop Docker image: `docker pull bkimminich/juice-shop`
- [ ] Start Juice Shop container: `docker run -d -p 3000:3000 bkimminich/juice-shop`
- [ ] Verify Juice Shop accessible at `http://localhost:3000`
- [ ] Clone Juice Shop source code into `repos/juice-shop/`
- [ ] Install `nmap` (verify with `nmap --version`)
- [ ] Install `whatweb` (verify with `whatweb --version`)
- [ ] Install `sqlmap` via pip (verify with `sqlmap --version`)
- [ ] Verify `curl` is available (usually pre-installed)
- [ ] Test Playwright MCP connection: `npx @playwright/mcp@latest --headless` (verify init handshake)

### Stream C — Vulnerability Research [E3: XSS + Report]

> **Files created/modified:** None in repo (research notes only)

- [ ] Research Juice Shop's known XSS vulnerabilities:
  - [ ] DOM XSS in search (`/#/search?q=`)
  - [ ] Reflected XSS in order tracking
  - [ ] Stored XSS via feedback/review forms
- [ ] Identify specific payloads for each XSS type
- [ ] Research Juice Shop's endpoint structure for report template planning
- [ ] Document Playwright interaction patterns needed for XSS proof capture (dialog events, DOM changes)
- [ ] Identify Juice Shop default credentials: `admin@juice-sh.op` / `admin123`

---

## Notes

- **E1 is not a blocker** in this phase — all streams are independent
- E2 should prioritize Docker setup first (other engineers may need the running target to test against)
- E3's research output feeds directly into prompt writing in Phase 2
- If Docker is unavailable, E2 can run Juice Shop natively via `npm start` in the cloned repo
