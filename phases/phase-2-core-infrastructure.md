# Phase 2: Core Infrastructure Build

**Hours:** 2–4  
**Objective:** `runAgent()` works with Claude SDK, MCP server operational, all prompt templates drafted.  
**Status:** Not Started

---

## Gate Criteria (all must pass to advance to Phase 3)

- [ ] `runAgent()` successfully executes a trivial prompt via Claude Agent SDK and returns a response
- [ ] Playwright MCP server connects and completes init handshake within `runAgent()`
- [ ] `save_deliverable` MCP tool writes files to `deliverables/` directory
- [ ] `loadPrompt()` correctly substitutes `{{VAR}}` placeholders in template files
- [ ] All 6 prompt template files exist and contain substantive instructions:
  - [ ] `src/prompts/recon.md`
  - [ ] `src/prompts/analysis-injection.md`
  - [ ] `src/prompts/analysis-xss.md`
  - [ ] `src/prompts/exploit-injection.md`
  - [ ] `src/prompts/exploit-xss.md`
  - [ ] `src/prompts/report.md`
- [ ] Shared prompt fragments exist:
  - [ ] `src/prompts/shared/tool-usage.txt`
  - [ ] `src/prompts/shared/login-instructions.txt`
  - [ ] `src/prompts/shared/network-interception.txt`

---

## Work Streams (parallel — no file conflicts between streams)

### Stream A — Agent Runner & Infrastructure [E1: Infrastructure] ⚠️ CRITICAL PATH

> **Files created/modified:** `src/agent-runner.ts`, `src/mcp-server.ts`, `src/utils.ts`, `src/types.ts`
>
> **Depends on:** Phase 1 Stream A (project scaffold complete)

- [ ] Build `src/types.ts` — define shared types:
  - [ ] `AgentConfig` interface (name, promptFile, vars, maxTurns, maxBudgetUsd)
  - [ ] `AgentResult` interface (deliverables, cost, turns, duration)
  - [ ] `PipelineConfig` interface (targetUrl, repoPath, outputDir)
  - [ ] Deliverable schema types (endpoint table structure, hypothesis format, finding format)
- [ ] Build `src/utils.ts` — utility functions:
  - [ ] `loadPrompt(file, vars)` — read prompt template, substitute `{{VAR}}` placeholders
  - [ ] `ensureDir(path)` — create directory if not exists
  - [ ] `readDeliverable(name)` — read file from deliverables directory
- [ ] Build `src/mcp-server.ts` — in-process MCP server:
  - [ ] Implement `createSdkMcpServer()` with `save_deliverable` tool
  - [ ] `save_deliverable` accepts `{ name: string, content: string }` and writes to `deliverables/`
  - [ ] Test that tool registration works with Agent SDK
- [ ] Build `src/agent-runner.ts` — universal agent launcher:
  - [ ] Implement `runAgent(config: AgentConfig)` wrapping `query()`
  - [ ] Configure Playwright MCP: `npx @playwright/mcp@latest --headless`
  - [ ] Configure in-process MCP server (save_deliverable)
  - [ ] Set permissions: `bypassPermissions` + `allowDangerouslySkipPermissions: true`
  - [ ] Set `maxTurns` per agent type (recon: 50, analysis: 30, exploit: 80, report: 20)
  - [ ] Set `maxBudgetUsd: 4.0` per agent
  - [ ] Add basic console logging: agent name, start/end timestamps
  - [ ] Test with trivial prompt: `"Say hello"` — verify response received
  - [ ] Test Playwright MCP init handshake

### Stream B — Recon & Injection Prompts [E2: Injection]

> **Files created/modified:** `src/prompts/recon.md`, `src/prompts/analysis-injection.md`, `src/prompts/exploit-injection.md`, `src/prompts/shared/*`
>
> **Depends on:** Phase 1 Stream B (target environment ready), Phase 1 Stream C (research insights)

- [ ] Write `src/prompts/shared/tool-usage.txt`:
  - [ ] Document available shell tools (nmap, whatweb, sqlmap, curl)
  - [ ] Document Playwright MCP usage patterns
  - [ ] Document `save_deliverable` tool usage
  - [ ] Document file reading via shell (`cat`, `head`, `find`, `grep`)
- [ ] Write `src/prompts/shared/login-instructions.txt`:
  - [ ] Juice Shop default credentials: `admin@juice-sh.op` / `admin123`
  - [ ] Login flow: navigate to `/#/login`, fill form, submit
  - [ ] Capture `Authorization: Bearer <token>` via network interception
  - [ ] Note: each agent handles its own authentication (no cross-agent state)
- [ ] Write `src/prompts/shared/network-interception.txt`:
  - [ ] Playwright network interception patterns
  - [ ] How to capture request/response pairs
  - [ ] How to extract tokens from responses
- [ ] Write `src/prompts/recon.md` — Phase 0 system prompt:
  - [ ] Instruct agent to read source code at `{{REPO_PATH}}`
  - [ ] Include 5 source code analysis tasks (from PenteraX §5.3):
    1. Route mapping — find all HTTP endpoints, URL patterns, handler functions
    2. Sink identification — dangerous function calls (SQL queries, eval, innerHTML, etc.)
    3. Auth mechanism analysis — middleware, JWT, session management
    4. Input entry point mapping — query params, POST bodies, headers, cookies
    5. Technology stack identification — framework, ORM, template engine
  - [ ] Instruct agent to run `nmap` and `whatweb` against `{{TARGET_URL}}`
  - [ ] Instruct agent to crawl app via Playwright and capture traffic baseline
  - [ ] Define output schema: `recon_report.md` with structured sections:
    - `## Technology Stack`
    - `## Endpoints` (markdown table: Route | Method | Parameters | Source File)
    - `## Identified Sinks`
    - `## Authentication Architecture`
    - `## Traffic Baseline`
    - `## Prioritized Attack Surface`
- [ ] Write `src/prompts/analysis-injection.md` — Phase 1 injection analysis:
  - [ ] Read `{{RECON_DATA}}` (recon_report.md contents)
  - [ ] Identify SQL injection surfaces from endpoints + sinks
  - [ ] Output `hypotheses_injection.md` with structured format:
    - `## Hypotheses` with numbered entries
    - Each: `### Hypothesis N`, `**Endpoint:**`, `**Parameter:**`, `**Payload:**`, `**Expected Result:**`
- [ ] Draft `src/prompts/exploit-injection.md` — Phase 2 injection exploitation:
  - [ ] Read `{{HYPOTHESES}}` (hypotheses_injection.md contents)
  - [ ] Use Playwright + sqlmap/curl to test each hypothesis
  - [ ] Include retry envelope: try up to 3 alternative payloads per hypothesis
  - [ ] Save HTTP response bodies as evidence
  - [ ] Output `findings_injection.md` with structured format:
    - `## Findings` with `### Finding N`
    - Each: `**Vulnerability:**`, `**Proof:**`, `**Severity:**`, `**Evidence:**`

### Stream C — XSS & Report Prompts [E3: XSS + Report]

> **Files created/modified:** `src/prompts/analysis-xss.md`, `src/prompts/exploit-xss.md`, `src/prompts/report.md`
>
> **Depends on:** Phase 1 Stream C (research complete)

- [ ] Write `src/prompts/analysis-xss.md` — Phase 1 XSS analysis:
  - [ ] Read `{{RECON_DATA}}` (recon_report.md contents)
  - [ ] Identify XSS surfaces: DOM sinks, reflected inputs, stored content
  - [ ] Output `hypotheses_xss.md` with structured format (same schema as injection)
- [ ] Write `src/prompts/exploit-xss.md` — Phase 2 XSS exploitation:
  - [ ] Read `{{HYPOTHESES}}` (hypotheses_xss.md contents)
  - [ ] Use Playwright to inject XSS payloads
  - [ ] Capture proof via dialog events and DOM changes
  - [ ] Include retry envelope: try up to 3 alternative payloads per hypothesis
  - [ ] Save Playwright screenshots as evidence
  - [ ] Output `findings_xss.md` with structured format
- [ ] Write `src/prompts/report.md` — Phase 3 report consolidation:
  - [ ] Read all `{{FINDINGS}}` files
  - [ ] Generate professional pentest report structure:
    - Executive Summary
    - Scope & Methodology
    - Findings (with CVSS v3.1 scores)
    - Evidence & Proof
    - Recommendations
    - Scope Limitations (explicitly note: only Injection + XSS tested)
  - [ ] Output `pentest_report.md`
- [ ] **Test report prompt early with mock data:**
  - [ ] Create sample `findings_injection.md` with mock finding
  - [ ] Create sample `findings_xss.md` with mock finding
  - [ ] Validate report prompt produces professional output (once runAgent() is available)

---

## Dependencies Between Streams

```
Stream A (agent-runner.ts) ──► Required by Phase 3 for agent execution
Stream B (prompts) ──────────► Required by Phase 3 for agent configuration
Stream C (prompts) ──────────► Required by Phase 3 for agent configuration
```

> **Key:** Stream A is the critical path. If E1 falls behind, E2/E3 can continue prompt writing but cannot test agents until `runAgent()` works.

---

## Notes

- The adversarial review recommends a 5-phase pipeline (split recon into code-analysis + external-recon). If time allows, implement this split in `pipeline.ts` during Phase 3. Otherwise, keep the 4-phase pipeline with enhanced recon prompt.
- `maxBudgetUsd: 4.0` per agent keeps total cost under $25/run (6 agents × $4 = $24)
- `maxTurns` are differentiated by agent type to prevent runaway agents
- Deliverable schemas defined in `types.ts` ensure consistent handoff between phases
