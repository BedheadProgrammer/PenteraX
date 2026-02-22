# Phase 2: Core Infrastructure Build

**Hours:** 2–4  
**Objective:** `runAgent()` works with Claude SDK, MCP server operational, all prompt templates drafted.  
**Status:** ✅ Complete

---

## Gate Criteria (all must pass to advance to Phase 3)

- [x] `runAgent()` successfully executes a trivial prompt via Claude Agent SDK and returns a response
- [x] Playwright MCP server connects and completes init handshake within `runAgent()`
- [x] `save_deliverable` MCP tool writes files to `deliverables/` directory
- [x] `loadPrompt()` correctly substitutes `{{VAR}}` placeholders in template files
- [x] All 6 prompt template files exist and contain substantive instructions:
  - [x] `src/prompts/recon.md`
  - [x] `src/prompts/analysis-injection.md`
  - [x] `src/prompts/analysis-xss.md`
  - [x] `src/prompts/exploit-injection.md`
  - [x] `src/prompts/exploit-xss.md`
  - [x] `src/prompts/report.md`
- [x] Shared prompt fragments exist:
  - [x] `src/prompts/shared/tool-usage.txt`
  - [x] `src/prompts/shared/login-instructions.txt`
  - [x] `src/prompts/shared/network-interception.txt`

---

## Work Streams (parallel — no file conflicts between streams)

### Stream A — Agent Runner & Infrastructure [E1: Infrastructure] ⚠️ CRITICAL PATH

> **Files created/modified:** `src/agent-runner.ts`, `src/mcp-server.ts`, `src/utils.ts`, `src/types.ts`
>
> **Depends on:** Phase 1 Stream A (project scaffold complete)

- [x] Build `src/types.ts` — define shared types:
  - [x] `AgentConfig` interface (name, promptFile, vars, maxTurns, maxBudgetUsd)
  - [x] `AgentResult` interface (deliverables, cost, turns, duration)
  - [x] `PipelineConfig` interface (targetUrl, repoPath, outputDir)
  - [x] Deliverable schema types (endpoint table structure, hypothesis format, finding format)
- [x] Build `src/utils.ts` — utility functions:
  - [x] `loadPrompt(file, vars)` — read prompt template, substitute `{{VAR}}` placeholders
  - [x] `ensureDir(path)` — create directory if not exists
  - [x] `readDeliverable(name)` — read file from deliverables directory
- [x] Build `src/mcp-server.ts` — in-process MCP server:
  - [x] Implement `createSdkMcpServer()` with `save_deliverable` tool
  - [x] `save_deliverable` accepts `{ name: string, content: string }` and writes to `deliverables/`
  - [x] Test that tool registration works with Agent SDK
- [x] Build `src/agent-runner.ts` — universal agent launcher:
  - [x] Implement `runAgent(config: AgentConfig)` wrapping `query()`
  - [x] Configure Playwright MCP: `npx @playwright/mcp@latest --headless`
  - [x] Configure in-process MCP server (save_deliverable)
  - [x] Set permissions: `bypassPermissions` + `allowDangerouslySkipPermissions: true`
  - [x] Set `maxTurns` per agent type (recon: 50, analysis: 30, exploit: 80, report: 20)
  - [x] Set `maxBudgetUsd: 4.0` per agent
  - [x] Add basic console logging: agent name, start/end timestamps
  - [x] Test with trivial prompt: `"Say hello"` — verify response received
  - [x] Test Playwright MCP init handshake

### Stream B — Recon & Injection Prompts [E2: Injection]

> **Files created/modified:** `src/prompts/recon.md`, `src/prompts/analysis-injection.md`, `src/prompts/exploit-injection.md`, `src/prompts/shared/*`
>
> **Depends on:** Phase 1 Stream B (target environment ready), Phase 1 Stream C (research insights)

- [x] Write `src/prompts/shared/tool-usage.txt`:
  - [x] Document available shell tools (nmap, whatweb, sqlmap, curl)
  - [x] Document Playwright MCP usage patterns
  - [x] Document `save_deliverable` tool usage
  - [x] Document file reading via shell (`cat`, `head`, `find`, `grep`)
- [x] Write `src/prompts/shared/login-instructions.txt`:
  - [x] Juice Shop default credentials: `admin@juice-sh.op` / `admin123`
  - [x] Login flow: navigate to `/#/login`, fill form, submit
  - [x] Capture `Authorization: Bearer <token>` via network interception
  - [x] Note: each agent handles its own authentication (no cross-agent state)
- [x] Write `src/prompts/shared/network-interception.txt`:
  - [x] Playwright network interception patterns
  - [x] How to capture request/response pairs
  - [x] How to extract tokens from responses
- [x] Write `src/prompts/recon.md` — Phase 0 system prompt:
  - [x] Instruct agent to read source code at `{{REPO_PATH}}`
  - [x] Include 5 source code analysis tasks (from PenteraX §5.3):
    1. Route mapping — find all HTTP endpoints, URL patterns, handler functions
    2. Sink identification — dangerous function calls (SQL queries, eval, innerHTML, etc.)
    3. Auth mechanism analysis — middleware, JWT, session management
    4. Input entry point mapping — query params, POST bodies, headers, cookies
    5. Technology stack identification — framework, ORM, template engine
  - [x] Instruct agent to run `nmap` and `whatweb` against `{{TARGET_URL}}`
  - [x] Instruct agent to crawl app via Playwright and capture traffic baseline
  - [x] Define output schema: `recon_report.md` with structured sections:
    - `## Technology Stack`
    - `## Endpoints` (markdown table: Route | Method | Parameters | Source File)
    - `## Identified Sinks`
    - `## Authentication Architecture`
    - `## Traffic Baseline`
    - `## Prioritized Attack Surface`
- [x] Write `src/prompts/analysis-injection.md` — Phase 1 injection analysis:
  - [x] Read `{{RECON_DATA}}` (recon_report.md contents)
  - [x] Identify SQL injection surfaces from endpoints + sinks
  - [x] Output `hypotheses_injection.md` with structured format:
    - `## Hypotheses` with numbered entries
    - Each: `### Hypothesis N`, `**Endpoint:**`, `**Parameter:**`, `**Payload:**`, `**Expected Result:**`
- [x] Draft `src/prompts/exploit-injection.md` — Phase 2 injection exploitation:
  - [x] Read `{{HYPOTHESES}}` (hypotheses_injection.md contents)
  - [x] Use Playwright + sqlmap/curl to test each hypothesis
  - [x] Include retry envelope: try up to 3 alternative payloads per hypothesis
  - [x] Save HTTP response bodies as evidence
  - [x] Output `findings_injection.md` with structured format:
    - `## Findings` with `### Finding N`
    - Each: `**Vulnerability:**`, `**Proof:**`, `**Severity:**`, `**Evidence:**`

### Stream C — XSS & Report Prompts [E3: XSS + Report]

> **Files created/modified:** `src/prompts/analysis-xss.md`, `src/prompts/exploit-xss.md`, `src/prompts/report.md`
>
> **Depends on:** Phase 1 Stream C (research complete)

- [x] Write `src/prompts/analysis-xss.md` — Phase 1 XSS analysis:
  - [x] Read `{{RECON_DATA}}` (recon_report.md contents)
  - [x] Identify XSS surfaces: DOM sinks, reflected inputs, stored content
  - [x] Output `hypotheses_xss.md` with structured format (same schema as injection)
- [x] Write `src/prompts/exploit-xss.md` — Phase 2 XSS exploitation:
  - [x] Read `{{HYPOTHESES}}` (hypotheses_xss.md contents)
  - [x] Use Playwright to inject XSS payloads
  - [x] Capture proof via dialog events and DOM changes
  - [x] Include retry envelope: try up to 3 alternative payloads per hypothesis
  - [x] Save Playwright screenshots as evidence
  - [x] Output `findings_xss.md` with structured format
- [x] Write `src/prompts/report.md` — Phase 3 report consolidation:
  - [x] Read all `{{FINDINGS}}` files
  - [x] Generate professional pentest report structure:
    - Executive Summary
    - Scope & Methodology
    - Findings (with CVSS v3.1 scores)
    - Evidence & Proof
    - Recommendations
    - Scope Limitations (explicitly note: only Injection + XSS tested)
  - [x] Output `pentest_report.md`
- [x] **Test report prompt early with mock data:**
  - [x] Create sample `findings_injection.md` with mock finding
  - [x] Create sample `findings_xss.md` with mock finding
  - [x] Validate report prompt produces professional output (once runAgent() is available)

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
