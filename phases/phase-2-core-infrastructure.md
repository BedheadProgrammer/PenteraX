# Phase 2: Core Infrastructure Build

**Hours:** 2–4  
**Objective:** Agent loop works with Claude SDK, Playwright operational in-process, all prompt templates drafted.  
**Status:** ✅ Complete

---

## Gate Criteria (all must pass to advance to Phase 3)

- [x] `runAgent()` (now `AgentRunner.run()`) successfully executes a prompt via Claude API and returns a response
- [x] Playwright browser works in-process (`playwright.sync_api`) — no MCP subprocess needed
- [x] `save_deliverable` tool writes files to `deliverables/` directory
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

> **Files created/modified:** `src/agent_runner.py`, `src/agent_loop.py`, `src/pipeline.py`, `src/config.py`, `src/skills/playwright_bridge.py`
>
> **Depends on:** Phase 1 Stream A (project scaffold complete)
>
> **Note:** The project uses **Python** (not TypeScript). The agent loop, pipeline, and
> Playwright browser bridge are all implemented in Python.

- [x] Build `src/config.py` — define shared configuration:
  - [x] `AppConfig` dataclass (target_url, repo_path, api_key, max_turns, max_budget_usd)
  - [x] `PipelineConfig` dataclass (use_playwright, max_browser_calls, max_retries)
- [x] Build `src/pipeline.py` — utility functions:
  - [x] `load_prompt(file, vars)` — read prompt template, substitute `{{VAR}}` placeholders
  - [x] `save_deliverable(name, content)` — write to deliverables/ directory
- [x] Build `src/skills/playwright_bridge.py` — in-process Playwright:
  - [x] `PlaywrightManager` singleton with `RLock` for thread-safety
  - [x] 6 handler functions: navigate, click, type, screenshot, evaluate, network_requests
  - [x] Dialog auto-capture, network logging, crash recovery
  - [x] `wait_until="load"` default (not `"networkidle"` — unsuitable for SPAs)
- [x] Build `src/agent_runner.py` — universal agent launcher:
  - [x] Implement `AgentRunner.run()` wrapping Claude API calls
  - [x] Configure Playwright in-process (no MCP subprocess needed)
  - [x] Configure tool dispatch via `SkillToolDispatcher`
  - [x] Set `max_turns` per agent type; `max_budget_usd: 4.0` per agent
  - [x] Add basic console logging: agent name, start/end timestamps
  - [x] Test: Playwright browser navigation works within agent loop

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
Stream A (agent_runner.py, agent_loop.py, playwright_bridge.py) ──► Required by Phase 3 for agent execution
Stream B (prompts) ──────────► Required by Phase 3 for agent configuration
Stream C (prompts) ──────────► Required by Phase 3 for agent configuration
```

> **Key:** Stream A is the critical path. If E1 falls behind, E2/E3 can continue prompt writing but cannot test agents until `runAgent()` works.

---

## Notes

- The adversarial review recommends a 5-phase pipeline (split recon into code-analysis + external-recon). If time allows, implement this split in `pipeline.py` during Phase 3. Otherwise, keep the 4-phase pipeline with enhanced recon prompt.
- `maxBudgetUsd: 4.0` per agent keeps total cost under $25/run (6 agents × $4 = $24)
- `maxTurns` are differentiated by agent type to prevent runaway agents
- Deliverable schemas defined in `types.ts` ensure consistent handoff between phases
