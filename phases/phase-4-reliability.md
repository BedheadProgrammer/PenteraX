# Phase 4: Prompt Engineering & Reliability

**Hours:** 8–16  
**Objective:** Pipeline reliably finds 2+ vulnerabilities (at least 1 injection, 1 XSS) across 3 consecutive runs. Report output is professional.  
**Status:** In Progress

---

## Gate Criteria (all must pass to advance to Phase 5)

- [ ] Pipeline successfully finds ≥ 1 SQL injection vulnerability in 3/3 consecutive runs
- [ ] Pipeline successfully finds ≥ 1 XSS vulnerability in 3/3 consecutive runs
- [ ] `pentest_report.md` includes CVSS scores, evidence references, and professional formatting
- [ ] Total pipeline runtime < 15 minutes
- [ ] Total API cost < $25 per run
- [ ] No agent crashes halt the pipeline (try/catch works for all phases)
- [ ] Phase 1 analysis agents run in parallel via `ThreadPoolExecutor` (saves 3-5 min)

---

## Work Streams (all parallel — each engineer iterates their own domain)

### Stream A — Error Handling & Pipeline Improvements [E1: Infrastructure]

> **Files modified:** `src/pipeline.py`, `src/cli.py`, `src/agent_loop.py`, `src/agent_runner.py`
>
> **Architecture note:** The pipeline is implemented in **Python** using `ThreadPoolExecutor`
> for parallelism.  Playwright runs in-process via `playwright.sync_api` (Stream A from
> `Playwright_wiring.md`) — there is a singleton `PlaywrightManager` in
> `src/skills/playwright_bridge.py` with an `RLock` ensuring thread-safety.  Because the
> browser is a single shared resource, **exploit agents that both use Playwright must run
> sequentially** (or the second agent waits for the lock).  Analysis agents (Phase 1) do not
> use Playwright and can safely run in parallel.

- [x] Add robust error handling:
  - [x] `try/except` around each agent call in pipeline
  - [x] On agent failure: log error, continue pipeline with available data
  - [x] Report agent handles partial input gracefully (missing injection OR XSS findings)
- [ ] Add timing and cost logging:
  - [ ] Log per-agent: name, duration (seconds), turns used, estimated cost
  - [ ] Log pipeline total: total duration, total cost, deliverables generated
  - [ ] Output timing summary at end of run
- [x] Implement `ThreadPoolExecutor` for Phase 1 (analysis agents):
  - [x] `analysis-injection` and `analysis-xss` run in parallel
  - [x] Both read `recon_report.md` (read-only, no conflicts)
  - [x] Each writes to separate output files (no conflicts)
  - [x] Analysis agents do not use Playwright — no browser conflicts
- [x] Implement `ThreadPoolExecutor` for Phase 2 (exploit agents):
  - [x] `exploit-injection` and `exploit-xss` run in parallel
  - [x] Playwright `PlaywrightManager._lock` (RLock) serialises browser access
  - [x] If one exploit agent is using the browser, the other waits for the lock
- [x] Add `--verbose` flag support:
  - [x] Default: phase-level progress only
  - [x] Verbose: agent turn-by-turn output
- [ ] Cost tracking validation:
  - [ ] Run 3 pipeline executions
  - [ ] Verify each run costs < $25
  - [ ] Verify `maxBudgetUsd: 4.0` per agent is enforced

> **Playwright `wait_until` note:** The default `wait_until` parameter in
> `handle_browser_navigate()` was changed from `"networkidle"` to `"load"` because
> Juice Shop (Angular SPA) maintains persistent WebSocket / socket.io connections that
> prevent `networkidle` from ever firing, causing 30-second timeout hangs.  Tests and
> exploit prompts that target Juice Shop should use `wait_until="domcontentloaded"` for
> fastest results.

### Stream B — Injection Prompt Deep Iteration [E2: Injection]

> **Files modified:** `src/prompts/recon.md`, `src/prompts/analysis-injection.md`, `src/prompts/exploit-injection.md`
> **Status:** COMPLETE — 3/3 cycles passed

- [x] Recon agent reliability:
  - [x] Agent consistently reads source code (not just network tools)
  - [x] Endpoint table is accurate and complete
  - [x] Sinks are correctly identified with file references
  - [x] Run 3 cycles; recon output should be consistent across runs
- [x] Injection-analysis agent reliability:
  - [x] Correctly identifies `/rest/products/search?q=` as SQL injection target
  - [x] Hypotheses include specific payloads (e.g., `' OR 1=1--`, `' UNION SELECT...`)
  - [x] Hypotheses reference source code evidence (why this endpoint is vulnerable)
- [x] Injection-exploit agent reliability:
  - [x] Successfully proves SQL injection with extracted data
  - [x] Retry envelope works: if first payload fails, tries alternatives
  - [x] Evidence includes HTTP response bodies showing extracted data
  - [x] Agent handles authentication when needed (login flow works)
- [x] Run 3+ full pipeline cycles:
  - [x] Cycle 1: 9/9 hyp, 10/10 findings, 5 confirmed, $0.80, 127s — PASSED
  - [x] Cycle 2: 9/9 hyp, 10/10 findings, 5 confirmed, $0.70, 173s — PASSED
  - [x] Cycle 3: 9/9 hyp, 10/10 findings, 5 confirmed, $0.74, 174s — PASSED

### Stream C — XSS & Report Prompt Deep Iteration [E3: XSS + Report]

> **Files modified:** `src/prompts/analysis-xss.md`, `src/prompts/exploit-xss.md`, `src/prompts/report.md`

- [ ] XSS-analysis agent reliability:
  - [ ] Correctly identifies DOM XSS in search (`/#/search?q=`)
  - [ ] Identifies stored XSS surfaces (feedback forms)
  - [ ] Hypotheses include specific payloads and expected proof mechanisms
- [ ] XSS-exploit agent reliability:
  - [x] Uses Playwright (in-process `playwright.sync_api`) to navigate to vulnerable page
  - [ ] Injects XSS payload (e.g., `<img src=x onerror=alert(1)>`)
  - [x] Captures proof: dialog event auto-captured by `PlaywrightManager._setup_dialog_listener()`
  - [ ] Retry envelope works: tries alternative payloads on failure
  - [x] Saves Playwright screenshots to `deliverables/evidence/` via `handle_browser_screenshot()`
- [ ] Report agent quality:
  - [ ] Professional formatting with proper sections
  - [ ] CVSS v3.1 scores assigned to each finding
  - [ ] Evidence properly referenced
  - [ ] Executive summary is concise and impactful
  - [ ] Scope limitations explicitly noted (only Injection + XSS tested)
  - [ ] Report handles partial data gracefully (missing one vuln class)
- [ ] Run 3+ full pipeline cycles:
  - [ ] Cycle 1: Identify report quality issues
  - [ ] Cycle 2: Iterate on prompt, verify improvements
  - [ ] Cycle 3: Confirm reliability and professional quality

---

## Dependencies Between Streams

```
Stream A (error handling + parallelism) ── independent, can start immediately
Stream B (injection iteration) ── independent, can start immediately
Stream C (XSS + report iteration) ── independent, can start immediately

All streams modify DIFFERENT files — full parallelism is safe.
```

---

## Notes

- This is the longest phase (8 hours) and the most iterative — expect many prompt revisions
- Focus on reliability over perfection: a consistently found vulnerability is more valuable than an occasionally impressive one
- The `ThreadPoolExecutor` parallelism for Phase 1/2 is a significant time saving (3-5 min per run) — prioritize this early in the phase
- Playwright is an in-process singleton (`PlaywrightManager`) with `RLock` — no MCP subprocess involved.  If exploit agents collide on browser access, the lock serialises them automatically.  This is by design, not a fallback.
- Track cost per run — if costs are trending over $25, reduce `maxBudgetUsd` or `maxTurns`
- The 3-consecutive-runs gate criterion is strict but necessary for demo confidence
