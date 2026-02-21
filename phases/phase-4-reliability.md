# Phase 4: Prompt Engineering & Reliability

**Hours:** 8–16  
**Objective:** Pipeline reliably finds 2+ vulnerabilities (at least 1 injection, 1 XSS) across 3 consecutive runs. Report output is professional.  
**Status:** Not Started

---

## Gate Criteria (all must pass to advance to Phase 5)

- [ ] Pipeline successfully finds ≥ 1 SQL injection vulnerability in 3/3 consecutive runs
- [ ] Pipeline successfully finds ≥ 1 XSS vulnerability in 3/3 consecutive runs
- [ ] `pentest_report.md` includes CVSS scores, evidence references, and professional formatting
- [ ] Total pipeline runtime < 15 minutes
- [ ] Total API cost < $25 per run
- [ ] No agent crashes halt the pipeline (try/catch works for all phases)
- [ ] Phase 1 analysis agents run in parallel via `Promise.all` (saves 3-5 min)

---

## Work Streams (all parallel — each engineer iterates their own domain)

### Stream A — Error Handling & Pipeline Improvements [E1: Infrastructure]

> **Files modified:** `src/agent-runner.ts`, `src/pipeline.ts`, `src/cli.ts`

- [ ] Add robust error handling:
  - [ ] `try/catch` around each agent call in pipeline (if not already done)
  - [ ] On agent failure: log error, continue pipeline with available data
  - [ ] Report agent handles partial input gracefully (missing injection OR XSS findings)
- [ ] Add timing and cost logging:
  - [ ] Log per-agent: name, duration (seconds), turns used, estimated cost
  - [ ] Log pipeline total: total duration, total cost, deliverables generated
  - [ ] Output timing summary at end of run
- [ ] Implement `Promise.all` for Phase 1 (analysis agents):
  - [ ] `analysis-injection` and `analysis-xss` run in parallel
  - [ ] Both read `recon_report.md` (read-only, no conflicts)
  - [ ] Each writes to separate output files (no conflicts)
  - [ ] Verify parallel execution doesn't cause Playwright MCP conflicts
- [ ] Implement `Promise.all` for Phase 2 (exploit agents):
  - [ ] `exploit-injection` and `exploit-xss` run in parallel
  - [ ] Verify separate Playwright sessions don't conflict
  - [ ] If Playwright conflicts occur, fall back to sequential
- [ ] Add `--verbose` flag support:
  - [ ] Default: phase-level progress only
  - [ ] Verbose: agent turn-by-turn output
- [ ] Cost tracking validation:
  - [ ] Run 3 pipeline executions
  - [ ] Verify each run costs < $25
  - [ ] Verify `maxBudgetUsd: 4.0` per agent is enforced

### Stream B — Injection Prompt Deep Iteration [E2: Injection]

> **Files modified:** `src/prompts/recon.md`, `src/prompts/analysis-injection.md`, `src/prompts/exploit-injection.md`

- [ ] Recon agent reliability:
  - [ ] Agent consistently reads source code (not just network tools)
  - [ ] Endpoint table is accurate and complete
  - [ ] Sinks are correctly identified with file references
  - [ ] Run 3 cycles; recon output should be consistent across runs
- [ ] Injection-analysis agent reliability:
  - [ ] Correctly identifies `/rest/products/search?q=` as SQL injection target
  - [ ] Hypotheses include specific payloads (e.g., `' OR 1=1--`, `' UNION SELECT...`)
  - [ ] Hypotheses reference source code evidence (why this endpoint is vulnerable)
- [ ] Injection-exploit agent reliability:
  - [ ] Successfully proves SQL injection with extracted data
  - [ ] Retry envelope works: if first payload fails, tries alternatives
  - [ ] Evidence includes HTTP response bodies showing extracted data
  - [ ] Agent handles authentication when needed (login flow works)
- [ ] Run 3+ full pipeline cycles:
  - [ ] Cycle 1: Identify issues, note prompt improvements needed
  - [ ] Cycle 2: Apply improvements, verify fixes
  - [ ] Cycle 3: Confirm reliability

### Stream C — XSS & Report Prompt Deep Iteration [E3: XSS + Report]

> **Files modified:** `src/prompts/analysis-xss.md`, `src/prompts/exploit-xss.md`, `src/prompts/report.md`

- [ ] XSS-analysis agent reliability:
  - [ ] Correctly identifies DOM XSS in search (`/#/search?q=`)
  - [ ] Identifies stored XSS surfaces (feedback forms)
  - [ ] Hypotheses include specific payloads and expected proof mechanisms
- [ ] XSS-exploit agent reliability:
  - [ ] Uses Playwright to navigate to vulnerable page
  - [ ] Injects XSS payload (e.g., `<img src=x onerror=alert(1)>`)
  - [ ] Captures proof: dialog event or DOM change confirmation
  - [ ] Retry envelope works: tries alternative payloads on failure
  - [ ] Saves Playwright screenshots as evidence
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
- The `Promise.all` parallelism for Phase 1/2 is a significant time saving (3-5 min per run) — prioritize this early in the phase
- If Playwright MCP has issues with parallel sessions, fall back to sequential execution for exploit agents (Phase 2)
- Track cost per run — if costs are trending over $25, reduce `maxBudgetUsd` or `maxTurns`
- The 3-consecutive-runs gate criterion is strict but necessary for demo confidence
