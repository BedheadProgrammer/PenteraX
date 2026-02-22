# Phase 3: Pipeline Integration & First End-to-End

**Hours:** 4–8  
**Objective:** Full pipeline runs end-to-end. At least one agent finds a real vulnerability in Juice Shop.  
**Status:** ✅ Complete

---

## Gate Criteria (all must pass to advance to Phase 4)

- [x] `pipeline.py` orchestrates all agents in sequence: recon → analysis → exploit → report
- [x] `cli.py` accepts `--target-url` and `--repo` arguments and triggers the pipeline
- [x] Running `python -m src --cli pipeline --target-url http://54.146.141.88:3000` starts the pipeline
- [ ] `deliverables/recon_report.md` is generated with endpoint mapping from source code
- [ ] `deliverables/hypotheses_injection.md` and `deliverables/hypotheses_xss.md` are generated
- [ ] At least one of `deliverables/findings_injection.md` or `deliverables/findings_xss.md` contains a real proven vulnerability
- [ ] `deliverables/pentest_report.md` is generated (even if sparse)
- [ ] Pipeline completes without crashing (try/catch at phase level)

---

## Work Streams

### Stream A1 — Pipeline Orchestrator [E1: Infrastructure] ⚠️ CRITICAL PATH

> **Files created/modified:** `src/pipeline.py`
>
> **Depends on:** Phase 2 Stream A (`AgentRunner.run()` works)

- [ ] Implement `runPipeline(config: PipelineConfig)` — sequential orchestrator calling `runAgent()` for each phase:
  1. Recon → `recon.md` with `{{TARGET_URL}}`, `{{REPO_PATH}}`
  2. Analysis → `analysis-injection.md` and `analysis-xss.md` with `{{RECON_DATA}}` (sequential; `ThreadPoolExecutor` parallelism is Phase 4)
  3. Exploit → `exploit-injection.md` and `exploit-xss.md` with `{{HYPOTHESES}}`
  4. Report → `report.md` with `{{FINDINGS}}`
- [ ] Add `try/catch` at each phase — if one fails, continue with available data
- [ ] Verify each phase's deliverable exists before advancing
- [ ] Add console progress: phase name, agent name, start/end timestamps

### Stream A2 — CLI & End-to-End Test [E1: Infrastructure]

> **Files created/modified:** `src/cli.py`
>
> **Depends on:** Stream A1 (`run_pipeline()` available)

- [x] Build `src/cli.py` — parse `--target-url` (required), `--repo` (optional), `--verbose` (optional)
- [x] Validate arguments, call `run_pipeline()`, print summary (time, deliverables, cost)
- [ ] **End-to-end test:** Run `python -m src --cli pipeline --target-url http://54.146.141.88:3000`
  - [ ] Verify all deliverable files are created
  - [ ] Check `recon_report.md` contains source-code-derived endpoints
  - [ ] Check at least one findings file has a real vulnerability

### Stream B1 — Recon Agent Testing [E2: Injection]

> **Files modified:** `src/prompts/recon.md`
>
> **Depends on:** Phase 2 Streams A + B

- [ ] Run recon agent standalone against Juice Shop via `runAgent()`
- [ ] Verify `recon_report.md` contains source-code-derived data (not just nmap output)
- [ ] Iterate `recon.md` until:
  - [ ] Agent reads source files (not just network tools)
  - [ ] Endpoint table is structured and parseable
  - [ ] Sinks are identified with source file references

### Stream B2 — Injection Agent Testing [E2: Injection]

> **Files modified:** `src/prompts/analysis-injection.md`, `src/prompts/exploit-injection.md`
>
> **Depends on:** Stream B1 (`recon_report.md` available)

- [ ] Test injection-analysis: feed `recon_report.md` → verify hypotheses with specific endpoints and payloads
- [ ] Test injection-exploit: feed hypotheses → target `/rest/products/search?q=` for SQL injection
- [ ] Verify agent produces evidence (HTTP response with extracted data)
- [ ] Iterate injection prompts until at least one SQL injection is proven

### Stream C1 — XSS Agent Testing [E3: XSS]

> **Files modified:** `src/prompts/analysis-xss.md`, `src/prompts/exploit-xss.md`
>
> **Depends on:** Phase 2 Streams A + C, Stream B1 (`recon_report.md` available)

- [ ] Test XSS-analysis: feed `recon_report.md` → verify hypotheses identify DOM XSS in search, reflected/stored XSS surfaces
- [ ] Test XSS-exploit: feed hypotheses → verify Playwright injects payloads and captures proof (dialog events or DOM changes)
- [ ] Iterate XSS prompts until at least one XSS is triggered via Playwright

### Stream C2 — Report Agent Testing [E3: Report] ✅ COMPLETE

> **Files modified:** `src/prompts/report.md`
>
> **Depends on:** Streams B2 + C1 (findings files available)

- [x] Test report agent first with mock findings data (from Phase 2), then with real agent output
- [x] Verify `pentest_report.md` is professional and contains all required sections
- [x] Iterate `report.md` until output quality is sufficient

---

## Dependencies Between Streams

```
Stream A1 (pipeline.py) ◄── Phase 2 Stream A (AgentRunner works)
Stream A2 (cli.py + E2E) ◄── Stream A1
Stream B1 (recon testing) ◄── Phase 2 Streams A + B
Stream B2 (injection testing) ◄── Stream B1
Stream C1 (XSS testing) ◄── Phase 2 Streams A + C, Stream B1
Stream C2 (report testing) ◄── Streams B2 + C1

Parallel groups:
  - A1, B1 can start immediately once Phase 2 gate passes
  - B2, C1 can run in parallel once B1 delivers recon_report.md
  - C2 runs after B2 and C1 produce findings
  - A2 runs after A1 + at least one agent stream completes
```

---

## Notes

- **Highest-risk phase.** If `runAgent()` has issues, it blocks everything. B1/C1 should test standalone before the pipeline is wired.
- Focus on getting any output first, then quality. A rough recon report is better than a perfect prompt that hasn't been tested.
- If exploit agents fail to find vulnerabilities, don't block — reasonable hypotheses are sufficient for this gate.
- `try/catch` at the phase level is critical: a crash in exploitation must not prevent the report phase from running with whatever data is available.
