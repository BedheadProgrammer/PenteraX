# Phase 3: Pipeline Integration & First End-to-End

**Hours:** 4–8  
**Objective:** Full pipeline runs end-to-end. At least one agent finds a real vulnerability in Juice Shop.  
**Status:** Not Started

---

## Gate Criteria (all must pass to advance to Phase 4)

- [ ] `pipeline.ts` orchestrates all agents in sequence: recon → analysis → exploit → report
- [ ] `cli.ts` accepts `--url` and `--repo` arguments and triggers the pipeline
- [ ] Running `npx ts-node src/cli.ts --url=http://54.146.141.88:3000 --repo=./repos/juice-shop` starts the pipeline
- [ ] `deliverables/recon_report.md` is generated with endpoint mapping from source code
- [ ] `deliverables/hypotheses_injection.md` and `deliverables/hypotheses_xss.md` are generated
- [ ] At least one of `deliverables/findings_injection.md` or `deliverables/findings_xss.md` contains a real proven vulnerability
- [ ] `deliverables/pentest_report.md` is generated (even if sparse)
- [ ] Pipeline completes without crashing (try/catch at phase level)

---

## Work Streams

### Stream A — Pipeline & CLI [E1: Infrastructure] ⚠️ CRITICAL PATH

> **Files created/modified:** `src/pipeline.ts`, `src/cli.ts`
>
> **Depends on:** Phase 2 Stream A (`runAgent()` works)

- [ ] Build `src/pipeline.ts` — sequential orchestrator:
  - [ ] Implement `runPipeline(config: PipelineConfig)` function
  - [ ] **Phase 0 — Recon:**
    - [ ] Load `recon.md` prompt with `{{TARGET_URL}}` and `{{REPO_PATH}}`
    - [ ] Call `runAgent()` with recon config
    - [ ] Verify `deliverables/recon_report.md` exists after completion
  - [ ] **Phase 1 — Analysis:**
    - [ ] Read `recon_report.md` contents
    - [ ] Load `analysis-injection.md` with `{{RECON_DATA}}`
    - [ ] Load `analysis-xss.md` with `{{RECON_DATA}}`
    - [ ] Run both analysis agents (sequential for now; `Promise.all` is Phase 4)
    - [ ] Verify hypothesis files exist
  - [ ] **Phase 2 — Exploitation:**
    - [ ] Read hypothesis files
    - [ ] Load `exploit-injection.md` with `{{HYPOTHESES}}`
    - [ ] Load `exploit-xss.md` with `{{HYPOTHESES}}`
    - [ ] Run both exploit agents (sequential)
    - [ ] Verify findings files exist
  - [ ] **Phase 3 — Report:**
    - [ ] Read all findings files
    - [ ] Load `report.md` with `{{FINDINGS}}`
    - [ ] Run report agent
    - [ ] Verify `pentest_report.md` exists
  - [ ] Add `try/catch` at each phase level — if one phase fails, continue with available data
  - [ ] Add console progress output: phase name, agent name, start/end timestamps
- [ ] Build `src/cli.ts` — entry point:
  - [ ] Parse `--url` argument (target URL, required)
  - [ ] Parse `--repo` argument (source code path, required)
  - [ ] Parse `--verbose` flag (optional, enables detailed logging)
  - [ ] Validate arguments
  - [ ] Call `runPipeline()` with parsed config
  - [ ] Print summary on completion (time elapsed, deliverables generated, cost)
- [ ] **End-to-end test:** Run full pipeline against Juice Shop
  - [ ] Verify all deliverable files are created
  - [ ] Check recon_report.md actually contains source-code-derived endpoint data
  - [ ] Check at least one findings file has a real vulnerability

### Stream B — Recon & Injection Agent Testing [E2: Injection]

> **Files modified:** `src/prompts/recon.md`, `src/prompts/analysis-injection.md`, `src/prompts/exploit-injection.md`
>
> **Depends on:** Phase 2 Stream A (`runAgent()` works), Phase 2 Stream B (prompts drafted)

- [ ] Test recon agent with E1's `runAgent()`:
  - [ ] Run recon agent standalone against Juice Shop
  - [ ] Verify `recon_report.md` is generated
  - [ ] Check that report contains source-code-derived data (not just nmap output)
  - [ ] Verify endpoint table has actual routes from Juice Shop source
- [ ] Iterate `recon.md` prompt until output quality is sufficient:
  - [ ] Agent reads source files (not just runs network tools)
  - [ ] Endpoint table is structured and parseable
  - [ ] Sinks are identified with source file references
- [ ] Test injection-analysis agent:
  - [ ] Feed recon_report.md output to analysis agent
  - [ ] Verify hypotheses are generated with specific endpoints and payloads
- [ ] Test injection-exploit agent:
  - [ ] Feed hypotheses to exploit agent
  - [ ] Target: Juice Shop's `/rest/products/search?q=` endpoint for SQL injection
  - [ ] Verify agent produces evidence (HTTP response with extracted data)
- [ ] Iterate injection prompts until at least one SQL injection is proven

### Stream C — XSS & Report Agent Testing [E3: XSS + Report]

> **Files modified:** `src/prompts/analysis-xss.md`, `src/prompts/exploit-xss.md`, `src/prompts/report.md`
>
> **Depends on:** Phase 2 Stream A (`runAgent()` works), Phase 2 Stream C (prompts drafted)

- [ ] Test XSS-analysis agent:
  - [ ] Feed recon_report.md output to XSS analysis agent
  - [ ] Verify hypotheses identify DOM XSS in search, reflected/stored XSS surfaces
- [ ] Test XSS-exploit agent:
  - [ ] Feed hypotheses to XSS exploit agent
  - [ ] Verify Playwright is used to inject payloads
  - [ ] Verify proof captured (dialog events or DOM changes)
- [ ] Test report agent:
  - [ ] First test with mock findings data (created in Phase 2)
  - [ ] Then test with real agent output once available
  - [ ] Verify report is professional and contains all required sections
- [ ] Iterate XSS prompts until at least one XSS is triggered via Playwright

---

## Dependencies Between Streams

```
Stream A (pipeline.ts, cli.ts) ◄── depends on Phase 2 Stream A (runAgent works)
Stream B (test + iterate recon/injection) ◄── depends on Phase 2 Streams A + B
Stream C (test + iterate XSS/report) ◄── depends on Phase 2 Streams A + C

Stream B and Stream C can run in PARALLEL once runAgent() is available.
Stream A must be completed for the gate criteria (full E2E run).
```

---

## Notes

- This is the highest-risk phase. If `runAgent()` has issues, it blocks everything.
- E2 and E3 should test agents individually (standalone calls to `runAgent()`) while E1 builds the pipeline
- Focus on getting any output first, then quality. A rough recon report is better than a perfect prompt that hasn't been tested.
- If the exploit agents fail to find vulnerabilities, don't block — the analysis agents producing reasonable hypotheses is sufficient for this gate
- `try/catch` at the phase level is critical: a crash in Phase 2 exploit should not prevent Phase 3 report from running with whatever data is available
