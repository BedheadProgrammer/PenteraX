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

### Stream A1 — Pipeline Orchestrator [E1: Infrastructure] ⚠️ CRITICAL PATH

> **Files created/modified:** `src/pipeline.ts`
>
> **Depends on:** Phase 2 Stream A (`runAgent()` works)

- [ ] Implement `runPipeline(config: PipelineConfig)` — sequential orchestrator calling `runAgent()` for each phase:
  1. Recon → `recon.md` with `{{TARGET_URL}}`, `{{REPO_PATH}}`
  2. Analysis → `analysis-injection.md` and `analysis-xss.md` with `{{RECON_DATA}}` (sequential; `Promise.all` is Phase 4)
  3. Exploit → `exploit-injection.md` and `exploit-xss.md` with `{{HYPOTHESES}}`
  4. Report → `report.md` with `{{FINDINGS}}`
- [ ] Add `try/catch` at each phase — if one fails, continue with available data
- [ ] Verify each phase's deliverable exists before advancing
- [ ] Add console progress: phase name, agent name, start/end timestamps

### Stream A2 — CLI & End-to-End Test [E1: Infrastructure]

> **Files created/modified:** `src/cli.ts`
>
> **Depends on:** Stream A1 (`runPipeline()` available)

- [ ] Build `src/cli.ts` — parse `--url` (required), `--repo` (required), `--verbose` (optional)
- [ ] Validate arguments, call `runPipeline()`, print summary (time, deliverables, cost)
- [ ] **End-to-end test:** Run `npx ts-node src/cli.ts --url=http://54.146.141.88:3000 --repo=./repos/juice-shop`
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

### Stream C2 — Report Agent Testing [E3: Report]

> **Files modified:** `src/prompts/report.md`
>
> **Depends on:** Streams B2 + C1 (findings files available)

- [ ] Test report agent first with mock findings data (from Phase 2), then with real agent output
- [ ] Verify `pentest_report.md` is professional and contains all required sections
- [ ] Iterate `report.md` until output quality is sufficient

---

## Dependencies Between Streams

```
Stream A1 (pipeline.ts) ◄── Phase 2 Stream A (runAgent works)
Stream A2 (cli.ts + E2E) ◄── Stream A1
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

## Execution Workflow — Parallel & Gated Streams

### Phase 2 Gate Prerequisites

Every Phase 3 stream requires at least one Phase 2 deliverable. The table
below maps each stream to the Phase 2 gates that must pass before it can
start.

| Stream | Phase 2 Gate(s) Required | Key Deliverable Needed |
|--------|--------------------------|------------------------|
| **A1** | Stream A | `runAgent()` operational |
| **A2** | _(gated by A1, not Phase 2 directly)_ | `runPipeline()` from A1 |
| **B1** | Streams A + B | `runAgent()` + recon/injection prompts |
| **B2** | _(gated by B1, not Phase 2 directly)_ | `recon_report.md` from B1 |
| **C1** | Streams A + C | `runAgent()` + XSS prompts (also needs B1's `recon_report.md`) |
| **C2** | _(gated by B2 + C1, not Phase 2 directly)_ | findings files from B2 + C1 |

### Parallel vs. Gated Classification

**Can execute in parallel (no dependency on each other):**

| Parallel Group | Streams | Condition |
|----------------|---------|-----------|
| Group 1 | A1 ‖ B1 | Phase 2 gate passes |
| Group 2 | B2 ‖ C1 | B1 delivers `recon_report.md` |
| Group 2+ | A2 (joins Group 2) | A1 also complete |

**Strictly gated (must wait for predecessor):**

| Stream | Gated By | Reason |
|--------|----------|--------|
| A2 | A1 | Needs `runPipeline()` |
| B2 | B1 | Needs `recon_report.md` |
| C1 | B1 | Needs `recon_report.md` (cross-stream) |
| C2 | B2 **and** C1 | Needs both `findings_injection.md` and `findings_xss.md` |

### Recommended Execution Order

Execute the streams in the following four steps. Within each step, all
listed streams run concurrently. A step cannot begin until every stream in
the preceding step has completed.

> **Engineer key:** E1 = Infrastructure, E2 = Injection, E3 = XSS/Report
> (see Work Streams above for full assignments)

```
═══════════════════════════════════════════════════════════════
  PHASE 2 GATE  ──  runAgent() works, all prompts drafted
═══════════════════════════════════════════════════════════════
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 1 — Parallel                                          │
│                                                             │
│   [E1] Stream A1: pipeline.ts       ──► runPipeline()       │
│                    ║                                        │
│   [E2] Stream B1: recon agent test  ──► recon_report.md     │
│                                                             │
│   (A1 and B1 have no mutual dependency; run simultaneously) │
└─────────────────────────────────────────────────────────────┘
          │
          ▼  (B1 must finish; A1 may still be running)
┌─────────────────────────────────────────────────────────────┐
│  Step 2 — Parallel (after B1 delivers recon_report.md)      │
│                                                             │
│   [E2] Stream B2: injection testing ──► findings_injection  │
│                    ║                                        │
│   [E3] Stream C1: XSS agent testing ──► findings_xss       │
│                                                             │
│   (B2 and C1 share the same input but do not conflict)      │
│                                                             │
│   If A1 is also complete, A2 may start here as well:        │
│   [E1] Stream A2: CLI + E2E test    ──► validated pipeline  │
└─────────────────────────────────────────────────────────────┘
          │
          ▼  (A1 must finish if it hasn't already)
┌─────────────────────────────────────────────────────────────┐
│  Step 3 — Sequential (if A2 was not started in Step 2)      │
│                                                             │
│   [E1] Stream A2: CLI + E2E test    ──► validated pipeline  │
│                                                             │
│   (Only needed when A1 finishes after B1)                   │
└─────────────────────────────────────────────────────────────┘
          │
          ▼  (B2 and C1 must both finish)
┌─────────────────────────────────────────────────────────────┐
│  Step 4 — Sequential                                        │
│                                                             │
│   [E3] Stream C2: report agent test ──► pentest_report.md   │
│                                                             │
│   (Requires findings from both B2 and C1)                   │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
═══════════════════════════════════════════════════════════════
  PHASE 3 GATE  ──  full pipeline runs, ≥1 real vulnerability
═══════════════════════════════════════════════════════════════
```

### Critical-Path Summary

The longest sequential chain determines overall Phase 3 duration:

```
Phase 2 Gate → B1 (recon) → B2 (injection) ─┐
                          → C1 (XSS)     ───┤──→ C2 (report) → Phase 3 Gate
```

**Critical path:** Phase 2 → B1 → {B2 ‖ C1} → C2

A1 and A2 run on the side; they are on the critical path only if A1 takes
longer than B1. Keeping A1 focused on the orchestrator (no prompt iteration)
ensures it finishes fast and unblocks A2.

---

## Notes

- **Highest-risk phase.** If `runAgent()` has issues, it blocks everything. B1/C1 should test standalone before the pipeline is wired.
- Focus on getting any output first, then quality. A rough recon report is better than a perfect prompt that hasn't been tested.
- If exploit agents fail to find vulnerabilities, don't block — reasonable hypotheses are sufficient for this gate.
- `try/catch` at the phase level is critical: a crash in exploitation must not prevent the report phase from running with whatever data is available.
