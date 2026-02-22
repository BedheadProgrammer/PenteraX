# Phase 5: Polish & Demo Preparation

**Hours:** 16–20  
**Objective:** Demo-ready system with professional console output, documentation, and rehearsed demo flow.  
**Status:** In Progress

---

## Priority Analysis

> **Stream B (Attack Coverage Hardening) is the HIGHEST priority** in this phase.
> It directly enhances attack coverage by adding an authentication vulnerability
> class and hardening existing injection detection — these are the changes that
> produce the most meaningful improvement to the pipeline's pentest capabilities.
>
> **Stream A (Console Output & CLI Polish) is the LOWEST priority.** The `--replay`
> flag and `--verbose` support are already implemented. Remaining Stream A items
> (colored console output, README polish, time profiling) are cosmetic and do not
> improve attack coverage. They should be deferred until all Stream B items are
> complete.
>
> **Stream C (Demo Materials)** is medium priority — needed for demo but does not
> affect attack coverage.

---

## Gate Criteria (all must pass to advance to Phase 6)

- [ ] Full pipeline run completes in < 10 minutes
- [ ] Auth vertical agents wired into pipeline and producing deliverables
- [ ] Console output clearly shows progress (phase/agent name, status, timing)
- [ ] `README.md` exists with setup instructions, usage, and architecture overview
- [ ] Demo script written and tested (10-minute walkthrough)
- [ ] Architecture diagram created
- [ ] `--replay` fallback flag works in CLI (copies pre-computed deliverables)
- [ ] One complete successful run recorded as backup deliverables

---

## Work Streams (ordered by attack coverage impact)

### Stream B — Auth Vertical & Hardening [E2: Injection] ⭐ HIGHEST PRIORITY

> **Files modified:** `src/prompts/analysis-auth.md` (NEW), `src/prompts/exploit-auth.md` (NEW),
> `src/pipeline.py`, `src/prompts/` (injection-related)
>
> **Rationale:** This stream adds an entirely new vulnerability class (authentication
> bypass) and hardens the existing injection detection. These changes produce the
> most enhanced attack coverage of any work in Phase 5.

- [x] **Option A — Auth Vertical:** Add authentication vulnerability class
  - [x] Write `src/prompts/analysis-auth.md` — authentication-focused analysis prompt
  - [x] Write `src/prompts/exploit-auth.md` — authentication-focused exploit prompt
  - [x] Target: Juice Shop admin login SQL injection, JWT manipulation, default credentials, password reset flaws
  - [x] Wire auth agents into pipeline (`pipeline.py` Phase 1 and Phase 2) as 3rd parallel track
  - [x] Update report phase to aggregate auth findings alongside injection and XSS
  - [x] Update `_PHASE_META` and `_REPLAY_FILES` for auth deliverables
  - [ ] Test 3 runs for reliability
- [ ] **Option B — Injection Hardening:**
  - [ ] Test against multiple injection types (not just product search)
  - [ ] Add error-based log in SQL injection as secondary target
  - [ ] Improve evidence quality (cleaner HTTP response captures)
- [ ] Harden recon agent:
  - [ ] Ensure consistent source code reading strategy
  - [ ] Reduce variability in output format

### Stream C — Demo Script & Materials [E3: XSS + Report]

> **Files created:** demo script (external), architecture diagram

- [ ] Write demo script (10-minute walkthrough):
  - [ ] **Minute 0-1:** Show Juice Shop running at `http://54.146.141.88:3000`, project structure overview
  - [ ] **Minute 1-2:** Launch pipeline: `python -m src --cli pipeline --target-url http://54.146.141.88:3000`
  - [ ] **Minute 2-4:** Narrate Phase 0 Recon (source code reading, nmap)
  - [ ] **Minute 4-5:** Narrate Phase 1 Analysis (hypothesis generation — injection, XSS, AND auth)
  - [ ] **Minute 5-8:** Narrate Phase 2 Exploitation (THE MONEY SHOT — Playwright browser automation live)
  - [ ] **Minute 8-9:** Show Phase 3 Report output (now includes auth findings)
  - [ ] **Minute 9-10:** Architecture overview, cost breakdown, future roadmap
  - [ ] Include contingency talking points for slow/failed agents
- [ ] Create architecture diagram:
  - [ ] 4-phase pipeline visualization (Python `ThreadPoolExecutor` parallelism)
  - [ ] Agent flow with deliverable handoff (now includes auth track)
  - [ ] Technology stack: Python 3.11+, Anthropic Claude API, Playwright (in-process `sync_api`), nmap, sqlmap
  - [ ] Playwright integration: singleton `PlaywrightManager`, `RLock` thread-safety, `wait_until="load"` default
- [ ] Test full demo flow end-to-end:
  - [ ] Time each phase
  - [ ] Identify dead-air moments (where narration is needed)
  - [ ] Practice switching to `--replay` if live run fails
- [ ] Generate backup deliverables:
  - [ ] Run full pipeline successfully
  - [ ] Copy all deliverables to `deliverables-backup/`
  - [ ] Verify `--replay` produces the same output (replay deliverables stored in `deliverables/replay/`)

### Stream A — Console Output & CLI Polish [E1: Infrastructure] ⬇️ LOWEST PRIORITY

> **Files modified:** `src/cli.py`, `src/pipeline.py`, `src/agent_runner.py`, `README.md`
>
> **Note:** The `--replay` flag and `--verbose` support are already implemented.
> Remaining items are cosmetic polish that does NOT enhance attack coverage.
> Defer these until Stream B is complete and verified.

- [ ] Add colored console output:
  - [ ] Phase headers with color (e.g., blue for phase name)
  - [ ] Agent start/complete indicators (green for success, red for failure)
  - [ ] Timing per agent and per phase
  - [ ] Pipeline summary at end (total time, cost, findings count)
- [x] ~~Add `--replay` fallback flag to `cli.py`~~ (already implemented)
- [ ] Write `README.md`:
  - [ ] Project overview and architecture
  - [ ] Prerequisites (Python 3.11+, Playwright Chromium, API key, external tools)
  - [ ] Setup instructions (step-by-step)
  - [ ] Usage and available flags
  - [ ] Architecture diagram reference
  - [ ] Cost and timing expectations
- [ ] Time optimization:
  - [ ] Profile full run — identify slowest agents
  - [ ] Reduce `maxTurns` further if agents consistently finish early
  - [ ] Verify total time < 10 minutes for demo

---

## Dependencies Between Streams

```
Stream B (auth vertical + hardening) ── HIGHEST PRIORITY — independent, start immediately
Stream C (demo materials) ── depends on Stream B completion (demo script must show auth findings)
                           — depends on a successful pipeline run (for backup deliverables)
Stream A (console polish + README) ── LOWEST PRIORITY — independent, defer until B complete
```

---

## Notes

- **Stream B is the critical path.** The auth vertical adds a third vulnerability class to the pipeline, significantly increasing attack coverage.
- Stream A items (colored output, README) are nice-to-have but do not affect attack coverage — skip if time is tight.
- The `--replay` flag is already implemented — no additional work needed.
- Backup deliverables should be generated from the best run during Phase 4 iteration.
- Architecture diagram can be hand-drawn or generated with a tool like Mermaid/draw.io.
