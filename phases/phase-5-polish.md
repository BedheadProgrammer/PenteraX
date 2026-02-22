# Phase 5: Polish & Demo Preparation

**Hours:** 16–20  
**Objective:** Demo-ready system with professional console output, documentation, and rehearsed demo flow.  
**Status:** In Progress

---

## Gate Criteria (all must pass to advance to Phase 6)

- [ ] Full pipeline run completes in < 10 minutes
- [ ] Console output clearly shows progress (phase/agent name, status, timing)
- [ ] `README.md` exists with setup instructions, usage, and architecture overview
- [ ] Demo script written and tested (10-minute walkthrough)
- [ ] Architecture diagram created
- [ ] `--replay` fallback flag works in CLI (copies pre-computed deliverables)
- [ ] One complete successful run recorded as backup deliverables

---

## Work Streams (all parallel — separate deliverables)

### Stream A — Console Output & CLI Polish [E1: Infrastructure]

> **Files modified:** `src/cli.py`, `src/pipeline.py`, `src/agent_runner.py`, `README.md`
>
> **Note:** The project is implemented in **Python** (`src/cli.py`, `src/pipeline.py`,
> `src/agent_runner.py`).  Playwright runs in-process via `playwright.sync_api` — there
> is no Node.js MCP subprocess.

- [ ] Add colored console output:
  - [ ] Phase headers with color (e.g., blue for phase name)
  - [ ] Agent start/complete indicators (green for success, red for failure)
  - [ ] Timing per agent and per phase
  - [ ] Pipeline summary at end (total time, cost, findings count)
- [ ] Add `--replay` fallback flag to `cli.py`:
  - [ ] When passed, copy pre-computed `deliverables/` files instead of running agents
  - [ ] Useful for live demo fallback if agents fail
  - [ ] Store backup deliverables in `deliverables/replay/` from a successful run
- [ ] Write `README.md`:
  - [ ] Project overview and architecture
  - [ ] Prerequisites (Python 3.11+, Playwright Chromium, API key, external tools)
  - [ ] Setup instructions (step-by-step):
    - `python -m venv .venv && .venv\Scripts\activate`
    - `pip install -e .`
    - `playwright install chromium`
  - [ ] Usage: `python -m src --cli pipeline --target-url http://54.146.141.88:3000`
  - [ ] Available flags (`--verbose`, `--replay`)
  - [ ] Architecture diagram reference
  - [ ] Cost and timing expectations
- [ ] Time optimization:
  - [ ] Profile full run — identify slowest agents
  - [ ] Reduce `maxTurns` further if agents consistently finish early
  - [ ] Verify total time < 10 minutes for demo

### Stream B — Stretch Features / Hardening [E2: Injection]

> **Files modified:** `src/prompts/` (injection-related only), potentially new auth prompt files
>
> ⚠️ **Option A (Auth Vertical) requires E1 coordination:** Adding auth agents requires changes to `pipeline.py` and potentially `cli.py`. Coordinate with E1 before starting. E2 writes prompts; E1 wires them into the pipeline.

- [ ] **Option A — Auth Vertical (STRETCH):** Add authentication vulnerability class
  - [ ] Coordinate with E1 — confirm pipeline can accept additional agents
  - [ ] Write `src/prompts/analysis-auth.md`
  - [ ] Write `src/prompts/exploit-auth.md`
  - [ ] Target: Juice Shop admin login SQL injection (`' OR 1=1--` at `POST /rest/user/login`)
  - [ ] E1 wires auth agents into pipeline (`pipeline.py` Phase 1 and Phase 2)
  - [ ] Test 3 runs for reliability
- [ ] **Option B — Injection Hardening (if Auth is too risky):**
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
  - [ ] **Minute 4-5:** Narrate Phase 1 Analysis (hypothesis generation)
  - [ ] **Minute 5-8:** Narrate Phase 2 Exploitation (THE MONEY SHOT — Playwright browser automation live)
  - [ ] **Minute 8-9:** Show Phase 3 Report output
  - [ ] **Minute 9-10:** Architecture overview, cost breakdown, future roadmap
  - [ ] Include contingency talking points for slow/failed agents
- [ ] Create architecture diagram:
  - [ ] 4-phase pipeline visualization (Python `ThreadPoolExecutor` parallelism)
  - [ ] Agent flow with deliverable handoff
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

---

## Dependencies Between Streams

```
Stream A (console polish + README) ── independent
Stream B (stretch features) ── independent (touches different prompt files)
Stream C (demo materials) ── depends on Stream A (needs final CLI behavior for demo script)
                           — depends on a successful pipeline run (for backup deliverables in deliverables/replay/)
```

---

## Notes

- **Do not introduce risky changes at this stage.** Stretch features (Auth vertical) should only be attempted if the core pipeline is rock-solid.
- The `--replay` flag is a critical safety net — prioritize it early in this phase
- Backup deliverables should be generated from the best run during Phase 4 iteration
- If time is tight, skip colored console output and focus on demo script + README
- Architecture diagram can be hand-drawn or generated with a tool like Mermaid/draw.io
