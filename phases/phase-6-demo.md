# Phase 6: Final Verification & Demo

**Hours:** 20–24  
**Objective:** Successful live demo with backup recording. All engineers aligned on talking points.  
**Status:** Not Started

---

## Gate Criteria (FINAL — all must pass for demo readiness)

- [ ] 3 dress rehearsal runs completed successfully
- [ ] Backup recording of a successful run saved
- [ ] All engineers know their demo talking points
- [ ] `--replay` fallback tested and ready
- [ ] Final pipeline run produces ≥ 2 proven vulnerabilities
- [ ] `pentest_report.md` is professional and complete
- [ ] Total run time < 10 minutes
- [ ] Total cost < $25

---

## Work Stream (collaborative — all engineers together)

### Dress Rehearsals [ALL]

- [ ] **Rehearsal 1 — Full live run:**
  - [ ] Verify AWS Juice Shop instance running at `http://54.146.141.88:3000`
  - [ ] Run `npx ts-node src/cli.ts --url=http://54.146.141.88:3000 --repo=./repos/juice-shop`
  - [ ] Time each phase
  - [ ] Note any issues (slow phases, failed agents, formatting problems)
  - [ ] Check all deliverables:
    - [ ] `recon_report.md` — has source-code-derived endpoints
    - [ ] `hypotheses_injection.md` — has specific attack hypotheses
    - [ ] `hypotheses_xss.md` — has specific XSS hypotheses
    - [ ] `findings_injection.md` — has proven SQL injection with evidence
    - [ ] `findings_xss.md` — has proven XSS with Playwright evidence
    - [ ] `pentest_report.md` — professional, CVSS scores, all findings
- [ ] **Fix issues from Rehearsal 1:**
  - [ ] List all issues found
  - [ ] Apply prompt fixes (quick iterations only — no architecture changes)
  - [ ] Apply CLI/output fixes
- [ ] **Rehearsal 2 — Verify fixes:**
  - [ ] Run full pipeline again
  - [ ] Confirm previous issues are resolved
  - [ ] Time run (should be < 10 min)
  - [ ] If issues remain, fix and iterate
- [ ] **Rehearsal 3 — Final confidence run:**
  - [ ] Full run, no changes allowed after this
  - [ ] This is the "what the audience will see" run
  - [ ] Save all deliverables as final backup
  - [ ] Record screen capture as ultimate fallback

### Demo Preparation [ALL]

- [ ] Prepare talking points for each engineer:
  - [ ] E1: Architecture decisions, SDK usage, pipeline design, cost model
  - [ ] E2: Source code analysis strategy, injection discovery, exploitation technique
  - [ ] E3: XSS approach, Playwright automation, report quality, what's next
- [ ] Prepare answers for expected questions:
  - [ ] "How does this differ from existing scanners?"
  - [ ] "What's the cost per scan?"
  - [ ] "How would you scale this?"
  - [ ] "What vulnerability classes are supported?"
  - [ ] "What's the false positive rate?"
- [ ] Final checklist before demo:
  - [ ] Docker container running and healthy at `http://54.146.141.88:3000`
  - [ ] API key has sufficient credits
  - [ ] Internet connection stable
  - [ ] Backup deliverables ready
  - [ ] `--replay` flag tested
  - [ ] Screen recording software ready (backup capture)

### Emergency Procedures

- [ ] **If live run crashes:** Switch to `--replay` mode, narrate pre-computed results
- [ ] **If live run is too slow:** Skip to pre-computed results, explain the pipeline verbally
- [ ] **If only 1 vulnerability found:** Present it as a focused demo, mention the other class was "in progress"
- [ ] **If API key fails:** Use backup recording
- [ ] **If AWS instance dies:** Switch to local Docker fallback (`docker run -d -p 3000:3000 bkimminich/juice-shop`) and update target to `http://localhost:3000`, or use `--replay` while it recovers

---

## Notes

- **No code changes after Rehearsal 3** — only talking point refinements
- The backup recording is non-negotiable — always have a pre-recorded successful run
- Allow 30 minutes between rehearsals for fixes
- Total rehearsal time budget: ~3 hours (3 × 10-min runs + fix time)
- The remaining hour (23-24) is buffer for unexpected issues
- If all 3 rehearsals pass cleanly, use extra time to practice presenter handoffs
