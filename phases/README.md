# SPAIDER Agent — Phase Gate Roadmap

## Overview

This document provides the master roadmap for the SPAIDER Agent 24-hour hackathon build. The implementation is broken into **6 phases** with explicit gate criteria. Each phase isolates work that can be run in parallel across engineers (E1, E2, E3) without causing conflicts.

Each phase has its own to-do list file that should be updated as work progresses.

---

## Phase Summary

| Phase | Name | Hours | Key Objective | Gate Criteria |
|-------|------|-------|---------------|---------------|
| **1** | [Foundation & Environment Setup](phase-1-foundation.md) | 0–2 | Project scaffold, target running, research complete | `npm install` succeeds, `npx tsc --noEmit` passes, Juice Shop accessible at `http://54.146.141.88:3000`, tools installed |
| **2** | [Core Infrastructure Build](phase-2-core-infrastructure.md) | 2–4 | `runAgent()` works, prompt drafts complete | Trivial agent runs via SDK, all prompt files exist |
| **3** | [Pipeline Integration & First E2E](phase-3-integration.md) | 4–8 | Full pipeline runs end-to-end | At least 1 real vulnerability found |
| **4** | [Prompt Engineering & Reliability](phase-4-reliability.md) | 8–16 | Agents reliably find vulnerabilities | 2+ vulns found across 3 consecutive runs |
| **5** | [Polish & Demo Preparation](phase-5-polish.md) | 16–20 | Demo-ready system | Full run completes in < 10 min, README exists, demo script ready |
| **6** | [Final Verification & Demo](phase-6-demo.md) | 20–24 | Successful demo | 3 dress rehearsals pass, backup recording made |

---

## Dependency Graph

```
Phase 1: Foundation & Environment Setup
  ├── [E1] Project scaffold ─────────────────────────┐
  ├── [E2] Target environment + tool install ────────┤ (all parallel, zero conflicts)
  └── [E3] Vulnerability research + prompt research ─┘
                         │
                    ── GATE 1 ──
                         │
Phase 2: Core Infrastructure Build
  ├── [E1] agent-runner.ts, mcp-server.ts, utils.ts, types.ts  (CRITICAL PATH)
  ├── [E2] recon.md, analysis-injection.md, shared prompts      (parallel — prompt files only)
  └── [E3] analysis-xss.md, exploit-xss.md drafts, report.md   (parallel — prompt files only)
                         │
                    ── GATE 2 ──
                         │
Phase 3: Pipeline Integration & First E2E
  ├── [E1] A1: pipeline.ts │ A2: cli.ts + E2E test ────────────(CRITICAL PATH)
  ├── [E2] B1: Recon agent testing │ B2: Injection agent testing
  └── [E3] C1: XSS agent testing │ C2: Report agent testing
                         │
                    ── GATE 3 ──
                         │
Phase 4: Prompt Engineering & Reliability
  ├── [E1] Error handling, logging, Promise.all parallelism ────┐
  ├── [E2] Deep injection prompt iteration (3+ full cycles) ────┤ (all parallel)
  └── [E3] Deep XSS + report prompt iteration (3+ full cycles) ┘
                         │
                    ── GATE 4 ──
                         │
Phase 5: Polish & Demo Preparation
  ├── [E1] Console output, README, timing optimization ────────┐
  ├── [E2] Stretch: Auth vertical / harden injection ──────────┤ (all parallel)
  └── [E3] Demo script, architecture diagram, demo flow test ──┘
                         │
                    ── GATE 5 ──
                         │
Phase 6: Final Verification & Demo
  └── [ALL] Dress rehearsals, flakiness fixes, demo execution
                         │
                    ── GATE 6 ──
                         │
                    ✅ DEMO DAY
```

---

## Parallel Work Streams

The following work streams are **fully independent** and can be assigned to separate agents or engineers without risk of file conflicts:

### Stream A — Infrastructure (E1)
Files owned: `src/agent-runner.ts`, `src/pipeline.ts`, `src/cli.ts`, `src/mcp-server.ts`, `src/utils.ts`, `src/types.ts`, `package.json`, `tsconfig.json`

### Stream B — Injection Vertical + Recon (E2)
Files owned: `src/prompts/recon.md`, `src/prompts/analysis-injection.md`, `src/prompts/exploit-injection.md`, `src/prompts/shared/*`, Docker/target setup

### Stream C — XSS Vertical + Report (E3)
Files owned: `src/prompts/analysis-xss.md`, `src/prompts/exploit-xss.md`, `src/prompts/report.md`, demo script, architecture diagram

> **Conflict Zones:** No files are shared across streams. The only coupling is through the `deliverables/*.md` runtime files (handoff format), which is governed by the deliverable schema defined in Phase 2.

---

## How to Use These Phase Documents

1. **Before starting work**, check the current phase's to-do list for uncompleted items
2. **Claim a task** by marking it as in-progress (or assign by engineer role)
3. **Mark tasks complete** with `[x]` as they are finished
4. **Do not advance to the next phase** until all gate criteria in the current phase are met
5. **Parallel tasks** within a phase can be worked on simultaneously by different agents/engineers
6. **Sequential tasks** are marked with dependencies and must wait for their prerequisites
