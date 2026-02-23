# PenteraX — About the Project

## Inspiration

The cybersecurity industry faces a persistent bottleneck: penetration testing is expensive, slow, and scarce. Skilled pentesters are in short supply, and manual assessments can take weeks for a single application. We asked ourselves — *what if an AI agent could autonomously execute a structured penetration test, from reconnaissance to exploitation to reporting, in minutes instead of days?*

The idea crystallized around two converging trends: the rise of agentic AI (LLMs that can reason, plan, and use tools in a loop) and the availability of deliberately vulnerable applications like OWASP Juice Shop that provide realistic attack surfaces. A hybrid system where deterministic pre-collection feeds high-quality context to an LLM agent that reasons about vulnerabilities, generates hypotheses, crafts exploits, and writes a professional report — all without human intervention.

We also wanted to prove that this kind of tool could be built in a 24-hour hackathon. Not a toy demo, but a working pipeline that finds real vulnerabilities and produces evidence-backed findings.

## What We Learned

**LLMs are surprisingly effective pentesters — with the right scaffolding.** Raw prompting produces hallucinated findings. But when you feed an agent real source code analysis, real nmap scan results, and real HTTP probe data, it reasons accurately about injection points, crafts working payloads, and adapts when its first attempt fails. The key insight was that *the quality of the pre-collected context determines the quality of the agent's output*.

**Prompt engineering for security is its own discipline.** We went through 3+ full iteration cycles on each prompt template (recon, analysis, exploit, report) across five vulnerability verticals — SQL injection, XSS, broken authentication, broken authorization/IDOR, and SSRF. Small wording changes in the exploit prompts (e.g., explicitly telling the agent to URL-encode payloads, or to use UNION SELECT with the exact column count from recon) made the difference between a working proof-of-concept and a wasted API call.

**Browser automation is essential for modern web exploits.** Many vulnerabilities — especially DOM-based XSS, stored XSS, and UI-level authentication bypasses — cannot be proven with curl alone. Integrating Playwright as an in-process tool the agent could call (navigate, click, type, evaluate JavaScript, capture screenshots) was a force multiplier. The agent could trigger an XSS payload and capture the resulting `alert()` dialog as evidence, just like a human pentester would.

**Race conditions hide everywhere in concurrent pipelines.** Running multiple analysis agents in parallel (injection, XSS, auth, authz, SSRF) against a shared Playwright browser and a shared cost-tracking budget required careful locking. We identified and fixed over 15 potential race conditions during the design review phase.

**Cost management matters.** Claude API calls for multi-turn agentic loops can get expensive fast. We implemented per-phase budget tracking with a global lock, exponential-backoff retry on transient errors, context-window overflow guards that truncate reference material, and a configurable browser call budget (default 50 per run) to prevent runaway costs.

## How We Built It

### Architecture

PenteraX is a **4-phase sequential pipeline** orchestrated by Python:

```
Phase 0 (Recon) → Phase 1 (Analysis) → Phase 2 (Exploit) → Phase 3 (Report)
```

Each phase loads a prompt template, injects skill outputs as template variables, runs the Claude agent with MCP-style tool definitions, validates the deliverable, and retries on failure (up to 3×).

### Core Components

| Component | Role |
|-----------|------|
| **`pipeline.py`** | Orchestrates the 4-phase pipeline, manages retries and deliverable validation |
| **`agent_runner.py`** | Wraps the Anthropic API with budget tracking, exponential backoff, and cooperative stop |
| **`agent_loop.py`** | Exposes 15+ MCP-compatible tool definitions (nmap, sqlmap, HTTP requests, CVE lookup, Playwright browser actions, deliverable saving) so the agent can act on the world |
| **`precollect.py`** | Hybrid pre-collection: source code grep analysis, nmap scanning, HTTP endpoint probing — all run before the agent to maximize context quality |
| **`playwright_bridge.py`** | Singleton Playwright manager: headless Chromium with thread-safe locking for navigate, click, type, screenshot, evaluate, and network capture |
| **`skill_loader.py`** | Dynamic skill discovery and registration from the `skills/` directory |
| **`gui.py`** | CustomTkinter desktop GUI with config panel, live log stream, phase status indicators, budget display, and replay mode |
| **`cli.py`** | Full CLI with subcommands for pipeline execution, skill management, deliverable validation, and CVE lookup |

### Vulnerability Coverage

We built dedicated analysis and exploit prompt chains for **9 vulnerability classes**:

- SQL Injection (union-based, boolean-based, auth bypass)
- NoSQL Injection (operator injection on MongoDB endpoints)
- XXE (XML External Entity via file upload and B2B endpoints)
- Path Traversal (directory traversal, null byte bypass)
- Server-Side Template Injection (Pug/Jade on B2B endpoints)
- Cross-Site Scripting (reflected, stored, DOM-based, JSONP, header-based)
- Broken Authentication (SQL injection bypass, JWT manipulation, default creds)
- Broken Authorization / IDOR (direct object reference, privilege escalation)
- SSRF (URL-based via profile image upload)

### Target

We tested against **OWASP Juice Shop** running on AWS (`http://54.146.141.88:3000`), a deliberately vulnerable web application that realistically simulates a modern Node.js/Angular e-commerce platform backed by SQLite and Sequelize ORM.

### Results

In a single automated run, PenteraX identified **29 confirmed vulnerabilities** (8 Critical, 12 High, 9 Medium) — including complete database compromise via union-based SQL injection extracting all 41 user credential hashes, authentication bypass for admin accounts, XXE file disclosure, and business logic flaws enabling financial fraud through negative quantity purchases.

### Tech Stack

- **Python 3.11+** — core pipeline, CLI, GUI
- **Anthropic Claude API** (claude-sonnet-4-20250514) — agentic reasoning engine
- **Playwright** — headless Chromium browser automation for XSS proof and DOM interaction
- **CustomTkinter** — cross-platform desktop GUI
- **nmap / sqlmap** — network reconnaissance and SQL injection automation
- **requests** — HTTP probing and exploit delivery

## Challenges We Faced

### 1. Context Window Management
The biggest technical challenge was fitting enough context into a single agent turn. Source code analysis of Juice Shop alone can produce thousands of lines. We had to implement configurable line limits per pattern category (`_MAX_MATCHES_PER_CATEGORY = 60`), strategic truncation of reference material, and a hybrid approach where deterministic pre-collection extracts only the most relevant code patterns (SQL queries, route handlers, sanitizer calls) rather than dumping everything.

### 2. Playwright Thread Safety
Playwright's `sync_api` is not thread-safe, but we needed multiple analysis agents to share a single browser instance during parallelized Phase 1. We solved this with a singleton `PlaywrightManager` using a `threading.RLock` around every public method, plus a per-run call budget to prevent infinite loops of browser actions.

### 3. Prompt Iteration Under Time Pressure
Getting the exploit prompts right required meticulous iteration. Early versions produced payloads that were syntactically correct but missed critical details — wrong column counts for UNION injection, missing URL encoding, or XSS payloads that triggered in the wrong context. We went through 3+ full cycles per vulnerability vertical, each time running the pipeline end-to-end and analyzing where the agent's reasoning diverged from reality.

### 4. Race Conditions in Budget Tracking
Multiple agents running concurrently all deduct from a shared USD budget. Without locking, two agents could both read the remaining budget as "$2.00", both decide they can afford a $1.50 call, and blow past the limit. We used `threading.Lock` for all budget mutations and `threading.Event` for cooperative stop signaling, catching `PipelineAbortedError` at every tool dispatch boundary.

### 5. Reliable Deliverable Validation
The agent's markdown output needed to match specific schemas (recon reports must have a Technology Stack table, findings must have CWE/CVSS fields, etc.). Early runs produced structurally invalid output that passed the agent's own checks but failed our validation schema. We built a `response_analysis_validate` tool with strict section/field checking and wired it into a retry loop — if validation fails, the agent gets the error list and tries again, up to 3 times.

### 6. Cross-Platform Compatibility
Nmap and sqlmap aren't available on all platforms. We implemented graceful degradation: if nmap isn't installed, the pre-collection step returns a descriptive fallback message instead of crashing. WhatWeb has a Python-based fallback. The pipeline adapts its prompts based on what data was actually collected.

### 7. Coordinating a 6-Phase Hackathon Build
We structured the 24-hour build into 6 explicit phase gates with dependency graphs and parallel work streams. Three engineers worked simultaneously on infrastructure (Stream A), injection/recon (Stream B), and XSS/reporting (Stream C) with zero file conflicts. The rigid phase-gate discipline — "don't start Phase 3 until Gate 2 passes" — kept us honest and prevented integration nightmares.

---

*Built in 24 hours. Finds 29 vulnerabilities autonomously. PenteraX proves that agentic AI can transform penetration testing from a weeks-long manual engagement into a push-button automated assessment.*
