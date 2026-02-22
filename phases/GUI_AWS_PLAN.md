# PenteraX — Full Pipeline Rewrite for AWS Juice Shop + GUI Launcher

## TL;DR

Rewrite all 6 phase documents and implement PenteraX as a **Python-only** agentic pentest pipeline targeting OWASP Juice Shop on a user-provided AWS instance, launched from a **CustomTkinter desktop GUI**. The existing Python infrastructure (pipeline orchestrator, skill registry, 3 skill scripts) is solid and stays. The missing layers — agent runner (Claude SDK), prompt templates, GUI, CLI, environment management — get built on top.

This plan identifies **15 specific race conditions / failure modes** and addresses each with concrete mitigations. It also defines **gate criteria** for every phase so we know exactly when each phase is done.

> **Why this plan exists:** The current phase docs describe a TypeScript architecture that was abandoned — the actual codebase is Python. All 6 phase docs will be rewritten to reflect reality.

---

## Existing Codebase Inventory (What We Keep)

Before building, confirm what already works:

| File | Status | Notes |
|------|--------|-------|
| `src/pipeline.py` (504 lines) | **KEEP + MODIFY** | 4-phase orchestrator, PipelineConfig, load_prompt(), save_deliverable(), validate_phase_output() |
| `src/skills/skill_loader.py` (328 lines) | **KEEP + MODIFY** | SkillRegistry, discover_skills(), run_skill_script(), build_prompt_context() |
| `src/skills/skill_wrappers.py` (266 lines) | **KEEP + MODIFY** | parse_nmap(), validate_deliverable(), lookup_cve(), batch_lookup_cve() |
| `src/__init__.py` | **KEEP + UPDATE** | Must export new modules |
| `src/skills/__init__.py` | **KEEP** | Already imports skill_loader, skill_wrappers |
| `skills/` (3 skills) | **KEEP** | network-recon, vulnerability-lookup, response-analysis |
| `skills_repo/` | **DELETE in Phase 1** | Exact duplicate of skills/ — causes drift risk |
| `requirements.txt` | **REWRITE** | Currently only requests + pyyaml, anthropic commented out |

---

## Architecture: AppConfig vs PipelineConfig

The existing `PipelineConfig` (pipeline.py line ~50) handles pipeline-level settings. The new `AppConfig` handles *application-level* settings (API keys, budget, GUI state). They relate as follows:

```
AppConfig (src/config.py)              PipelineConfig (src/pipeline.py)
├── anthropic_api_key                  ├── target_url ← from AppConfig
├── nvd_api_key                        ├── repo_path
├── target_url  ──────────────────────►├── output_dir ← from AppConfig
├── output_dir  ──────────────────────►├── max_retries ← from AppConfig
├── max_retries ──────────────────────►└── verbose ← from AppConfig
├── max_budget_usd
└── verbose
```

`AppConfig.to_pipeline_config() -> PipelineConfig` — adapter method. PipelineConfig stays unchanged so existing pipeline code doesn't break. AppConfig is the new *source of truth* passed from GUI/CLI.

---

## Exception Types: `src/exceptions.py` (NEW — Phase 1)

All custom exceptions defined in one module, imported everywhere:

```python
class PenteraXError(Exception): ...              # Base
class BudgetExhaustedError(PenteraXError): ...   # AgentRunner — budget exceeded
class PipelineAbortedError(PenteraXError): ...   # User clicked Stop / Ctrl+C
class PreflightError(PenteraXError): ...         # Pre-flight check critical failure
class ValidationError(PenteraXError): ...        # Deliverable validation failure
```

---

## Directory Structure (Final Target)

```
PenteraX/
├── pyproject.toml                 # NEW — package config + entry points
├── requirements.txt               # REWRITTEN — all deps
├── .env.example                   # NEW — template for secrets
├── .gitignore                     # UPDATE — add deliverables/, .env, __pycache__
├── skills/                        # KEEP — 3 skills
├── src/
│   ├── __init__.py                # UPDATE — export new modules
│   ├── __main__.py                # NEW — python -m src entry
│   ├── config.py                  # NEW — AppConfig + load_dotenv
│   ├── exceptions.py              # NEW — all custom exceptions
│   ├── preflight.py               # NEW — pre-flight checks
│   ├── agent_runner.py            # NEW — Claude SDK wrapper
│   ├── pipeline.py                # MODIFY — atomic writes, dynamic tech stack, stop event
│   ├── gui.py                     # NEW — CustomTkinter app
│   ├── gui_events.py              # NEW — event dataclasses for queue
│   ├── logging_handler.py         # NEW — logging → GUI bridge
│   ├── cli.py                     # NEW — argparse headless entry
│   ├── skills/
│   │   ├── __init__.py            # KEEP
│   │   ├── skill_loader.py        # MODIFY — frozen flag, context caching
│   │   └── skill_wrappers.py      # MODIFY — tempfile for batch, retry
│   └── prompts/                   # NEW DIRECTORY — all prompt templates
│       ├── recon.md
│       ├── analysis-injection.md
│       ├── analysis-xss.md
│       ├── exploit-injection.md
│       ├── exploit-xss.md
│       ├── report.md
│       └── shared/                # NEW DIRECTORY — reusable fragments
│           ├── target-context.md
│           ├── output-format.md
│           └── safety-rails.md
└── deliverables/                  # RUNTIME — gitignored
    ├── .gitkeep
    └── replay/                    # Pre-recorded fallback deliverables
```

---

## Phase 1 — Foundation (Hours 0–2)

### Objective
Python project scaffold complete, all dependencies installable, configuration and pre-flight modules working, ready to build agent infrastructure.

### Gate Criteria (ALL must pass to advance)
- [ ] `python -m venv .venv && .venv\Scripts\activate && pip install -e .` succeeds
- [ ] `python -c "from src.config import AppConfig; print(AppConfig())"` works
- [ ] `python -c "from src.preflight import run_preflight; print(run_preflight.__doc__)"` works
- [ ] `python -c "from src.exceptions import BudgetExhaustedError"` works
- [ ] `.env.example` exists at project root
- [ ] `skills_repo/` directory is deleted
- [ ] `src/prompts/` and `src/prompts/shared/` directories exist (empty files OK)
- [ ] `python -c "from src.pipeline import PipelineConfig"` still works (no regressions)

### Step 1.1 — Delete `skills_repo/`
Remove the duplicate immediately to prevent drift. The pipeline uses `PROJECT_ROOT / "skills"` which points to `skills/`. Verify with: `python -c "from src.skills.skill_loader import SKILLS_DIR; print(SKILLS_DIR)"`.

### Step 1.2 — Create `pyproject.toml`
Canonical package config at project root. Define entry points:
- `penterax = "src.gui:main"` (GUI default)
- `penterax-cli = "src.cli:main"` (headless)

Pin ALL dependencies (including those needed in later phases — install once):

```
anthropic>=0.40.0          # Claude SDK (currently commented in requirements.txt)
customtkinter>=5.2.0       # GUI
requests>=2.31.0           # existing
pyyaml>=6.0                # existing
python-dotenv>=1.0.0       # .env loading
Pillow>=10.0.0             # optional — GUI icons/screenshots
filelock>=3.12.0           # Phase 4 — CVE cache locking
```

### Step 1.3 — Rewrite `requirements.txt`
Mirror pyproject.toml deps for pip-only workflows:
```
anthropic>=0.40.0
customtkinter>=5.2.0
requests>=2.31.0
pyyaml>=6.0
python-dotenv>=1.0.0
Pillow>=10.0.0
filelock>=3.12.0
```

### Step 1.4 — Create `src/exceptions.py`
All custom exception classes (see Architecture section above). This must exist before any other new module.

### Step 1.5 — Create `src/config.py`
Centralized configuration module:
- `load_dotenv()` from `.env` file at project root
- `AppConfig` dataclass with fields:
  - `target_url: str = ""` (empty — forces explicit config, replaces hardcoded `localhost:3000`)
  - `anthropic_api_key: str = ""`
  - `nvd_api_key: str | None = None`
  - `output_dir: Path = DELIVERABLES_DIR`
  - `max_retries: int = 3`
  - `max_budget_usd: float = 10.0`
  - `verbose: bool = False`
- `to_pipeline_config() -> PipelineConfig` adapter method — creates a PipelineConfig from AppConfig fields so existing pipeline code doesn't change
- `validate() -> list[str]` — returns list of error strings (empty = valid). Checks: target_url non-empty, anthropic_api_key non-empty, output_dir writable
- `from_env() -> AppConfig` classmethod — loads from environment variables / .env file

### Step 1.6 — Create `.env.example`
```
ANTHROPIC_API_KEY=sk-ant-...
NVD_API_KEY=              # optional, higher rate limits
TARGET_URL=http://<aws-ip>:3000
```

### Step 1.7 — Create `src/preflight.py`
Pre-flight validation module (runs before pipeline starts):

| Check | Function | Why |
|-------|----------|-----|
| Target reachable | `check_target_reachable(url, timeout=10)` → HTTP GET, expect 200 | AWS security group misconfigs, wrong IP, Juice Shop not running |
| Nmap installed | `check_nmap_installed()` → `subprocess.run(["nmap", "--version"])` | Nmap is not bundled — may be missing |
| API key valid | `check_api_key_valid(key)` → lightweight Anthropic API call | Catches bad keys before burning budget |
| Disk space | `check_disk_space(output_dir, min_mb=100)` → `shutil.disk_usage()` | Long runs generate deliverables |
| Optional tools | `check_optional_tools()` → probe whatweb, sqlmap, curl | Report degraded features, don't fail |

Returns `PreflightResult` dataclass:
```python
@dataclass
class PreflightCheck:
    name: str
    passed: bool
    message: str
    critical: bool  # If True and failed, pipeline must not start

@dataclass
class PreflightResult:
    checks: list[PreflightCheck]
    @property
    def all_critical_passed(self) -> bool: ...
    @property
    def summary(self) -> str: ...
```

### Step 1.8 — Create directory scaffolding
- `src/prompts/` (empty)
- `src/prompts/shared/` (empty)
- `deliverables/.gitkeep`
- `deliverables/replay/` (empty)

### Step 1.9 — Update `.gitignore`
Add: `deliverables/*.md`, `deliverables/*.json`, `deliverables/pipeline.log`, `.env`, `__pycache__/`, `*.egg-info/`, `.venv/`

### Step 1.10 — Update `src/__init__.py`
Expose new modules so `from src.config import AppConfig` works. Keep existing exports intact.

### AWS Target Setup Note
Remove all Docker/localhost references from phase-1-foundation.md. The target is a **pre-existing AWS instance**. User must ensure:
- Juice Shop running on port 3000
- Security group allows inbound TCP on ports 22, 80, 443, 3000
- Security group allows nmap scan traffic (don't block SYN probes)

### File Dependency Order (Phase 1)
```
src/exceptions.py          (no deps — create first)
    ↓
src/config.py              (imports exceptions)
    ↓
src/preflight.py           (imports config, exceptions)
    ↓
pyproject.toml, .env.example, .gitignore   (no code deps)
```

---

## Phase 2 — Core Infrastructure (Hours 2–4)

### Objective
Claude SDK integration working, all prompt templates drafted with structured output schemas, agent can be called and returns content.

### Gate Criteria (ALL must pass)
- [ ] `python -c "from src.agent_runner import AgentRunner"` works
- [ ] `AgentRunner.run("Say hello", "test")` returns a string response from Claude
- [ ] Budget tracking increments after a call (`runner.total_cost_usd > 0`)
- [ ] All 6 prompt template files exist in `src/prompts/` with `{{VAR}}` placeholders
- [ ] All 3 shared fragments exist in `src/prompts/shared/`
- [ ] `load_prompt(PROMPTS_DIR / "recon.md", {"TARGET_URL": "http://example.com"})` returns substituted text
- [ ] Prompt templates contain explicit "Do NOT assume localhost" instructions

### Step 2.1 — Create `src/agent_runner.py`
Claude SDK integration:

```python
class AgentRunner:
    def __init__(self, api_key: str, max_budget_usd: float = 10.0,
                 stop_event: threading.Event | None = None):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.max_budget_usd = max_budget_usd
        self.total_cost_usd = 0.0
        self._budget_lock = threading.Lock()  # Race condition #1
        self._stop_event = stop_event

    def run(self, prompt: str, phase_name: str) -> str:
        """Matches Callable[[str, str], str] expected by run_pipeline(agent_runner=...)."""
        ...
```

**Critical signature detail:** `run_pipeline()` in pipeline.py calls `agent_runner(prompt_text, "recon")` — a 2-arg callable returning `str`. The `AgentRunner.run(prompt, phase_name)` method must match this exactly. To pass the bound method: `agent_runner=runner.run`.

Features:
- **Budget tracking:** Running `total_cost_usd` from `response.usage.input_tokens + output_tokens * model_pricing`. Raise `BudgetExhaustedError` if over budget. Protected by `threading.Lock` (Race condition #1).
- **Retry with exponential backoff:** Catch `anthropic.RateLimitError`, `anthropic.APIConnectionError`, `anthropic.InternalServerError`. Retry 3x with delays `[2s, 8s, 32s]`.
- **Context window management:** If prompt exceeds model context, truncate skill reference material (largest section) with warning log.
- **Stop event check:** Before each API call, check `self._stop_event.is_set()` — raise `PipelineAbortedError` if set.
- **Structured logging:** Emit log events with `phase_name, tokens_in, tokens_out, cost, duration` — picked up by the logging handler for GUI display.

### Step 2.2 — Create `src/gui_events.py`
Event dataclasses for the GUI queue (define early so agent_runner and logging_handler can emit them):

```python
@dataclass
class LogEvent:
    level: str          # DEBUG, INFO, WARNING, ERROR
    message: str
    timestamp: float

@dataclass
class PhaseStatusEvent:
    phase_name: str     # recon, analysis, exploit, report
    status: str         # started, completed, failed

@dataclass
class BudgetEvent:
    total_cost_usd: float
    phase_name: str

@dataclass
class PipelineCompleteEvent:
    success: bool
    total_duration: float
    deliverables: list[str]
```

### Step 2.3 — Create 6 prompt templates in `src/prompts/`

Each template must include these AWS-specific instructions at the top:
```
CRITICAL: The target is a REMOTE server at {{TARGET_URL}}.
Do NOT assume localhost. Do NOT use 127.0.0.1.
Use the provided {{TARGET_URL}} for ALL requests.
```

#### Template specifications:

**`recon.md`** — Phase 0 Recon
- Variables: `{{TARGET_URL}}`, `{{REPO_PATH}}`, `{{NETWORK_RECON_SKILL}}`, `{{VULN_LOOKUP_SKILL}}`
- Output deliverable: `recon_report.md`
- Required sections in output:
  - `## Technology Stack` (framework, ORM, template engine)
  - `## Endpoints` (markdown table: Route | Method | Parameters | Auth Required)
  - `## Identified Sinks` (SQL queries, eval, innerHTML, etc.)
  - `## Authentication Architecture` (JWT, session, middleware)
  - `## Traffic Baseline` (normal request/response patterns)
  - `## Prioritized Attack Surface` (ranked by exploitability)
- Must instruct agent to use `nmap -Pn --host-timeout 120s` for AWS targets
- Must instruct agent to run nmap against the **IP extracted from TARGET_URL**, not localhost

**`analysis-injection.md`** — Phase 1a Injection Analysis
- Variables: `{{RECON_DATA}}`, `{{KNOWN_VULNS}}`, `{{TARGET_URL}}`
- Output deliverable: `hypotheses_injection.md`
- Required format per hypothesis:
  ```
  ### Hypothesis N
  **Endpoint:** POST /rest/products/search
  **Parameter:** q
  **Payload:** ' OR 1=1--
  **Expected Result:** Returns all products instead of filtered subset
  **Evidence from recon:** [reference to specific sink/endpoint from recon_report.md]
  ```

**`analysis-xss.md`** — Phase 1b XSS Analysis
- Variables: same as injection
- Output deliverable: `hypotheses_xss.md`
- Same format but XSS-specific (DOM sinks, reflected inputs, stored content)

**`exploit-injection.md`** — Phase 2a Injection Exploitation
- Variables: `{{HYPOTHESES}}`, `{{TARGET_URL}}`
- Output deliverable: `findings_injection.md`
- Required format per finding:
  ```
  ### Finding N
  **Vulnerability:** SQL Injection in product search
  **Endpoint:** GET /rest/products/search?q=
  **Severity:** HIGH (CVSS 8.6)
  **Proof:** [HTTP request/response showing data extraction]
  **Evidence:** [raw HTTP response body]
  ```
- Must include retry envelope: try up to 3 alternative payloads per hypothesis

**`exploit-xss.md`** — Phase 2b XSS Exploitation
- Variables: same as injection exploit
- Output deliverable: `findings_xss.md`
- Same format with XSS proof (dialog events, DOM changes)

**`report.md`** — Phase 3 Report
- Variables: `{{FINDINGS}}`, `{{TARGET_URL}}`
- Output deliverable: `pentest_report.md`
- Required sections:
  - Executive Summary
  - Scope & Methodology
  - Findings (with CVSS v3.1 scores)
  - Evidence & Proof
  - Recommendations
  - Scope Limitations (explicitly: "Only Injection + XSS tested")

### Step 2.4 — Create `src/prompts/shared/` fragments

**`target-context.md`** — Juice Shop architecture overview:
- Default credentials: `admin@juice-sh.op` / `admin123`
- Known API patterns: `/api/*`, `/rest/*`, `/b2b/v2/*`
- Angular SPA + Express backend + SQLite/Sequelize
- Known interesting endpoints for pentest

**`output-format.md`** — Deliverable formatting rules:
- Must match validation schemas in `skills/response-analysis/references/validation-schemas.md`
- Markdown heading hierarchy requirements
- Table formatting requirements
- Evidence block formatting

**`safety-rails.md`** — Ethical constraints:
- Scope limited to the single TARGET_URL
- Do NOT scan adjacent AWS IPs
- Do NOT attempt to escalate beyond the Juice Shop application
- Do NOT exfiltrate real user data (Juice Shop is synthetic)

### File Dependency Order (Phase 2)
```
src/gui_events.py          (no deps — create first)
    ↓
src/agent_runner.py        (imports exceptions, gui_events)
    ↓
src/prompts/*.md           (no code deps — create in parallel)
src/prompts/shared/*.md    (no code deps — create in parallel)
```

---

## Phase 3 — Integration + GUI (Hours 4–8)

### Objective
Agent runner wired into pipeline, GUI launches and controls the pipeline, first end-to-end run completes against AWS target.

### Gate Criteria (ALL must pass)
- [ ] `python -m src --cli --target-url http://<aws-ip>:3000 --api-key sk-ant-...` starts the pipeline
- [ ] GUI launches with `python -m src` and all widgets render
- [ ] Clicking "Run Preflight" shows pass/fail results in the log panel
- [ ] Clicking "Start Pipeline" launches the background thread and logs appear in real-time
- [ ] Clicking "Stop" terminates the pipeline within 10 seconds
- [ ] `deliverables/recon_report.md` is generated from a real run
- [ ] At least 1 of `findings_injection.md` or `findings_xss.md` is generated
- [ ] Pipeline completes without crashing (try/catch at phase level still works)
- [ ] `save_deliverable()` uses atomic write pattern on all platforms

### Step 3.1 — Modify `pipeline.py` — atomic deliverable writes
Replace `Path.write_text()` in `save_deliverable()` (line ~101) with write-to-temp + `os.replace()`:

```python
import os, tempfile

def save_deliverable(name: str, content: str, output_dir: Path = DELIVERABLES_DIR) -> Path:
    ensure_dir(output_dir)
    path = output_dir / name
    # Atomic write: temp file → os.replace()
    fd, tmp_path = tempfile.mkstemp(dir=str(output_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
        # On Windows, os.replace() can fail with PermissionError — retry
        for attempt in range(3):
            try:
                os.replace(tmp_path, str(path))
                break
            except PermissionError:
                if attempt == 2:
                    raise
                time.sleep(0.1 * (attempt + 1))
    except:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
    logger.info("Saved deliverable: %s", path)
    return path
```

This addresses **Race condition #9** (Windows `os.replace()` not atomic) directly in the function instead of as a cross-cutting afterthought.

### Step 3.2 — Modify `pipeline.py` — dynamic tech stack parser
Replace the hardcoded tech_stack list in `run_phase_analysis()` (line ~225):

```python
def _extract_tech_stack_from_recon(recon_data: str) -> list[dict[str, str]]:
    """Parse Technology Stack section from recon_report.md.

    Looks for a ## Technology Stack section and extracts product/version pairs.
    Falls back to hardcoded Juice Shop defaults if parsing fails.
    """
    FALLBACK = [
        {"product": "express", "version": "4.17.1"},
        {"product": "angular", "version": "1.6.0"},
        {"product": "jsonwebtoken", "version": "8.5.1"},
        {"product": "sequelize", "version": "5.22.5"},
    ]
    # ... regex or line-by-line parser for ## Technology Stack section ...
    # return parsed list or FALLBACK
```

### Step 3.3 — Modify `pipeline.py` — accept `stop_event`
Add `stop_event: threading.Event | None = None` parameter to `run_pipeline()`. Pass it down to each phase function. Check `stop_event.is_set()` before starting each phase:

```python
def run_pipeline(config=None, agent_runner=None, skills_dir=None,
                 stop_event: threading.Event | None = None) -> PipelineResult:
    ...
    for phase_label, phase_fn in phases:
        if stop_event and stop_event.is_set():
            logger.info("Pipeline aborted by user before %s", phase_label)
            break
        ...
```

### Step 3.4 — Create `src/logging_handler.py`
Bridge between Python `logging` and the GUI queue:

```python
class QueueLoggingHandler(logging.Handler):
    """Puts LogEvent objects onto a queue for GUI consumption."""
    def __init__(self, event_queue: queue.Queue):
        super().__init__()
        self.event_queue = event_queue

    def emit(self, record: logging.LogRecord):
        self.event_queue.put(LogEvent(
            level=record.levelname,
            message=self.format(record),
            timestamp=record.created,
        ))
```

**How it captures existing logs:** Attach this handler to the **root logger** at startup. All existing `logger.info()` calls in pipeline.py, skill_loader.py, and skill_wrappers.py use `logging.getLogger("spaider.pipeline")` and `logging.getLogger("spaider.skills")` — both propagate to root. The handler captures them all.

Also configure a `RotatingFileHandler` writing to `deliverables/pipeline.log` for post-mortem debugging.

### Step 3.5 — Create `src/gui.py` — CustomTkinter GUI

Layout:
```
┌─────────────────────────────────────────────────────┐
│  PenteraX — Agentic Pentest Pipeline                │
├──────────────────┬──────────────────────────────────┤
│  CONFIG PANEL    │  LOG STREAM                      │
│                  │                                  │
│  Target URL:[__] │  [scrolling log output]          │
│  API Key:  [__]  │                                  │
│  Output Dir:[__] │                                  │
│  Max Retries:[_] │                                  │
│  Budget ($):[__] │                                  │
│                  │                                  │
│  [Run Preflight] ├──────────────────────────────────┤
│  [Start Pipeline]│  PHASE STATUS                    │
│  [Stop]          │  ● Recon      [✓/✗/…]           │
│                  │  ● Analysis   [✓/✗/…]           │
│  BUDGET: $X.XX   │  ● Exploit    [✓/✗/…]           │
│  ELAPSED: MM:SS  │  ● Report     [✓/✗/…]           │
└──────────────────┴──────────────────────────────────┘
```

**Thread architecture** (THE critical design):

1. **GUI main thread** — all Tkinter widget updates.
2. **Pipeline daemon thread** — `threading.Thread(target=..., daemon=True)`.
3. **Communication:** `queue.Queue` (thread-safe).
   - Background thread pushes `LogEvent`, `PhaseStatusEvent`, `BudgetEvent`, `PipelineCompleteEvent`.
   - Main thread polls queue every 100ms via `root.after(100, poll_queue)`.
4. **Stop button:** Sets `threading.Event` (`stop_requested`). Agent runner checks before each API call.

**Race condition mitigations (GUI-specific):**

- **#2:** Never access Tkinter widgets from background thread. ALL widget updates go through queue → `after()` poll.
- **#3:** "Start Pipeline" button disabled while running. Re-enabled on `PipelineCompleteEvent`. Use `BooleanVar` for state.
- **#4:** `WM_DELETE_WINDOW` handler: (1) set `stop_requested`, (2) wait up to 5s for thread join, (3) force-exit if stuck.

### Step 3.6 — Create `src/cli.py` — headless CLI

```python
def main():
    parser = argparse.ArgumentParser(description="PenteraX CLI")
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--output-dir", default="deliverables")
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--budget", type=float, default=10.0)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--resume-from", choices=["recon","analysis","exploit","report"])
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
```

**SIGINT handling for CLI** (not just GUI):
```python
import signal
stop_event = threading.Event()
signal.signal(signal.SIGINT, lambda *_: stop_event.set())
```
Pass `stop_event` to both `AgentRunner` and `run_pipeline()`. On Ctrl+C, graceful shutdown propagates exactly like the GUI Stop button.

### Step 3.7 — Create `src/__main__.py`
```python
"""Enable python -m src invocation."""
import sys
if "--cli" in sys.argv:
    from src.cli import main
else:
    from src.gui import main
main()
```

### File Dependency Order (Phase 3)
```
src/logging_handler.py     (imports gui_events)
    ↓
src/gui.py                 (imports config, preflight, agent_runner, logging_handler, gui_events, pipeline)
src/cli.py                 (imports config, preflight, agent_runner, pipeline)
src/__main__.py            (imports gui or cli)

pipeline.py modifications  (no new deps — just code changes)
```

---

## Phase 4 — Reliability (Hours 8–16)

### Objective
Pipeline reliably finds 2+ vulnerabilities across consecutive runs. Parallel execution, locking, connection resilience, and abort propagation all working.

### Gate Criteria (ALL must pass)
- [ ] Pipeline finds ≥1 SQL injection in 3/3 consecutive runs
- [ ] Pipeline finds ≥1 XSS in 3/3 consecutive runs
- [ ] Analysis sub-phases run in parallel (injection + XSS simultaneously)
- [ ] Exploit sub-phases run in parallel
- [ ] Total pipeline runtime < 15 minutes
- [ ] Total API cost < $25 per run
- [ ] Stop button / Ctrl+C terminates pipeline within 10 seconds
- [ ] No deadlocks or race conditions observed in 5 consecutive runs
- [ ] CVE cache works correctly under parallel access
- [ ] `batch_lookup_cve()` uses unique temp files per call

### Step 4.1 — Parallel sub-phase execution
Refactor the sequential `for` loop in `run_phase_analysis()` (pipeline.py line ~240) and `run_phase_exploit()` to use `concurrent.futures.ThreadPoolExecutor(max_workers=2)`:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_phase_analysis(registry, config, agent_runner=None, stop_event=None):
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            pool.submit(_run_single_analysis, "injection", ...): "injection",
            pool.submit(_run_single_analysis, "xss", ...): "xss",
        }
        for future in as_completed(futures):
            result = future.result()
            ...
```

**Race condition #5:** Each sub-phase writes to a different deliverable (no file contention). Shared `AgentRunner` budget counter is protected by lock (#1).

**Race condition #6:** Concurrent retries both call `agent_runner()`. Claude API handles concurrent requests. Budget counter uses `threading.Lock` with compare-and-raise-if-over-budget.

### Step 4.2 — Fix `batch_lookup_cve()` temp file race
**Race condition #7:** `batch_lookup_cve()` writes to hardcoded `_tech_stack_batch.json`. If called concurrently, both write to the same file.

Fix in `skill_wrappers.py`:
```python
import tempfile
if batch_file_path is None:
    fd, batch_file_path = tempfile.mkstemp(
        suffix="_tech_stack_batch.json",
        dir=str(PROJECT_ROOT / "deliverables"),
    )
    os.close(fd)
```

### Step 4.3 — CVE cache locking
Add `filelock` around cache read-write in `lookup_cve.py`:

```python
from filelock import FileLock

cache_lock = FileLock(str(cache_path) + ".lock")
with cache_lock:
    # read or write cache
```

On Windows, `os.replace()` can fail with `PermissionError` if another process has the file open — wrap in retry loop (Race condition #9).

### Step 4.4 — Connection resilience for AWS
| Component | Current | Fix |
|-----------|---------|-----|
| `lookup_cve.py` API calls | 10s/15s timeout, no retry | Add 2 retries with exponential backoff |
| `parse_nmap.py` / nmap | Default timeout | Add `--host-timeout 120s` to all nmap invocations |
| HTTP to Juice Shop | No retry | Add retry wrapper with backoff on `ConnectionError`, `Timeout` |

### Step 4.5 — Validation hardening
Update `validate_response.py` to add checks:
- **Target URL consistency:** Deliverable should reference the AWS URL, not `localhost` or `127.0.0.1`
- **Evidence authenticity:** HTTP response codes should be plausible (100-599 range)
- **Finding deduplication:** Same CVE shouldn't appear multiple times in findings

### Step 4.6 — SkillRegistry thread safety
**Race condition #8:** `build_prompt_context()` reads files from disk on every call. Cache after first build.

Add to `SkillRegistry`:
```python
self._frozen = False
self._context_cache: dict[str, str] = {}

def freeze(self):
    """Prevent reload() during pipeline run."""
    self._frozen = True

def build_prompt_context(self, skill_name: str) -> str:
    if skill_name in self._context_cache:
        return self._context_cache[skill_name]
    ctx = self._build_prompt_context_uncached(skill_name)
    if self._frozen:
        self._context_cache[skill_name] = ctx
    return ctx
```

### Step 4.7 — Pipeline abort propagation
When user clicks "Stop" or sends Ctrl+C, the `stop_requested` event propagates into:

| Location | Mechanism |
|----------|-----------|
| `agent_runner.run()` | Check before API call → raise `PipelineAbortedError` |
| `run_skill_script()` | `proc.kill()` on stop event (subprocess bounded by timeout) |
| `validate_phase_output()` retry loop | Check before each retry iteration |
| `run_pipeline()` phase loop | Check before starting each phase |

### Testing Protocol (Phase 4 gate)
Run the following test matrix:

| Run | Mode | Expected |
|-----|------|----------|
| 1 | Full pipeline, GUI | ≥2 vulns found, no crashes |
| 2 | Full pipeline, CLI | ≥2 vulns found, cost < $25 |
| 3 | Full pipeline, CLI | ≥2 vulns found, time < 15min |
| 4 | Stop mid-pipeline (GUI) | Terminates < 10s, no orphan processes |
| 5 | Stop mid-pipeline (CLI, Ctrl+C) | Same |

---

## Phase 5 — Polish (Hours 16–20)

### Objective
Demo-ready system with polished GUI, replay fallback, resume capability, and report export.

### Gate Criteria (ALL must pass)
- [ ] Full pipeline run completes in < 10 minutes
- [ ] GUI shows real-time phase progress with visual indicators
- [ ] Settings persist between sessions (`~/.penterax/settings.json`)
- [ ] `--replay` flag loads pre-recorded deliverables and shows "[REPLAY MODE]"
- [ ] `--resume-from exploit` skips recon and analysis, starts at exploit phase
- [ ] "Save Report" button exports `pentest_report.md` to user-chosen path
- [ ] Dark/light theme toggle works
- [ ] One complete successful run recorded in `deliverables/replay/`

### Step 5.1 — GUI enhancements
- **Phase progress indicators:** Indeterminate spinner during agent calls, checkmark/X on completion
- **Findings viewer tab:** After pipeline, display `pentest_report.md` in scrollable text widget
- **Settings persistence:** Save to `~/.penterax/settings.json`:
  ```json
  {
    "target_url": "http://...",
    "output_dir": "deliverables",
    "max_budget_usd": 10.0,
    "theme": "dark"
  }
  ```
  Load on startup; API key is NEVER persisted (security).
- **Dark/light theme:** `ctk.set_appearance_mode("dark" | "light")`

### Step 5.2 — Replay mode
If Claude API unavailable or budget exhausted:
- Load pre-recorded deliverables from `deliverables/replay/`
- Run pipeline in validation-only mode (`agent_runner=None`)
- GUI shows "[REPLAY MODE]" in status bar
- CLI prints "[REPLAY MODE]" banner

### Step 5.3 — Resume from phase
If pipeline crashed on Phase 2 (Exploit), restart from Phase 2 using existing Phase 0/1 deliverables:
- CLI: `--resume-from exploit`
- GUI: Dropdown selector for starting phase
- Implementation: Skip phase functions before the resume point. Pipeline already reads deliverables from disk, so this is just `phases = phases[resume_index:]`.

### Step 5.4 — Report export
"Save Report" button → `tkinter.filedialog.asksaveasfilename()` → copy `pentest_report.md`.
Optional: render to HTML via `markdown` library (add as optional dependency, not required).

---

## Phase 6 — Demo (Hours 20–24)

### Objective
Successful live demo with backup recording. All contingencies tested.

### Gate Criteria (FINAL)
- [ ] 3 dress rehearsal runs completed successfully
- [ ] Backup recording saved in `deliverables/replay/`
- [ ] `--replay` fallback tested and confirmed working
- [ ] Final run produces ≥2 proven vulnerabilities
- [ ] `pentest_report.md` is professional and complete
- [ ] Total run time < 10 minutes
- [ ] Total cost < $25

### Demo Preparation Checklist
1. Verify AWS Juice Shop instance running and accessible
2. Pre-warm CVE cache: `python -c "from src.skills.skill_wrappers import ..."`
3. Prepare replay recording from best Phase 4/5 run
4. Test full pipeline 3x end-to-end (3 dress rehearsals)
5. Capture GUI screenshots at each phase transition

### Emergency Procedures
| Scenario | Action |
|----------|--------|
| Claude API goes down | Switch to `--replay` mode |
| AWS instance dies | Have local Docker Juice Shop ready: `docker run -d -p 3000:3000 bkimminich/juice-shop` |
| Nmap hangs | GUI Stop button → skip recon → use cached recon deliverable |
| Pipeline too slow | Switch to replay, narrate pre-computed results |
| Only 1 vuln found | Present as focused demo, mention other class "in progress" |

### Dress Rehearsal Protocol
- **Rehearsal 1:** Full live run. Note all issues.
- **Fix window:** Apply prompt/output fixes (no architecture changes).
- **Rehearsal 2:** Verify fixes. Confirm time < 10min.
- **Rehearsal 3:** Final confidence run. Save all deliverables as replay backup. No changes after this.

---

## Cross-Cutting Concerns

### Race Condition Summary

| # | Location | Risk | Mitigation |
|---|----------|------|------------|
| 1 | `AgentRunner.total_cost_usd` | GUI thread reads while pipeline writes | `threading.Lock` on budget counter |
| 2 | Tkinter widgets | Background thread touches widgets → crash | ALL updates via queue → `after()` poll |
| 3 | "Start Pipeline" button | Double-click launches two pipelines | Disable button while running via `BooleanVar` |
| 4 | Window close during run | Orphan background thread | `WM_DELETE_WINDOW` → stop + join(5s) + force-exit |
| 5 | Parallel analysis deliverables | Two threads write same file | Different output files per sub-phase |
| 6 | Parallel retry budget | Concurrent retries exceed budget | `threading.Lock` with compare-and-raise |
| 7 | `batch_lookup_cve()` temp file | Concurrent writes to `_tech_stack_batch.json` | `tempfile.mkstemp()` unique per call |
| 8 | `build_prompt_context()` disk reads | Files change during run | Cache after first build + `frozen` flag |
| 9 | Windows `os.replace()` | `PermissionError` if file open | Retry loop with 100ms backoff |

### Windows Path Handling
All existing code uses `pathlib.Path` (good). Additional care:
- `os.replace()` retry in `save_deliverable()` (Step 3.1)
- `os.replace()` retry in CVE cache writes (Step 4.3)
- `tempfile.mkstemp()` uses `dir=` parameter so temp files are on the same filesystem as targets (required for `os.replace()`)

### Nmap on AWS
AWS security groups may silently drop SYN packets, making nmap hang. Mitigations baked into the recon prompt:
- Force `-Pn` (skip host discovery, assume host is up)
- Force `--host-timeout 120s`
- The `nmap-options.md` reference already documents these flags — the prompt enforces them

### `skills_repo/` Cleanup
Deleted in Phase 1 Step 1.1. Pipeline uses `PROJECT_ROOT / "skills"`. No symlinks needed.

---

## Transition: GUI_AWS_PLAN → Phase 1

When this plan is over a new agent can begin execution. Stop iterating. Your context window is likely cooked.

1. **Activate venv:** `python -m venv .venv && .venv\Scripts\activate`
2. **Delete `skills_repo/`** (Step 1.1)
3. **Create `src/exceptions.py`** (Step 1.4 — no dependencies)
4. **Create `src/config.py`** (Step 1.5)
5. **Create `src/preflight.py`** (Step 1.7)
6. **Create `pyproject.toml` + rewrite `requirements.txt`** (Steps 1.2, 1.3)
7. **Create `.env.example`, update `.gitignore`** (Steps 1.6, 1.9)
8. **Create directory scaffolding** (Step 1.8)
9. **Run gate criteria checks** — all must pass before advancing to Phase 2
10. **Rewrite `phase-1-foundation.md`** to reflect what was actually built

Each subsequent phase follows the same pattern: build → verify gate criteria → rewrite the phase doc.

Subprocess cleanup — run_skill_script() in skill_loader.py line ~130 catches TimeoutExpired but doesn't call proc.kill(). A timed-out nmap subprocess could become a zombie. Add proc.kill() + proc.wait() in the except block.

Logging standardization — currently the pipeline uses print() statements (visible in the code). Replace all print() calls with logging.getLogger("penterax") calls so the GUI log handler captures everything.

New File Structure (Final)

PenteraX/
├── pyproject.toml              ← NEW
├── requirements.txt            ← UPDATED
├── .env.example                ← NEW
├── phases/                     ← ALL REWRITTEN
│   ├── phase-1-foundation.md
│   ├── phase-2-core-infrastructure.md
│   ├── phase-3-integration.md
│   ├── phase-4-reliability.md
│   ├── phase-5-polish.md
│   └── phase-6-demo.md
├── skills/                     ← UNCHANGED (existing scripts are solid)
├── src/
│   ├── __init__.py             ← UPDATED (exports, version)
│   ├── __main__.py             ← NEW
│   ├── config.py               ← NEW
│   ├── preflight.py            ← NEW
│   ├── agent_runner.py         ← NEW
│   ├── pipeline.py             ← MODIFIED (atomic writes, dynamic tech stack, stop event)
│   ├── gui.py                  ← NEW
│   ├── cli.py                  ← NEW
│   ├── logging_handler.py      ← NEW
│   ├── prompts/                ← NEW
│   │   ├── recon.md
│   │   ├── analysis-injection.md
│   │   ├── analysis-xss.md
│   │   ├── exploit-injection.md
│   │   ├── exploit-xss.md
│   │   ├── report.md
│   │   └── shared/
│   │       ├── target-context.md
│   │       ├── output-format.md
│   │       └── safety-rails.md
│   └── skills/                 ← MINOR UPDATES
│       ├── __init__.py
│       ├── skill_loader.py     ← MODIFIED (subprocess cleanup, freeze flag)
│       └── skill_wrappers.py   ← MODIFIED (unique temp files)
└── deliverables/               ← CREATED AT RUNTIME
    ├── replay/                 ← PRE-RECORDED FALLBACK
    └── pipeline.log


    Race Condition & Failure Mode Summary
#	Issue	Location	Mitigation
1	Budget counter concurrent access	agent_runner.py	threading.Lock on accumulator
2	Tkinter widget access from bg thread	gui.py	Queue + after() poll pattern
3	Double pipeline launch	gui.py	Disable button while running
4	Window close during pipeline	gui.py	WM_DELETE_WINDOW → stop + join
5	Parallel sub-phase file contention	pipeline.py	Separate deliverable filenames (already correct)
6	Parallel sub-phase budget race	agent_runner.py	Lock around compare + raise
7	Shared temp batch file	skill_wrappers.py line ~144	Unique NamedTemporaryFile per call
8	Skills dir modified during run	skill_loader.py	Cache prompt context after first build
9	Windows os.replace() failure	pipeline.py, lookup_cve.py	Retry-on-PermissionError wrapper
10	Zombie nmap subprocess	skill_loader.py line ~130	proc.kill() + proc.wait() on timeout
11	Stale CVE cache in parallel lookups	lookup_cve.py	File lock (filelock package)
12	AWS SG dropping nmap packets	Recon prompt	Enforce -Pn --host-timeout 120s
13	Claude API transient failures	agent_runner.py	Exponential backoff (3 retries)
14	Corrupt deliverable from crash	pipeline.py line ~101	Atomic write (temp + os.replace())
15	Pipeline abort not propagating	pipeline.py, skill_loader.py	Check stop_requested event at every phase boundary + kill subprocesses
Verification

Unit tests: pytest tests/ covering config.py, preflight.py, agent_runner.py (with mocked Anthropic client), atomic write utilities, queue-based logging
Integration test: Launch GUI → enter AWS target URL → run preflight → verify all checks pass → start pipeline → verify all 4 phases complete → view report
Stress test: Run 3 consecutive full pipelines without restarting the GUI to catch resource leaks (file handles, threads, queue buildup)
Stop-button test: Start pipeline → wait for Phase 1 to begin → click Stop → verify background thread terminates within 5s and no zombie subprocesses remain
Replay test: Disconnect from internet → start pipeline in replay mode → verify it completes using pre-recorded deliverables
Windows-specific: Test os.replace() atomic writes under concurrent access on NTFS
Decisions

Python-only — chose Python over the TypeScript architecture described in phase docs, matching existing implementation reality
CustomTkinter over Streamlit — per user preference; ships with no server dependency, native desktop feel
Pre-existing AWS instance — user provides URL, no auto-provisioning; simplest integration path
Remove skills_repo — eliminate duplication drift risk; vendored skills is the source of truth
filelock package for CVE cache — cross-platform file locking; avoids platform-specific fcntl/msvcrt code