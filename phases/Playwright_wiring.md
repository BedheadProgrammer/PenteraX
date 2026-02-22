# Playwright Wiring — Two-Stream Implementation Plan

**Status:** ✅ Complete (Stream A) — Stream B deferred  
**Created:** 2026-02-22  
**Updated:** 2026-02-22  
**Priority:** Complete — In-process Playwright (`sync_api`) is fully wired and tested  

---

## Problem Statement

The XSS exploit pipeline now has Playwright **fully wired** via Stream A (Python in-process `sync_api`):

| Layer | Expected | Actual |
|-------|----------|--------|
| `MCP_TOOLS` definitions | `browser_navigate`, `browser_click`, etc. | **✅ Present** — 6 browser tools + 8 non-browser tools (14 total) |
| `SkillToolDispatcher._handlers` | Playwright-backed handler functions | **✅ Registered** — all 6 handlers dispatch via `PlaywrightManager` |
| Python dependency | `playwright` in `.venv` | **✅ Installed** — `playwright>=1.40.0` in `pyproject.toml` + `requirements.txt` |
| Node dependency | `@playwright/mcp` in `node_modules` | **N/A** — Stream B (MCP subprocess) deferred; not needed for Stream A |
| Prompt accuracy | Matches available tools | **✅ Consistent** — `exploit-xss.md` and `tool-usage.txt` reference correct tool names |

**Default `wait_until` changed:** `handle_browser_navigate()` now defaults to `wait_until="load"` instead of `"networkidle"`.  Juice Shop (Angular SPA) maintains persistent WebSocket connections that prevent `networkidle` from ever firing, causing 30-second timeout hangs.  Tests and prompts targeting Juice Shop should use `wait_until="domcontentloaded"` for fastest results.

---

## Architecture Decision

Two parallel implementation streams that converge at a single integration point (`SkillToolDispatcher`):

```
Stream A: Python-native Playwright          Stream B: Playwright MCP subprocess
(playwright sync API in-process)            (npx @playwright/mcp --headless stdio)
         │                                            │
         ▼                                            ▼
   PlaywrightManager                          MCP StdioClient
   (sync_playwright)                          (JSON-RPC over stdin/stdout)
         │                                            │
         └────────────┬───────────────────────────────┘
                      ▼
           SkillToolDispatcher._handlers
           (browser_navigate, browser_click, ...)
                      │
                      ▼
             MCP_TOOLS definitions
             (sent to Claude API)
                      │
                      ▼
           exploit-xss.md prompts
           (already written — just needs real tools behind them)
```

**Stream A** is the recommended path (simpler, fewer moving parts, synchronous).  
**Stream B** is the alternative if MCP protocol compliance is needed for future multi-server setups.

---

## Stream A — Python-native Playwright (Recommended)

> In-process `playwright.sync_api` managed by a new `PlaywrightManager` class in `src/skills/playwright_bridge.py`.

### A1. Install dependencies
- [x] Add `playwright>=1.40.0` to `pyproject.toml` `[project.dependencies]` and `requirements.txt`
- [x] Run: `pip install playwright && playwright install chromium`
- [x] Verify: `python -c "from playwright.sync_api import sync_playwright; print('OK')"`

### A2. Create `src/skills/playwright_bridge.py`
- [x] `PlaywrightManager` class — singleton lifecycle manager with `RLock`
  ```python
  class PlaywrightManager:
      """Manages a single headless Chromium browser + context + page."""
      _instance: PlaywrightManager | None = None
      
      def __init__(self):
          self._pw = sync_playwright().start()
          self._browser = self._pw.chromium.launch(headless=True)
          self._context = self._browser.new_context()
          self._page = self._context.new_page()
          self._dialog_log: list[dict] = []
          self._setup_dialog_listener()
      
      def _setup_dialog_listener(self):
          """Auto-capture alert/confirm/prompt dialogs."""
          def on_dialog(dialog):
              self._dialog_log.append({
                  "type": dialog.type,
                  "message": dialog.message,
              })
              dialog.accept()
          self._page.on("dialog", on_dialog)
      
      @classmethod
      def get(cls) -> PlaywrightManager:
          if cls._instance is None:
              cls._instance = cls()
          return cls._instance
      
      @classmethod
      def shutdown(cls):
          if cls._instance:
              cls._instance._browser.close()
              cls._instance._pw.stop()
              cls._instance = None
  ```

- [x] Tool handler functions (match the names the prompts already use):
  ```python
  def handle_browser_navigate(url: str, wait_until: str = "load") -> dict:
      mgr = PlaywrightManager.get()
      mgr._dialog_log.clear()
      mgr._page.goto(url, wait_until=wait_until, timeout=30000)
      return {
          "success": True,
          "url": mgr._page.url,
          "title": mgr._page.title(),
          "dialogs": list(mgr._dialog_log),
      }
  
  def handle_browser_click(selector: str) -> dict: ...
  def handle_browser_type(selector: str, text: str) -> dict: ...
  def handle_browser_screenshot(path: str = None, full_page: bool = True) -> dict: ...
  def handle_browser_evaluate(expression: str) -> dict: ...
  def handle_browser_network_requests() -> dict: ...
  ```

### A3. Register tools in `agent_loop.py`

- [x] Add 6 tool definitions to `MCP_TOOLS` list:

  | Tool Name | Description | Required Params |
  |-----------|-------------|-----------------|
  | `browser_navigate` | Navigate to a URL, returns title + captured dialogs | `url` |
  | `browser_click` | Click element by CSS selector or text | `selector` |
  | `browser_type` | Type text into an input field | `selector`, `text` |
  | `browser_screenshot` | Capture page screenshot, returns base64 PNG | — |
  | `browser_evaluate` | Execute JavaScript in page context | `expression` |
  | `browser_network_requests` | List captured network request/response pairs | — |

- [x] Add handler mappings to `SkillToolDispatcher.__init__`:
  ```python
  from .skills.playwright_bridge import (
      handle_browser_navigate,
      handle_browser_click,
      handle_browser_type,
      handle_browser_screenshot,
      handle_browser_evaluate,
      handle_browser_network_requests,
      PlaywrightManager,
  )
  
  self._handlers.update({
      "browser_navigate": self._handle_browser_navigate,
      "browser_click": self._handle_browser_click,
      "browser_type": self._handle_browser_type,
      "browser_screenshot": self._handle_browser_screenshot,
      "browser_evaluate": self._handle_browser_evaluate,
      "browser_network_requests": self._handle_browser_network_requests,
  })
  ```

### A4. Lifecycle integration

- [x] Start Playwright lazily on first `browser_*` call (not at import time) — `PlaywrightManager.get()` is lazy singleton
- [x] Shut down Playwright when pipeline finishes — `PlaywrightManager.shutdown()` called in cleanup
- [x] Add timeout guard: browser calls have per-operation timeouts (30s navigate, 10s click/type, 15s screenshot)
- [x] Handle crash recovery: `_ensure_page()` re-creates context/page if browser page crashed

### A5. Evidence directory

- [x] Create `deliverables/evidence/` directory for screenshots
- [x] `browser_screenshot` saves PNG to `deliverables/evidence/<name>.png`
- [x] Return the relative path in the tool result so the agent can reference it

### A6. Update prompts (minimal — they're mostly correct already)

- [x] Fix contradiction: `analysis-xss.md` no longer references "no Playwright" (prompts are consistent)
- [x] `tool-usage.txt` Section 2 matches the actual tool names and parameter schemas
- [x] `network-interception.txt` examples match actual handler return format

---

## Stream B — Playwright MCP Subprocess (Alternative)

> Spawn `npx @playwright/mcp@latest --headless` as a child process, communicate via JSON-RPC over stdio.

### B1. Install dependencies
- [ ] `npm install @playwright/mcp@latest`
- [ ] Verify: `npx @playwright/mcp@latest --headless` starts and responds to init

### B2. Create `src/mcp_client.py`
- [ ] `McpStdioClient` class — manages subprocess lifecycle
  ```python
  class McpStdioClient:
      """JSON-RPC client over stdin/stdout to an MCP subprocess."""
      
      def __init__(self, command: list[str]):
          self.proc = subprocess.Popen(
              command,
              stdin=subprocess.PIPE,
              stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,
          )
          self._msg_id = 0
          self._initialize()
      
      def _initialize(self):
          """Send MCP initialize handshake."""
          self._send({"method": "initialize", "params": {...}})
          self._send({"method": "notifications/initialized"})
      
      def call_tool(self, name: str, arguments: dict) -> dict:
          """Call an MCP tool and return the result."""
          self._msg_id += 1
          return self._send({
              "method": "tools/call",
              "params": {"name": name, "arguments": arguments},
              "id": self._msg_id,
          })
      
      def list_tools(self) -> list[dict]:
          """Discover available tools from the MCP server."""
          return self._send({"method": "tools/list", "id": ...})
  ```

### B3. Create `src/skills/playwright_mcp_bridge.py`
- [ ] Adapter that translates `SkillToolDispatcher` calls → `McpStdioClient.call_tool()`
- [ ] Map our tool names to Playwright MCP tool names:
  | Our Tool Name | Playwright MCP Tool |
  |---------------|---------------------|
  | `browser_navigate` | `browser_navigate` |
  | `browser_click` | `browser_click` |
  | `browser_type` | `browser_type` |
  | `browser_screenshot` | `browser_screenshot` |
  | `browser_evaluate` | `browser_evaluate` |
  | `browser_network_requests` | `browser_network_requests` |

### B4. Register in dispatcher (same as A3)
- [ ] Same `MCP_TOOLS` definitions and `_handlers` mapping
- [ ] Handler functions delegate to `McpStdioClient` instead of `sync_playwright`

### B5. Lifecycle
- [ ] Start MCP subprocess on first `browser_*` call
- [ ] Health-check: ping subprocess, restart if dead
- [ ] Kill subprocess on pipeline completion

---

## Shared Tasks (Both Streams)

### S1. Testing
- [x] Unit test: `tests/test_playwright_bridge.py` — mock browser, verify tool handlers return correct schema
- [x] Integration test: navigate to Juice Shop, trigger search XSS, capture dialog
  ```python
  def test_xss_search_dialog():
      result = handle_browser_navigate(f"{TARGET_URL}/#/search?q=<iframe src='javascript:alert(`xss`)'>")
      assert result["success"]
      assert any(d["message"] == "xss" for d in result["dialogs"])
  ```
- [x] Integration test: screenshot capture produces a valid PNG file
- [x] Integration test: `browser_evaluate` returns DOM query results
- [ ] End-to-end: run `run_xss_standalone.py`, verify `findings_xss.md` contains Playwright evidence

### S2. Update `test_playwright_integration.py`
- [x] Extend existing test to verify all 6 browser tools are in `MCP_TOOLS`
- [x] Verify all 6 handlers dispatch without `KeyError`
- [x] Verify `browser_navigate` actually loads a page (integration mode)

### S3. Config & feature flag
- [x] Add `use_playwright: bool = True` to `PipelineConfig` in `pipeline.py`
- [x] When `False`, omit `browser_*` tools from `MCP_TOOLS` and don't import `playwright_bridge`
- [x] This lets the pipeline degrade gracefully to `http_request`-only mode

### S4. Budget awareness
- [x] Playwright calls are free (no API cost) but add wall-clock time
- [x] Add a `max_browser_calls: int = 50` guard (`PlaywrightManager._max_calls`) to prevent infinite page loads
- [ ] Log browser call count alongside API call stats in `AgentStats`

---

## File Change Map

| File | Change | Stream |
|------|--------|--------|
| `pyproject.toml` | Add `playwright>=1.40.0` to dependencies | A |
| `requirements.txt` | Add `playwright>=1.40.0` | A |
| `package.json` | Add `@playwright/mcp@latest` to dependencies | B |
| **`src/skills/playwright_bridge.py`** | **NEW** — PlaywrightManager + 6 handler functions | A |
| **`src/mcp_client.py`** | **NEW** — McpStdioClient for JSON-RPC over stdio | B |
| **`src/skills/playwright_mcp_bridge.py`** | **NEW** — Adapter from dispatcher to MCP client | B |
| `src/agent_loop.py` | Add 6 `MCP_TOOLS` defs + 6 `_handlers` entries | A/B |
| `src/pipeline.py` | Add `use_playwright` config flag + cleanup hook | A/B |
| `src/prompts/exploit-xss.md` | No change needed (already correct) | — |
| `src/prompts/analysis-xss.md` | Remove "no Playwright" caveat | A/B |
| `src/prompts/shared/tool-usage.txt` | Verify Section 2 matches real schemas | A/B |
| `src/prompts/shared/network-interception.txt` | Update return format examples | A/B |
| **`tests/test_playwright_bridge.py`** | **NEW** — unit + integration tests | A/B |
| `test_playwright_integration.py` | Update assertions for new tools | A/B |

---

## Implementation Order

```
Week 1: Stream A (Python-native — get it working)
─────────────────────────────────────────────────
Day 1:  A1 — Install playwright + chromium in .venv
        A2 — Build PlaywrightManager + 6 handlers
Day 2:  A3 — Register MCP_TOOLS defs + dispatcher handlers
        A4 — Lifecycle (lazy start, cleanup, timeout)
Day 3:  A5 — Evidence directory + screenshot storage
        A6 — Fix prompt contradictions
        S1 — Unit tests + integration tests
Day 4:  S3 — Config flag (use_playwright)
        S4 — Budget/call-count guard
        S2 — Update integration test
Day 5:  End-to-end: run_xss_standalone.py with real Playwright
        Fix any issues, validate findings_xss.md quality

Week 2: Stream B (MCP subprocess — optional, for extensibility)
───────────────────────────────────────────────────────────────
Day 1:  B1 — Install @playwright/mcp, verify handshake
        B2 — Build McpStdioClient
Day 2:  B3 — Build MCP bridge adapter
        B4 — Register as alternate dispatcher backend
Day 3:  B5 — Lifecycle (health check, restart, kill)
        Port tests to Stream B
Day 4:  Add config switch: PLAYWRIGHT_BACKEND=native|mcp
        Compare performance/reliability of both streams
Day 5:  Documentation, choose default backend, merge
```

---

## Success Criteria

| # | Criterion | Validation |
|---|-----------|------------|
| 1 | `browser_navigate` dispatches without error | `dispatcher.dispatch("browser_navigate", {"url": "..."})` returns `{"success": True}` |
| 2 | XSS dialog captured | Navigate to `/#/search?q=<iframe src="javascript:alert('xss')">`, result contains `dialogs: [{type: "alert", message: "xss"}]` |
| 3 | Screenshot saved | `deliverables/evidence/xss-search-dom.png` exists and is valid PNG |
| 4 | DOM evaluation works | `browser_evaluate("document.querySelectorAll('iframe').length")` returns `> 0` |
| 5 | `findings_xss.md` has real evidence | Run `run_xss_standalone.py` — output references actual dialog messages and screenshot paths |
| 6 | No KeyError on any browser tool | All 6 tools dispatch cleanly in `test_playwright_integration.py` |
| 7 | Graceful degradation | With `use_playwright=False`, pipeline runs with `http_request` only (no crash) |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Chromium fails to install on Windows | Medium | High | Use `playwright install --with-deps chromium`; document manual fallback |
| Juice Shop SPA needs wait-time tuning | High | Medium | **Resolved:** Changed default `wait_until` from `"networkidle"` to `"load"`. Tests use `"domcontentloaded"` for Juice Shop. `networkidle` is unsuitable for SPAs with persistent WebSocket connections. |
| Dialog auto-dismiss breaks page flow | Medium | Medium | Queue dialogs, let the agent decide when to dismiss via tool calls |
| Screenshot files bloat deliverables | Low | Low | Cap at 10 screenshots per run, compress with Pillow |
| MCP subprocess (Stream B) hangs on Windows | Medium | High | Use `timeout` on `proc.communicate()`, kill after 5s stall |
| Thread-safety (browser not thread-safe) | High | High | PlaywrightManager is singleton with lock; only one browser call at a time |
