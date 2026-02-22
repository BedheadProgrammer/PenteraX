"""Playwright browser automation bridge for XSS exploitation.

Provides a singleton ``PlaywrightManager`` that owns a headless Chromium
browser and exposes tool-handler functions matching the MCP tool names
already referenced in the prompt templates (``browser_navigate``,
``browser_click``, etc.).

Stream A implementation — in-process ``playwright.sync_api``.
"""

from __future__ import annotations

import base64
import logging
import threading
import time
from pathlib import Path
from typing import Any

from playwright.sync_api import sync_playwright, Playwright, Browser, BrowserContext, Page

logger = logging.getLogger("spaider.playwright_bridge")

# Evidence directory lives under deliverables/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
EVIDENCE_DIR = _PROJECT_ROOT / "deliverables" / "evidence"


# ---------------------------------------------------------------------------
# PlaywrightManager — singleton lifecycle manager
# ---------------------------------------------------------------------------

class PlaywrightManager:
    """Manages a single headless Chromium browser + context + page.

    Thread-safety: all public methods acquire ``_lock`` so only one
    browser operation runs at a time (Playwright is not thread-safe).
    """

    _instance: PlaywrightManager | None = None
    _lock = threading.RLock()

    # Budget guard — max browser calls per pipeline run
    _max_calls: int = 50
    _call_count: int = 0

    def __init__(self) -> None:
        self._pw: Playwright = sync_playwright().start()
        self._browser: Browser = self._pw.chromium.launch(headless=True)
        self._context: BrowserContext = self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )
        self._page: Page = self._context.new_page()
        self._dialog_log: list[dict[str, str]] = []
        self._network_log: list[dict[str, Any]] = []
        self._setup_dialog_listener()
        self._setup_network_listener()
        logger.info("PlaywrightManager started (Chromium headless)")

    # -- listeners ----------------------------------------------------------

    def _setup_dialog_listener(self) -> None:
        """Auto-capture alert/confirm/prompt dialogs."""
        def on_dialog(dialog):
            self._dialog_log.append({
                "type": dialog.type,
                "message": dialog.message,
            })
            dialog.accept()
        self._page.on("dialog", on_dialog)

    def _setup_network_listener(self) -> None:
        """Capture network request/response pairs."""
        def on_response(response):
            try:
                self._network_log.append({
                    "url": response.url,
                    "status": response.status,
                    "method": response.request.method,
                    "headers": dict(response.headers),
                })
            except Exception:
                pass  # ignore failures on cancelled requests
        self._page.on("response", on_response)

    # -- singleton access ---------------------------------------------------

    @classmethod
    def get(cls) -> PlaywrightManager:
        """Return the singleton instance, creating it lazily on first call."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def shutdown(cls) -> None:
        """Shut down the browser and Playwright process."""
        with cls._lock:
            if cls._instance is not None:
                try:
                    cls._instance._browser.close()
                except Exception:
                    pass
                try:
                    cls._instance._pw.stop()
                except Exception:
                    pass
                cls._instance = None
                cls._call_count = 0
                logger.info("PlaywrightManager shut down")

    @classmethod
    def is_running(cls) -> bool:
        return cls._instance is not None

    @classmethod
    def set_max_calls(cls, n: int) -> None:
        cls._max_calls = n

    @classmethod
    def get_call_count(cls) -> int:
        return cls._call_count

    @classmethod
    def _tick(cls) -> None:
        """Increment call counter; raise if budget exhausted."""
        cls._call_count += 1
        if cls._call_count > cls._max_calls:
            raise RuntimeError(
                f"Browser call budget exhausted ({cls._max_calls} calls). "
                "Increase max_browser_calls in config or reduce browser usage."
            )

    # -- crash recovery -----------------------------------------------------

    def _ensure_page(self) -> Page:
        """Re-create page if the previous one crashed."""
        try:
            # Simple liveness check
            self._page.url  # noqa: B018
        except Exception:
            logger.warning("Browser page crashed — re-creating")
            try:
                self._context.close()
            except Exception:
                pass
            self._context = self._browser.new_context(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
            )
            self._page = self._context.new_page()
            self._dialog_log.clear()
            self._network_log.clear()
            self._setup_dialog_listener()
            self._setup_network_listener()
        return self._page


# ---------------------------------------------------------------------------
# Tool handler functions
# ---------------------------------------------------------------------------

def handle_browser_navigate(url: str, wait_until: str = "load") -> dict[str, Any]:
    """Navigate to *url*, return page title and any captured dialogs.

    The default *wait_until* is ``"load"`` rather than ``"networkidle"``
    because single-page apps (e.g. Juice Shop) maintain persistent
    WebSocket / long-poll connections that prevent ``networkidle`` from
    ever firing, causing the call to block until the full timeout expires.
    Playwright themselves discourage ``networkidle`` for testing.
    """
    with PlaywrightManager._lock:
        PlaywrightManager._tick()
        mgr = PlaywrightManager.get()
        page = mgr._ensure_page()
        mgr._dialog_log.clear()
        mgr._network_log.clear()
        try:
            page.goto(url, wait_until=wait_until, timeout=30_000)
        except Exception as exc:
            # Timeout or navigation error — still return what we have
            logger.warning("browser_navigate error: %s", exc)
        # Retrieve page metadata with safety timeouts to avoid hanging
        # on pages in a transitional state after a goto timeout.
        try:
            current_url = page.url
        except Exception:
            current_url = url
        try:
            title = page.title()
        except Exception:
            title = ""
        return {
            "success": True,
            "url": current_url,
            "title": title,
            "dialogs": list(mgr._dialog_log),
        }


def handle_browser_click(selector: str) -> dict[str, Any]:
    """Click element matching *selector* (CSS or ``text=...``)."""
    with PlaywrightManager._lock:
        PlaywrightManager._tick()
        mgr = PlaywrightManager.get()
        page = mgr._ensure_page()
        try:
            page.click(selector, timeout=10_000)
            return {"success": True, "selector": selector}
        except Exception as exc:
            return {"success": False, "error": str(exc), "selector": selector}


def handle_browser_type(selector: str, text: str) -> dict[str, Any]:
    """Type *text* into the input matching *selector*."""
    with PlaywrightManager._lock:
        PlaywrightManager._tick()
        mgr = PlaywrightManager.get()
        page = mgr._ensure_page()
        try:
            page.fill(selector, text, timeout=10_000)
            return {"success": True, "selector": selector, "text": text}
        except Exception as exc:
            return {"success": False, "error": str(exc), "selector": selector}


def handle_browser_screenshot(path: str | None = None, full_page: bool = True) -> dict[str, Any]:
    """Capture a screenshot.  Saves to *path* (or auto-generated name) under
    ``deliverables/evidence/`` and returns the base64-encoded PNG plus the
    relative file path.
    """
    with PlaywrightManager._lock:
        PlaywrightManager._tick()
        mgr = PlaywrightManager.get()
        page = mgr._ensure_page()

        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

        if path is None:
            ts = int(time.time() * 1000)
            path = f"screenshot-{ts}.png"

        # Ensure the file ends up inside the evidence directory
        out_path = EVIDENCE_DIR / Path(path).name

        raw_bytes = page.screenshot(full_page=full_page, timeout=15_000)
        out_path.write_bytes(raw_bytes)
        b64 = base64.b64encode(raw_bytes).decode("ascii")

        rel_path = f"deliverables/evidence/{out_path.name}"
        return {
            "success": True,
            "path": rel_path,
            "size_bytes": len(raw_bytes),
            "base64_png": b64[:200] + "..." if len(b64) > 200 else b64,
        }


def handle_browser_evaluate(expression: str) -> dict[str, Any]:
    """Execute JavaScript *expression* in the page context and return the result."""
    with PlaywrightManager._lock:
        PlaywrightManager._tick()
        mgr = PlaywrightManager.get()
        page = mgr._ensure_page()
        try:
            result = page.evaluate(expression)
            return {"success": True, "result": result}
        except Exception as exc:
            return {"success": False, "error": str(exc)}


def handle_browser_network_requests() -> dict[str, Any]:
    """Return captured network request/response pairs since last navigation."""
    with PlaywrightManager._lock:
        mgr = PlaywrightManager.get()
        return {
            "success": True,
            "requests": list(mgr._network_log),
            "count": len(mgr._network_log),
        }
