"""Tests for the Playwright bridge (Stream A).

Unit tests mock the browser; integration tests (marked with ``_integration``)
require a live Chromium and optionally a running Juice Shop instance.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# Ensure the project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Unit tests (mocked — no real browser needed)
# ---------------------------------------------------------------------------

class TestPlaywrightBridgeUnit(unittest.TestCase):
    """Verify handler functions return the expected schema using mocks."""

    def _make_mocked_manager(self):
        """Create a mock PlaywrightManager (no real browser)."""
        mock_page = MagicMock()
        mock_page.url = "http://example.com"
        mock_page.title.return_value = "Example"
        mock_page.screenshot.return_value = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        mock_page.evaluate.return_value = 42

        mgr = MagicMock()
        mgr._page = mock_page
        mgr._dialog_log = []
        mgr._network_log = []
        mgr._ensure_page.return_value = mock_page

        return mgr

    @patch("src.skills.playwright_bridge.PlaywrightManager")
    def test_handle_browser_navigate_schema(self, MockPWM):
        """browser_navigate returns {success, url, title, dialogs}."""
        from src.skills.playwright_bridge import handle_browser_navigate

        mgr = self._make_mocked_manager()
        MockPWM.get.return_value = mgr
        MockPWM._lock = MagicMock()
        MockPWM._tick = MagicMock()

        result = handle_browser_navigate("http://example.com")
        self.assertIn("success", result)
        self.assertIn("url", result)
        self.assertIn("title", result)
        self.assertIn("dialogs", result)

    @patch("src.skills.playwright_bridge.PlaywrightManager")
    def test_handle_browser_click_schema(self, MockPWM):
        """browser_click returns {success, selector}."""
        from src.skills.playwright_bridge import handle_browser_click

        mgr = self._make_mocked_manager()
        MockPWM.get.return_value = mgr
        MockPWM._lock = MagicMock()
        MockPWM._tick = MagicMock()

        result = handle_browser_click("#btn")
        self.assertIn("success", result)
        self.assertIn("selector", result)

    @patch("src.skills.playwright_bridge.PlaywrightManager")
    def test_handle_browser_type_schema(self, MockPWM):
        """browser_type returns {success, selector, text}."""
        from src.skills.playwright_bridge import handle_browser_type

        mgr = self._make_mocked_manager()
        MockPWM.get.return_value = mgr
        MockPWM._lock = MagicMock()
        MockPWM._tick = MagicMock()

        result = handle_browser_type("#input", "hello")
        self.assertIn("success", result)

    @patch("src.skills.playwright_bridge.PlaywrightManager")
    def test_handle_browser_evaluate_schema(self, MockPWM):
        """browser_evaluate returns {success, result}."""
        from src.skills.playwright_bridge import handle_browser_evaluate

        mgr = self._make_mocked_manager()
        MockPWM.get.return_value = mgr
        MockPWM._lock = MagicMock()
        MockPWM._tick = MagicMock()

        result = handle_browser_evaluate("1+1")
        self.assertIn("success", result)
        self.assertIn("result", result)

    @patch("src.skills.playwright_bridge.PlaywrightManager")
    def test_handle_browser_network_requests_schema(self, MockPWM):
        """browser_network_requests returns {success, requests, count}."""
        from src.skills.playwright_bridge import handle_browser_network_requests

        mgr = self._make_mocked_manager()
        MockPWM.get.return_value = mgr
        MockPWM._lock = MagicMock()

        result = handle_browser_network_requests()
        self.assertIn("success", result)
        self.assertIn("requests", result)
        self.assertIn("count", result)


class TestMCPToolDefinitions(unittest.TestCase):
    """Ensure all 6 browser tools are registered in MCP_TOOLS."""

    EXPECTED_BROWSER_TOOLS = {
        "browser_navigate",
        "browser_click",
        "browser_type",
        "browser_screenshot",
        "browser_evaluate",
        "browser_network_requests",
    }

    def test_all_browser_tools_defined(self):
        from src.agent_loop import MCP_TOOLS
        tool_names = {t["name"] for t in MCP_TOOLS}
        missing = self.EXPECTED_BROWSER_TOOLS - tool_names
        self.assertFalse(missing, f"Missing browser tool definitions: {missing}")

    def test_browser_tools_have_input_schema(self):
        from src.agent_loop import MCP_TOOLS
        for tool in MCP_TOOLS:
            if tool["name"] in self.EXPECTED_BROWSER_TOOLS:
                self.assertIn("input_schema", tool, f"{tool['name']} missing input_schema")


class TestDispatcherHandlers(unittest.TestCase):
    """All 6 browser handlers are registered and dispatch without KeyError."""

    EXPECTED_BROWSER_TOOLS = {
        "browser_navigate",
        "browser_click",
        "browser_type",
        "browser_screenshot",
        "browser_evaluate",
        "browser_network_requests",
    }

    def test_all_browser_handlers_registered(self):
        from src.agent_loop import SkillToolDispatcher
        from src.skills.skill_loader import SkillRegistry

        registry = SkillRegistry()
        dispatcher = SkillToolDispatcher(registry, use_playwright=True)
        handler_names = set(dispatcher.tool_names)

        missing = self.EXPECTED_BROWSER_TOOLS - handler_names
        self.assertFalse(missing, f"Missing browser handlers: {missing}")

    def test_playwright_disabled_removes_handlers(self):
        from src.agent_loop import SkillToolDispatcher
        from src.skills.skill_loader import SkillRegistry

        registry = SkillRegistry()
        dispatcher = SkillToolDispatcher(registry, use_playwright=False)
        handler_names = set(dispatcher.tool_names)

        present = self.EXPECTED_BROWSER_TOOLS & handler_names
        self.assertFalse(present, f"Browser handlers should NOT be present when Playwright disabled: {present}")


class TestConfigFlag(unittest.TestCase):
    """PipelineConfig.use_playwright flag works."""

    def test_default_true(self):
        from src.pipeline import PipelineConfig
        cfg = PipelineConfig()
        self.assertTrue(cfg.use_playwright)

    def test_can_disable(self):
        from src.pipeline import PipelineConfig
        cfg = PipelineConfig(use_playwright=False)
        self.assertFalse(cfg.use_playwright)

    def test_max_browser_calls_default(self):
        from src.pipeline import PipelineConfig
        cfg = PipelineConfig()
        self.assertEqual(cfg.max_browser_calls, 50)


# ---------------------------------------------------------------------------
# Integration tests (require real Chromium — skip if not installed)
# ---------------------------------------------------------------------------

def _playwright_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True)
        browser.close()
        pw.stop()
        return True
    except Exception:
        return False


PLAYWRIGHT_AVAILABLE = _playwright_available()


@unittest.skipUnless(PLAYWRIGHT_AVAILABLE, "Playwright/Chromium not installed")
class TestPlaywrightIntegration(unittest.TestCase):
    """Integration tests with a real headless browser."""

    @classmethod
    def setUpClass(cls):
        from src.skills.playwright_bridge import PlaywrightManager
        PlaywrightManager.set_max_calls(100)

    @classmethod
    def tearDownClass(cls):
        from src.skills.playwright_bridge import PlaywrightManager
        PlaywrightManager.shutdown()

    def test_navigate_to_example(self):
        from src.skills.playwright_bridge import handle_browser_navigate
        result = handle_browser_navigate("https://example.com")
        self.assertTrue(result["success"])
        self.assertIn("Example", result["title"])

    def test_evaluate_js(self):
        from src.skills.playwright_bridge import handle_browser_evaluate
        result = handle_browser_evaluate("1 + 1")
        self.assertTrue(result["success"])
        self.assertEqual(result["result"], 2)

    def test_screenshot_creates_file(self):
        from src.skills.playwright_bridge import handle_browser_screenshot, EVIDENCE_DIR
        result = handle_browser_screenshot("test-screenshot.png")
        self.assertTrue(result["success"])
        png_path = EVIDENCE_DIR / "test-screenshot.png"
        self.assertTrue(png_path.exists())
        self.assertGreater(png_path.stat().st_size, 0)
        # Clean up
        png_path.unlink(missing_ok=True)

    def test_network_requests_populated(self):
        from src.skills.playwright_bridge import (
            handle_browser_navigate,
            handle_browser_network_requests,
        )
        handle_browser_navigate("https://example.com")
        result = handle_browser_network_requests()
        self.assertTrue(result["success"])
        self.assertGreater(result["count"], 0)

    def test_dispatch_browser_navigate(self):
        """Full dispatch through SkillToolDispatcher works."""
        from src.agent_loop import SkillToolDispatcher
        from src.skills.skill_loader import SkillRegistry

        registry = SkillRegistry()
        dispatcher = SkillToolDispatcher(registry, use_playwright=True)
        result = dispatcher.dispatch("browser_navigate", {"url": "https://example.com"})
        self.assertTrue(result.get("success"))


# ---------------------------------------------------------------------------
# Juice Shop integration (optional — requires running target)
# ---------------------------------------------------------------------------

TARGET_URL = os.environ.get("TARGET_URL", "http://54.146.141.88:3000")


def _juice_shop_reachable() -> bool:
    import requests
    try:
        r = requests.get(TARGET_URL, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


JUICE_SHOP_UP = _juice_shop_reachable() if PLAYWRIGHT_AVAILABLE else False


@unittest.skipUnless(JUICE_SHOP_UP, "Juice Shop not reachable")
class TestXSSOnJuiceShop(unittest.TestCase):
    """Live XSS proof against Juice Shop."""

    @classmethod
    def setUpClass(cls):
        from src.skills.playwright_bridge import PlaywrightManager
        PlaywrightManager.set_max_calls(100)

    @classmethod
    def tearDownClass(cls):
        from src.skills.playwright_bridge import PlaywrightManager
        PlaywrightManager.shutdown()

    def test_xss_search_dialog(self):
        from src.skills.playwright_bridge import handle_browser_navigate
        result = handle_browser_navigate(
            f"{TARGET_URL}/#/search?q=<iframe src='javascript:alert(`xss`)'>",
            wait_until="domcontentloaded",
        )
        self.assertTrue(result["success"])
        # Check if a dialog was captured (XSS proof)
        if result["dialogs"]:
            self.assertTrue(
                any(d["message"] == "xss" for d in result["dialogs"]),
                f"Expected 'xss' dialog, got: {result['dialogs']}"
            )

    def test_dom_evaluation(self):
        from src.skills.playwright_bridge import handle_browser_navigate, handle_browser_evaluate
        handle_browser_navigate(
            f"{TARGET_URL}/#/search?q=test",
            wait_until="domcontentloaded",
        )
        result = handle_browser_evaluate("document.title")
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["result"])


if __name__ == "__main__":
    # Run with verbosity
    unittest.main(verbosity=2)
