"""Test: Is Playwright properly integrated for exploitation?

This test checks whether:
1. Browser/Playwright tools are defined in MCP_TOOLS (sent to Claude API)
2. Browser/Playwright handlers exist in SkillToolDispatcher
3. What happens when the agent tries to call browser_navigate
4. Whether playwright is installed as a Python/Node dependency
"""

import sys
import subprocess
import importlib

def test_mcp_tool_definitions():
    """Check if browser tools are defined in MCP_TOOLS."""
    from src.agent_loop import MCP_TOOLS
    tool_names = [t["name"] for t in MCP_TOOLS]
    print("=== MCP_TOOLS (tool schemas sent to Claude API) ===")
    for name in tool_names:
        print(f"  - {name}")

    browser_tools = [n for n in tool_names if "browser" in n.lower() or "playwright" in n.lower()]
    print(f"\nBrowser/Playwright tool DEFINITIONS: {browser_tools or 'NONE'}")

    EXPECTED = {"browser_navigate", "browser_click", "browser_type",
                "browser_screenshot", "browser_evaluate", "browser_network_requests"}
    missing = EXPECTED - set(browser_tools)
    if missing:
        print(f"  MISSING definitions: {missing}")
    return browser_tools


def test_dispatcher_handlers():
    """Check if dispatcher has browser tool handlers."""
    from src.agent_loop import SkillToolDispatcher
    from src.skills.skill_loader import SkillRegistry
    registry = SkillRegistry()
    dispatcher = SkillToolDispatcher(registry, use_playwright=True)

    print("\n=== Dispatcher handlers (actual tool implementations) ===")
    for name in dispatcher.tool_names:
        print(f"  - {name}")

    browser_handlers = [n for n in dispatcher.tool_names if "browser" in n.lower() or "playwright" in n.lower()]
    print(f"\nBrowser/Playwright HANDLERS: {browser_handlers or 'NONE'}")

    EXPECTED = {"browser_navigate", "browser_click", "browser_type",
                "browser_screenshot", "browser_evaluate", "browser_network_requests"}
    missing = EXPECTED - set(browser_handlers)
    if missing:
        print(f"  MISSING handlers: {missing}")
    return browser_handlers


def test_dispatch_browser_navigate():
    """Simulate what happens when Claude calls browser_navigate."""
    from src.agent_loop import SkillToolDispatcher
    from src.skills.skill_loader import SkillRegistry
    registry = SkillRegistry()
    dispatcher = SkillToolDispatcher(registry, use_playwright=True)

    print("\n=== Simulating: Claude calls browser_navigate ===")
    try:
        dispatcher.dispatch("browser_navigate", {"url": "http://example.com"})
        print("RESULT: SUCCESS (tool executed)")
        return True
    except KeyError as e:
        print(f"RESULT: KeyError - {e}")
        return False
    except Exception as e:
        print(f"RESULT: {type(e).__name__} - {e}")
        return False


def test_playwright_python_package():
    """Check if playwright Python package is installed."""
    print("\n=== Checking playwright Python package ===")
    try:
        import playwright
        print(f"playwright Python package: INSTALLED (v{playwright.__version__})")
        return True
    except ImportError:
        print("playwright Python package: NOT INSTALLED")
        return False


def test_playwright_node_package():
    """Check if @playwright/mcp Node package is available."""
    print("\n=== Checking @playwright/mcp Node package ===")
    try:
        result = subprocess.run(
            ["npx", "@playwright/mcp@latest", "--help"],
            capture_output=True, text=True, timeout=30,
            shell=True
        )
        if result.returncode == 0:
            print("@playwright/mcp: AVAILABLE")
            return True
        else:
            print(f"@playwright/mcp: NOT AVAILABLE (exit code {result.returncode})")
            print(f"  stderr: {result.stderr[:200]}")
            return False
    except FileNotFoundError:
        print("@playwright/mcp: npx not found")
        return False
    except subprocess.TimeoutExpired:
        print("@playwright/mcp: timed out (may need install)")
        return False
    except Exception as e:
        print(f"@playwright/mcp: Error - {e}")
        return False


def test_prompt_claims_vs_reality():
    """Check what the prompts tell the agent vs what's actually available."""
    print("\n=== Prompt claims vs reality ===")
    
    # Read exploit-xss prompt
    with open("src/prompts/exploit-xss.md", "r") as f:
        xss_prompt = f.read()
    
    playwright_refs = xss_prompt.lower().count("playwright")
    browser_refs = sum(1 for line in xss_prompt.split("\n") 
                       if any(b in line for b in ["browser_navigate", "browser_click", 
                                                   "browser_screenshot", "browser_evaluate",
                                                   "page.goto", "page.on(", "page.locator"]))
    
    print(f"exploit-xss.md references 'playwright': {playwright_refs} times")
    print(f"exploit-xss.md references browser/page APIs: {browser_refs} lines")
    
    # Read tool-usage prompt
    with open("src/prompts/shared/tool-usage.txt", "r") as f:
        tool_usage = f.read()
    
    playwright_section = "Playwright" in tool_usage
    print(f"tool-usage.txt has Playwright section: {playwright_section}")
    
    # Check analysis-xss acknowledgment
    try:
        with open("src/prompts/analysis-xss.md", "r") as f:
            analysis = f.read()
        admits_no_playwright = "no playwright" in analysis.lower() or "no browser" in analysis.lower()
        print(f"analysis-xss.md admits no Playwright: {admits_no_playwright}")
    except FileNotFoundError:
        print("analysis-xss.md: not found")


def main():
    print("=" * 60)
    print("PLAYWRIGHT INTEGRATION TEST")
    print("=" * 60)
    
    # Run all tests
    browser_defs = test_mcp_tool_definitions()
    browser_handlers = test_dispatcher_handlers()
    nav_works = test_dispatch_browser_navigate()
    py_installed = test_playwright_python_package()
    node_available = test_playwright_node_package()
    test_prompt_claims_vs_reality()
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    issues = []
    if not browser_defs:
        issues.append("NO browser tool definitions in MCP_TOOLS (Claude doesn't know they exist)")
    if not browser_handlers:
        issues.append("NO browser tool handlers in dispatcher (calls would crash)")
    if not nav_works:
        issues.append("browser_navigate dispatch FAILS with KeyError")
    if not py_installed:
        issues.append("playwright Python package NOT installed")
    if not node_available:
        issues.append("@playwright/mcp Node package NOT available")
    
    if issues:
        print(f"\nFOUND {len(issues)} CRITICAL ISSUES:")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
        print("\nVERDICT: Playwright is NOT functional for exploitation.")
        print("The prompts reference Playwright extensively but NO actual")
        print("integration exists. The agent has only http_request (curl-like).")
    else:
        print("\nAll checks passed - Playwright integration is functional.")
    
    return len(issues)


if __name__ == "__main__":
    sys.exit(main())
