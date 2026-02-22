"""Pre-flight checks — validates environment before the pipeline starts.

Each check returns a ``PreflightCheck`` dataclass.  The top-level
``run_preflight()`` function aggregates them into a ``PreflightResult``.

Usage::

    from src.config import AppConfig
    from src.preflight import run_preflight

    cfg = AppConfig.from_env()
    result = run_preflight(cfg)
    if not result.all_critical_passed:
        print(result.summary)
        sys.exit(1)
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from .config import AppConfig

logger = logging.getLogger("penterax.preflight")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PreflightCheck:
    """Outcome of a single pre-flight check."""

    name: str
    passed: bool
    message: str
    critical: bool  # If ``True`` and failed, pipeline must not start.


@dataclass
class PreflightResult:
    """Aggregated outcome of all pre-flight checks."""

    checks: list[PreflightCheck] = field(default_factory=list)

    @property
    def all_critical_passed(self) -> bool:
        """Return *True* when every critical check has passed."""
        return all(c.passed for c in self.checks if c.critical)

    @property
    def summary(self) -> str:
        """Human-readable summary of all checks."""
        lines: list[str] = []
        for c in self.checks:
            icon = "PASS" if c.passed else "FAIL"
            crit = " [CRITICAL]" if c.critical and not c.passed else ""
            lines.append(f"  [{icon}] {c.name}: {c.message}{crit}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_target_reachable(url: str, timeout: int = 10) -> PreflightCheck:
    """Verify the target Juice Shop instance is reachable via HTTP GET."""
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        if resp.status_code < 500:
            return PreflightCheck(
                name="Target reachable",
                passed=True,
                message=f"HTTP {resp.status_code} from {url}",
                critical=True,
            )
        return PreflightCheck(
            name="Target reachable",
            passed=False,
            message=f"Server error HTTP {resp.status_code} from {url}",
            critical=True,
        )
    except requests.RequestException as exc:
        return PreflightCheck(
            name="Target reachable",
            passed=False,
            message=f"Cannot reach {url}: {exc}",
            critical=True,
        )


def check_nmap_installed() -> PreflightCheck:
    """Verify nmap is installed and on the PATH."""
    try:
        proc = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version_line = proc.stdout.strip().splitlines()[0] if proc.stdout else "unknown"
        return PreflightCheck(
            name="Nmap installed",
            passed=True,
            message=version_line,
            critical=True,
        )
    except FileNotFoundError:
        return PreflightCheck(
            name="Nmap installed",
            passed=False,
            message="nmap not found on PATH",
            critical=True,
        )
    except Exception as exc:  # noqa: BLE001
        return PreflightCheck(
            name="Nmap installed",
            passed=False,
            message=f"Error checking nmap: {exc}",
            critical=True,
        )


def check_api_key_valid(api_key: str) -> PreflightCheck:
    """Verify the Anthropic API key with a lightweight API call."""
    if not api_key:
        return PreflightCheck(
            name="API key valid",
            passed=False,
            message="No API key provided",
            critical=True,
        )
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        # Minimal call to validate the key
        resp = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=10,
            messages=[{"role": "user", "content": "Say OK"}],
        )
        return PreflightCheck(
            name="API key valid",
            passed=True,
            message="Anthropic API key verified",
            critical=True,
        )
    except Exception as exc:  # noqa: BLE001
        return PreflightCheck(
            name="API key valid",
            passed=False,
            message=f"API key validation failed: {exc}",
            critical=True,
        )


def check_disk_space(output_dir: Path, min_mb: int = 100) -> PreflightCheck:
    """Verify sufficient disk space in the output directory."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        usage = shutil.disk_usage(str(output_dir))
        free_mb = usage.free / (1024 * 1024)
        if free_mb >= min_mb:
            return PreflightCheck(
                name="Disk space",
                passed=True,
                message=f"{free_mb:.0f} MB free (need {min_mb} MB)",
                critical=True,
            )
        return PreflightCheck(
            name="Disk space",
            passed=False,
            message=f"Only {free_mb:.0f} MB free (need {min_mb} MB)",
            critical=True,
        )
    except OSError as exc:
        return PreflightCheck(
            name="Disk space",
            passed=False,
            message=f"Cannot check disk space: {exc}",
            critical=True,
        )


def check_optional_tools() -> PreflightCheck:
    """Probe for optional tools (whatweb, sqlmap, curl) and report availability."""
    tools = ["whatweb", "sqlmap", "curl"]
    found: list[str] = []
    missing: list[str] = []

    for tool in tools:
        if shutil.which(tool):
            found.append(tool)
        else:
            missing.append(tool)

    msg_parts: list[str] = []
    if found:
        msg_parts.append(f"found: {', '.join(found)}")
    if missing:
        msg_parts.append(f"missing: {', '.join(missing)}")
    message = "; ".join(msg_parts) or "No optional tools checked"

    return PreflightCheck(
        name="Optional tools",
        passed=True,  # never critical
        message=message,
        critical=False,
    )


# ---------------------------------------------------------------------------
# Top-level runner
# ---------------------------------------------------------------------------

def run_preflight(config: "AppConfig") -> PreflightResult:
    """Execute all pre-flight checks and return the aggregated result.

    Parameters
    ----------
    config:
        Application configuration (target URL, API key, output dir, etc.).

    Returns
    -------
    PreflightResult
        Contains individual check outcomes. Inspect
        ``result.all_critical_passed`` before starting the pipeline.
    """
    checks: list[PreflightCheck] = [
        check_target_reachable(config.target_url),
        check_nmap_installed(),
        check_api_key_valid(config.anthropic_api_key),
        check_disk_space(config.output_dir),
        check_optional_tools(),
    ]

    result = PreflightResult(checks=checks)
    logger.info("Pre-flight summary:\n%s", result.summary)
    return result
