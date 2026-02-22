"""Cross-platform discovery of external security tools (nmap, whatweb, sqlmap).

Provides ``find_tool()`` — the single source of truth for locating external
binaries.  Pipeline modules, preflight checks, and skill wrappers should all
call ``find_tool("nmap")`` rather than hard-coding paths or using
``shutil.which()`` directly.

Tool resolution order:
1. Environment variable override (e.g. ``NMAP_PATH``)
2. ``shutil.which()`` (system PATH)
3. Platform-specific well-known install locations
4. Python-package console scripts (e.g. sqlmap installed via pip)

Usage::

    from src.tool_discovery import find_tool, ToolInfo, check_all_tools

    nmap = find_tool("nmap")
    if nmap.available:
        subprocess.run([nmap.path, "--version"])

    summary = check_all_tools()
    for name, info in summary.items():
        print(f"{name}: {'OK' if info.available else 'MISSING'} — {info.path or info.reason}")
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

logger = logging.getLogger("spaider.tool_discovery")

VENV_SCRIPTS = Path(sys.executable).parent  # e.g. .venv/Scripts or .venv/bin


@dataclass
class ToolInfo:
    """Result of attempting to locate a tool."""

    name: str
    available: bool
    path: str | None = None
    version: str | None = None
    reason: str = ""


# ---------------------------------------------------------------------------
# Well-known install locations (per platform)
# ---------------------------------------------------------------------------

_WINDOWS_KNOWN_PATHS: dict[str, list[str]] = {
    "nmap": [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    ],
    "whatweb": [],            # WhatWeb is rare on Windows; typically needs Ruby
    "sqlmap": [
        str(VENV_SCRIPTS / "sqlmap.exe"),
        str(VENV_SCRIPTS / "sqlmap"),
    ],
    "curl": [
        r"C:\Windows\System32\curl.exe",
    ],
}

_UNIX_KNOWN_PATHS: dict[str, list[str]] = {
    "nmap": ["/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/homebrew/bin/nmap"],
    "whatweb": ["/usr/bin/whatweb", "/usr/local/bin/whatweb", "/opt/homebrew/bin/whatweb"],
    "sqlmap": [
        str(VENV_SCRIPTS / "sqlmap"),
        "/usr/bin/sqlmap",
        "/usr/local/bin/sqlmap",
    ],
    "curl": ["/usr/bin/curl", "/usr/local/bin/curl"],
}

# Version flags by tool
_VERSION_FLAGS: dict[str, list[str]] = {
    "nmap": ["--version"],
    "whatweb": ["--version"],
    "sqlmap": ["--version"],
    "curl": ["--version"],
}


# ---------------------------------------------------------------------------
# Core discovery logic
# ---------------------------------------------------------------------------

def _env_override(tool_name: str) -> str | None:
    """Check for an environment variable override like NMAP_PATH."""
    var = f"{tool_name.upper()}_PATH"
    val = os.environ.get(var)
    if val and Path(val).is_file():
        return val
    return None


def _which(tool_name: str) -> str | None:
    """Standard PATH lookup."""
    return shutil.which(tool_name)


def _known_paths(tool_name: str) -> str | None:
    """Check platform-specific well-known install locations."""
    if platform.system() == "Windows":
        candidates = _WINDOWS_KNOWN_PATHS.get(tool_name, [])
    else:
        candidates = _UNIX_KNOWN_PATHS.get(tool_name, [])

    for p in candidates:
        if Path(p).is_file():
            return p
    return None


def _python_module_path(tool_name: str) -> str | None:
    """For tools installable via pip (e.g. sqlmap), check as a Python module."""
    if tool_name == "sqlmap":
        # sqlmap installs a console_scripts entry point
        exe_name = "sqlmap.exe" if platform.system() == "Windows" else "sqlmap"
        candidate = VENV_SCRIPTS / exe_name
        if candidate.is_file():
            return str(candidate)
        # Fall back to `python -m sqlmap`
        try:
            result = subprocess.run(
                [sys.executable, "-m", "sqlmap", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return f"{sys.executable} -m sqlmap"
        except Exception:
            pass
    return None


def _get_version(tool_path: str, tool_name: str) -> str:
    """Attempt to extract the version string for a discovered tool."""
    flags = _VERSION_FLAGS.get(tool_name, ["--version"])

    # Handle "python -m sqlmap" style paths
    if tool_path.endswith(f"-m {tool_name}"):
        cmd = tool_path.split() + flags
    else:
        cmd = [tool_path] + flags

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
        )
        output = (proc.stdout or proc.stderr or "").strip()
        # Return first non-empty line
        for line in output.splitlines():
            line = line.strip()
            if line:
                return line
    except Exception:
        pass
    return "unknown"


def find_tool(tool_name: str, skip_version: bool = False) -> ToolInfo:
    """Locate an external tool and return its path + version info.

    Resolution order:
    1. ``<TOOL>_PATH`` environment variable
    2. ``shutil.which()``
    3. Platform-specific well-known locations
    4. Python-package console scripts (sqlmap)

    Args:
        tool_name: One of "nmap", "whatweb", "sqlmap", "curl".
        skip_version: If True, skip the version check (faster).

    Returns:
        ToolInfo with ``available=True`` and ``path`` set, or
        ``available=False`` with ``reason`` explaining why.
    """
    tool_name = tool_name.lower().strip()

    resolvers = [
        ("env override", _env_override),
        ("system PATH", _which),
        ("well-known path", _known_paths),
        ("Python package", _python_module_path),
    ]

    for source, resolver in resolvers:
        path = resolver(tool_name)
        if path:
            version = _get_version(path, tool_name) if not skip_version else None
            logger.info("Found %s via %s: %s (version: %s)",
                        tool_name, source, path, version)
            return ToolInfo(
                name=tool_name,
                available=True,
                path=path,
                version=version,
            )

    reason = (
        f"{tool_name} not found. Checked: environment variable "
        f"{tool_name.upper()}_PATH, system PATH, well-known install locations, "
        f"and Python packages."
    )
    logger.warning(reason)
    return ToolInfo(name=tool_name, available=False, reason=reason)


def check_all_tools(
    tools: list[str] | None = None,
    skip_version: bool = False,
) -> dict[str, ToolInfo]:
    """Check availability of all (or specified) external tools.

    Args:
        tools: List of tool names. Defaults to ["nmap", "whatweb", "sqlmap", "curl"].
        skip_version: If True, skip version checks.

    Returns:
        Dict mapping tool name to ToolInfo.
    """
    if tools is None:
        tools = ["nmap", "whatweb", "sqlmap", "curl"]
    return {name: find_tool(name, skip_version=skip_version) for name in tools}


def get_tool_path_or_raise(tool_name: str) -> str:
    """Return the tool path or raise FileNotFoundError.

    Convenience wrapper for scripts that require a tool to be present.
    """
    info = find_tool(tool_name, skip_version=True)
    if not info.available or not info.path:
        raise FileNotFoundError(
            f"{tool_name} is not installed or not found. {info.reason}"
        )
    return info.path
