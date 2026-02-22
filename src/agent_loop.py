"""Agentic loop integration — exposes SPAIDER skills as MCP tool definitions.

Provides:
- MCP-compatible tool definitions for each skill
- SkillToolDispatcher for runtime tool routing
- build_system_prompt_skills_section() for teaching agents about available tools
- setup_agentic_loop() convenience function for bootstrapping
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .skills.skill_loader import SkillRegistry, SkillResult, PROJECT_ROOT
from .skills.skill_wrappers import (
    parse_nmap,
    run_nmap,
    run_whatweb,
    run_sqlmap,
    run_http_request,
    validate_deliverable,
    lookup_cve,
    batch_lookup_cve,
    format_known_vulns_for_prompt,
    format_technologies_for_prompt,
    format_sqlmap_finding,
    nmap_to_markdown,
)
from .skills.playwright_bridge import (
    handle_browser_navigate,
    handle_browser_click,
    handle_browser_type,
    handle_browser_screenshot,
    handle_browser_evaluate,
    handle_browser_network_requests,
    handle_browser_set_auth,
    PlaywrightManager,
)
from .artifact_store import ArtifactStore
from .pipeline import save_deliverable, DELIVERABLES_DIR

logger = logging.getLogger("spaider.agent_loop")


# ---------------------------------------------------------------------------
# MCP Tool Definitions
# ---------------------------------------------------------------------------

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "network_recon_parse_nmap",
        "description": (
            "Parse an nmap XML scan file into structured JSON and optional "
            "markdown table. Returns host/port/service/version data."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "xml_path": {
                    "type": "string",
                    "description": "Path to the nmap XML output file.",
                },
                "output_path": {
                    "type": "string",
                    "description": "Optional path to write JSON output to.",
                },
                "markdown": {
                    "type": "boolean",
                    "description": "If true, also produce a markdown table.",
                    "default": True,
                },
            },
            "required": ["xml_path"],
        },
    },
    {
        "name": "response_analysis_validate",
        "description": (
            "Validate a pipeline deliverable against its expected schema. "
            "Returns {valid: bool, errors: list, error_count: int}. "
            "Schema types: recon_report, hypotheses, findings, pentest_report."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "deliverable_path": {
                    "type": "string",
                    "description": "Path to the deliverable markdown file.",
                },
                "schema_type": {
                    "type": "string",
                    "description": "One of: recon_report, hypotheses, findings, pentest_report.",
                    "enum": ["recon_report", "hypotheses", "findings", "pentest_report"],
                },
            },
            "required": ["deliverable_path", "schema_type"],
        },
    },
    {
        "name": "vulnerability_lookup_cve",
        "description": (
            "Look up known CVEs for a product/version, CWE, or keyword. "
            "Queries OSV.dev and NVD. Returns a list of matching vulnerabilities "
            "with CVE IDs, severity, CVSS scores, and summaries."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "product": {
                    "type": "string",
                    "description": "Software product name (e.g. 'express').",
                },
                "version": {
                    "type": "string",
                    "description": "Version string (e.g. '4.17.1').",
                },
                "cwe": {
                    "type": "string",
                    "description": "CWE identifier (e.g. 'CWE-89' or '89').",
                },
                "keyword": {
                    "type": "string",
                    "description": "Free-text keyword search.",
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity level.",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                },
            },
        },
    },
    {
        "name": "network_recon_run_nmap",
        "description": (
            "Run nmap against a target host and return structured JSON with "
            "open ports, services, versions, and script output. Supports scan "
            "profiles: quick, standard, stealth, web-focused."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host or IP to scan.",
                },
                "profile": {
                    "type": "string",
                    "description": "Scan profile.",
                    "enum": ["quick", "standard", "stealth", "web-focused"],
                    "default": "web-focused",
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification override (e.g. '80,443,3000').",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 180).",
                    "default": 180,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "network_recon_run_whatweb",
        "description": (
            "Run whatweb (or Python fallback) to fingerprint web technologies "
            "at the target URL. Returns identified frameworks, CMS, JS libraries, "
            "server software with versions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target URL to fingerprint.",
                },
                "aggression": {
                    "type": "integer",
                    "description": "WhatWeb aggression level 1-4 (default: 3).",
                    "default": 3,
                },
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "sql_injection_run_sqlmap",
        "description": (
            "Run sqlmap against a target endpoint to test for SQL injection. "
            "Returns whether the parameter is injectable, the technique used, "
            "payloads, and optionally discovered tables. Always uses --batch "
            "(non-interactive) mode."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target URL with query parameters.",
                },
                "param": {
                    "type": "string",
                    "description": "Parameter to test for SQL injection.",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method (GET/POST). Auto-detected if omitted.",
                },
                "data": {
                    "type": "string",
                    "description": "POST body (JSON string or form data).",
                },
                "headers": {
                    "type": "string",
                    "description": "Extra headers (comma-separated key:value).",
                },
                "dbms": {
                    "type": "string",
                    "description": "Target DBMS (default: sqlite).",
                    "default": "sqlite",
                },
                "level": {
                    "type": "integer",
                    "description": "Test level 1-5 (default: 3).",
                    "default": 3,
                },
                "risk": {
                    "type": "integer",
                    "description": "Risk level 1-3 (default: 2).",
                    "default": 2,
                },
                "technique": {
                    "type": "string",
                    "description": "Injection techniques: B=Boolean, E=Error, U=Union, S=Stacked, T=Time (default: BEUST).",
                    "default": "BEUST",
                },
                "tamper": {
                    "type": "string",
                    "description": "Tamper scripts (comma-separated, e.g. 'space2comment,between').",
                },
                "dump_tables": {
                    "type": "boolean",
                    "description": "If true, enumerate tables on confirmed injection.",
                    "default": False,
                },
            },
            "required": ["target_url", "param"],
        },
    },
    {
        "name": "http_request",
        "description": (
            "Send an HTTP request to a URL and return the response (status code, "
            "headers, body). Use this as your primary tool for manual exploitation "
            "testing — equivalent to curl. Supports GET, POST, PUT, DELETE. "
            "Returns truncated response body (max 10KB)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL to request (including query params for GET).",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method (default: GET).",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                    "default": "GET",
                },
                "headers": {
                    "type": "object",
                    "description": "HTTP headers as key-value pairs (e.g. {\"Content-Type\": \"application/json\"}).",
                },
                "body": {
                    "type": "string",
                    "description": "Request body (for POST/PUT). Use JSON string for JSON APIs.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 30).",
                    "default": 30,
                },
                "file_upload": {
                    "type": "object",
                    "description": (
                        "For multipart/form-data file upload. Provide field name, "
                        "filename, content (string), and content_type. When set, "
                        "the request is sent as multipart/form-data instead of raw body. "
                        "Example: {\"field\": \"file\", \"filename\": \"evil.xml\", "
                        "\"content\": \"<?xml ...>\", \"content_type\": \"application/xml\"}"
                    ),
                    "properties": {
                        "field": {
                            "type": "string",
                            "description": "Form field name (default: file).",
                        },
                        "filename": {
                            "type": "string",
                            "description": "Upload filename.",
                        },
                        "content": {
                            "type": "string",
                            "description": "File content as a string.",
                        },
                        "content_type": {
                            "type": "string",
                            "description": "MIME type (default: application/octet-stream).",
                        },
                    },
                    "required": ["field", "filename", "content"],
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "save_deliverable",
        "description": (
            "Save content to a named deliverable file in the deliverables/ "
            "directory. Returns the absolute path of the saved file."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": (
                        "Filename for the deliverable "
                        "(e.g. 'recon_report.md', 'findings_injection.md')."
                    ),
                },
                "content": {
                    "type": "string",
                    "description": "The full content to write to the deliverable file.",
                },
            },
            "required": ["name", "content"],
        },
    },
    # -- Playwright browser tools -------------------------------------------
    {
        "name": "browser_navigate",
        "description": (
            "Navigate the headless browser to a URL. Returns the page title, "
            "current URL, and any JavaScript dialogs (alert/confirm/prompt) "
            "that fired during navigation — critical for XSS proof. "
            "Dialogs are automatically captured and returned in the 'dialogs' "
            "array. Use 'load' wait_until for SPAs (default)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to navigate to.",
                },
                "wait_until": {
                    "type": "string",
                    "description": (
                        "When to consider navigation complete. Use 'load' (default) "
                        "for SPAs like Juice Shop — 'networkidle' will hang due to "
                        "persistent WebSocket connections."
                    ),
                    "enum": ["load", "domcontentloaded", "networkidle", "commit"],
                    "default": "load",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "browser_click",
        "description": (
            "Click an element on the page by CSS selector or text selector "
            "(e.g. 'text=Submit'). Returns success/failure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {
                    "type": "string",
                    "description": "CSS selector or Playwright text selector (e.g. 'text=Login').",
                },
            },
            "required": ["selector"],
        },
    },
    {
        "name": "browser_type",
        "description": (
            "Type text into an input field identified by CSS selector. "
            "Clears the field first, then types the given text."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {
                    "type": "string",
                    "description": "CSS selector for the input field.",
                },
                "text": {
                    "type": "string",
                    "description": "The text to type into the field.",
                },
            },
            "required": ["selector", "text"],
        },
    },
    {
        "name": "browser_screenshot",
        "description": (
            "Capture a full-page screenshot. Saves the PNG to "
            "deliverables/evidence/<name>.png and returns the file path "
            "and a base64-encoded preview. Use for exploitation evidence."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Filename for the screenshot (e.g. 'xss-search-dom.png'). Auto-generated if omitted.",
                },
                "full_page": {
                    "type": "boolean",
                    "description": "Capture the full scrollable page (default: true).",
                    "default": True,
                },
            },
        },
    },
    {
        "name": "browser_evaluate",
        "description": (
            "Execute a JavaScript expression in the page context and return "
            "the result. Use for DOM inspection, e.g. "
            "document.querySelectorAll('iframe').length."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "JavaScript expression to evaluate in the page.",
                },
            },
            "required": ["expression"],
        },
    },
    {
        "name": "browser_network_requests",
        "description": (
            "List captured network request/response pairs since the last "
            "browser_navigate call. Returns URL, status, method, and headers "
            "for each request."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "browser_set_auth",
        "description": (
            "Inject an Authorization JWT token into the browser context. "
            "All subsequent browser_navigate calls will include this token. "
            "Also sets the token in localStorage so Angular SPAs pick it up. "
            "Use this AFTER obtaining a JWT via http_request login."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "JWT token (without 'Bearer ' prefix).",
                },
            },
            "required": ["token"],
        },
    },
    # -- Artifact Store tools (cross-agent sharing) -------------------------
    {
        "name": "store_artifact",
        "description": (
            "Store a named artifact (JWT token, extracted data, credentials, etc.) "
            "so that OTHER parallel exploit agents can retrieve it. Use this to "
            "share JWTs, cookies, user IDs, and any data needed across phases. "
            "Example keys: 'admin_jwt', 'jim_jwt', 'bender_jwt', 'user_ids'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Artifact name (e.g. 'admin_jwt', 'jim_jwt', 'extracted_hashes').",
                },
                "value": {
                    "type": "string",
                    "description": "Artifact value (JWT string, JSON blob, etc.).",
                },
            },
            "required": ["key", "value"],
        },
    },
    {
        "name": "get_artifact",
        "description": (
            "Retrieve a previously stored artifact by name. Returns the value "
            "if found, or null if no artifact with that key exists. Also supports "
            "key='*' to list all available artifact keys. Use this to retrieve "
            "JWTs stored by other agents (e.g. auth agent stores admin JWT, "
            "authz agent retrieves it)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Artifact name to retrieve, or '*' to list all keys.",
                },
            },
            "required": ["key"],
        },
    },
    {
        "name": "check_challenge_status",
        "description": (
            "Check the Juice Shop scoreboard to see which challenges are solved. "
            "Call this AFTER each exploit attempt to verify the challenge was "
            "actually completed. Returns solved/unsolved status. Optionally filter "
            "by challenge name substring."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Juice Shop base URL (e.g. http://host:3000).",
                },
                "challenge_name": {
                    "type": "string",
                    "description": (
                        "Optional: substring to filter challenges by name "
                        "(e.g. 'XSS', 'Login', 'Admin'). Omit to get full summary."
                    ),
                },
            },
            "required": ["target_url"],
        },
    },
]


# ---------------------------------------------------------------------------
# Tool Dispatcher
# ---------------------------------------------------------------------------

class SkillToolDispatcher:
    """Routes MCP tool_use calls to the appropriate skill wrapper.

    Usage::

        registry = SkillRegistry()
        dispatcher = SkillToolDispatcher(registry)

        # When the agent returns a tool_use block:
        result = dispatcher.dispatch("vulnerability_lookup_cve",
                                     {"product": "express", "version": "4.17.1"})
    """

    def __init__(
        self,
        registry: SkillRegistry,
        use_playwright: bool = True,
        artifact_store: ArtifactStore | None = None,
    ):
        self.registry = registry
        self._artifact_store = artifact_store or ArtifactStore()
        self._handlers: dict[str, Callable[..., dict[str, Any]]] = {
            "network_recon_parse_nmap": self._handle_parse_nmap,
            "network_recon_run_nmap": self._handle_run_nmap,
            "network_recon_run_whatweb": self._handle_run_whatweb,
            "sql_injection_run_sqlmap": self._handle_run_sqlmap,
            "http_request": self._handle_http_request,
            "response_analysis_validate": self._handle_validate,
            "vulnerability_lookup_cve": self._handle_lookup_cve,
            "save_deliverable": self._handle_save_deliverable,
        }
        if use_playwright:
            self._handlers.update({
                "browser_navigate": self._handle_browser_navigate,
                "browser_click": self._handle_browser_click,
                "browser_type": self._handle_browser_type,
                "browser_screenshot": self._handle_browser_screenshot,
                "browser_evaluate": self._handle_browser_evaluate,
                "browser_network_requests": self._handle_browser_network_requests,
                "browser_set_auth": self._handle_browser_set_auth,
            })
        # Artifact store tools are always available
        self._handlers["store_artifact"] = self._handle_store_artifact
        self._handlers["get_artifact"] = self._handle_get_artifact
        # Challenge verification tool
        self._handlers["check_challenge_status"] = self._handle_check_challenge_status

    @property
    def tool_names(self) -> list[str]:
        """Return all registered tool names."""
        return list(self._handlers.keys())

    def dispatch(self, tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call and return the result as a JSON-serialisable dict.

        Raises:
            KeyError: If ``tool_name`` is not a recognised tool.
        """
        handler = self._handlers.get(tool_name)
        if handler is None:
            raise KeyError(
                f"Unknown tool: {tool_name!r}. Available: {self.tool_names}"
            )
        logger.info("Dispatching tool: %s(%s)", tool_name, list(tool_input.keys()))
        try:
            return handler(**tool_input)
        except Exception as e:
            logger.error("Tool %s raised: %s", tool_name, e)
            return {"error": str(e), "success": False}

    # -- individual handlers ------------------------------------------------

    def _handle_parse_nmap(
        self,
        xml_path: str,
        output_path: str | None = None,
        markdown: bool = True,
    ) -> dict[str, Any]:
        result = parse_nmap(
            self.registry,
            xml_path=xml_path,
            output_path=output_path,
            markdown=markdown,
        )
        return self._skill_result_to_dict(result)

    def _handle_validate(
        self,
        deliverable_path: str,
        schema_type: str,
    ) -> dict[str, Any]:
        result = validate_deliverable(
            self.registry,
            deliverable_path=deliverable_path,
            schema_type=schema_type,
        )
        return self._skill_result_to_dict(result)

    def _handle_lookup_cve(
        self,
        product: str = "",
        version: str = "",
        cwe: str = "",
        keyword: str = "",
        severity: str = "",
    ) -> dict[str, Any]:
        result = lookup_cve(
            self.registry,
            product=product,
            version=version,
            cwe=cwe,
            keyword=keyword,
            severity=severity,
        )
        return self._skill_result_to_dict(result)

    def _handle_run_nmap(
        self,
        target: str,
        profile: str = "web-focused",
        ports: str | None = None,
        timeout: int = 180,
    ) -> dict[str, Any]:
        result = run_nmap(
            self.registry,
            target=target,
            profile=profile,
            ports=ports,
            timeout=timeout,
        )
        return self._skill_result_to_dict(result)

    def _handle_run_whatweb(
        self,
        target_url: str,
        aggression: int = 3,
    ) -> dict[str, Any]:
        result = run_whatweb(
            self.registry,
            target_url=target_url,
            aggression=aggression,
        )
        return self._skill_result_to_dict(result)

    def _handle_run_sqlmap(
        self,
        target_url: str,
        param: str,
        method: str | None = None,
        data: str | None = None,
        headers: str | None = None,
        dbms: str = "sqlite",
        level: int = 3,
        risk: int = 2,
        technique: str = "BEUST",
        tamper: str | None = None,
        dump_tables: bool = False,
    ) -> dict[str, Any]:
        result = run_sqlmap(
            self.registry,
            target_url=target_url,
            param=param,
            method=method,
            data=data,
            headers=headers,
            dbms=dbms,
            level=level,
            risk=risk,
            technique=technique,
            tamper=tamper,
            dump_tables=dump_tables,
        )
        return self._skill_result_to_dict(result)

    def _handle_http_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: int = 30,
        file_upload: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        result = run_http_request(
            url=url,
            method=method,
            headers=headers,
            body=body,
            timeout=timeout,
            file_upload=file_upload,
        )
        return self._skill_result_to_dict(result)

    def _handle_save_deliverable(
        self,
        name: str,
        content: str,
    ) -> dict[str, Any]:
        path = save_deliverable(name, content)
        return {
            "success": True,
            "path": str(path),
            "message": f"Saved deliverable: {name}",
        }

    # -- Playwright browser handlers ----------------------------------------

    def _handle_browser_navigate(self, **kwargs) -> dict[str, Any]:
        return handle_browser_navigate(**kwargs)

    def _handle_browser_click(self, **kwargs) -> dict[str, Any]:
        return handle_browser_click(**kwargs)

    def _handle_browser_type(self, **kwargs) -> dict[str, Any]:
        return handle_browser_type(**kwargs)

    def _handle_browser_screenshot(self, **kwargs) -> dict[str, Any]:
        return handle_browser_screenshot(**kwargs)

    def _handle_browser_evaluate(self, **kwargs) -> dict[str, Any]:
        return handle_browser_evaluate(**kwargs)

    def _handle_browser_network_requests(self, **kwargs) -> dict[str, Any]:
        return handle_browser_network_requests(**kwargs)

    def _handle_browser_set_auth(self, **kwargs) -> dict[str, Any]:
        return handle_browser_set_auth(**kwargs)

    # -- Artifact Store handlers ------------------------------------------ #

    def _handle_store_artifact(self, key: str, value: str, **kwargs: Any) -> dict[str, Any]:
        """Store an artifact for cross-agent sharing."""
        self._artifact_store.put(key, value)
        return {
            "success": True,
            "message": f"Artifact '{key}' stored ({len(value)} chars). "
                       f"Other agents can retrieve it with get_artifact.",
            "keys": self._artifact_store.keys(),
        }

    def _handle_get_artifact(self, key: str, **kwargs: Any) -> dict[str, Any]:
        """Retrieve a stored artifact by key, or list all keys with '*'."""
        if key == "*":
            all_keys = self._artifact_store.keys()
            return {
                "success": True,
                "keys": all_keys,
                "count": len(all_keys),
            }
        value = self._artifact_store.get(key)
        if value is None:
            return {
                "success": False,
                "error": f"No artifact found with key '{key}'.",
                "available_keys": self._artifact_store.keys(),
            }
        return {
            "success": True,
            "key": key,
            "value": value,
        }

    def _handle_check_challenge_status(
        self,
        target_url: str,
        challenge_name: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Query /api/Challenges to see solved status."""
        import json as _json

        result = run_http_request(
            url=f"{target_url.rstrip('/')}/api/Challenges/",
            method="GET",
            timeout=10,
        )
        if not result.success:
            return {"success": False, "error": result.errors}

        try:
            body = result.output.get("body", "") if isinstance(result.output, dict) else str(result.output)
            data = _json.loads(body) if isinstance(body, str) else body
            challenges = data.get("data", [])

            if challenge_name:
                matches = [
                    c for c in challenges
                    if challenge_name.lower() in c.get("name", "").lower()
                    or challenge_name.lower() in c.get("category", "").lower()
                ]
                return {
                    "success": True,
                    "filter": challenge_name,
                    "matches": [
                        {
                            "name": c["name"],
                            "solved": c.get("solved", False),
                            "difficulty": c.get("difficulty"),
                            "category": c.get("category", ""),
                        }
                        for c in matches
                    ],
                    "matched_count": len(matches),
                }

            solved = [c for c in challenges if c.get("solved")]
            unsolved = [c for c in challenges if not c.get("solved")]
            return {
                "success": True,
                "total_challenges": len(challenges),
                "solved_count": len(solved),
                "unsolved_count": len(unsolved),
                "solved": [
                    {"name": c["name"], "difficulty": c.get("difficulty")}
                    for c in solved
                ],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def _skill_result_to_dict(result: SkillResult) -> dict[str, Any]:
        """Convert a SkillResult to a plain dict for JSON serialisation."""
        return {
            "success": result.success,
            "skill_name": result.skill_name,
            "output": result.output,
            "exit_code": result.exit_code,
            "errors": result.errors,
        }


# ---------------------------------------------------------------------------
# System Prompt Builder
# ---------------------------------------------------------------------------

def build_system_prompt_skills_section(registry: SkillRegistry) -> str:
    """Generate the skills section for injection into an agent's system prompt.

    This teaches the agent:
    1. What tools are available (names, descriptions, parameters)
    2. When to use each tool
    3. Expected output formats

    Returns a markdown-formatted string suitable for concatenation into a
    system prompt.
    """
    lines = [
        "# SPAIDER Skill Tools",
        "",
        "You have access to the following cybersecurity skill tools. "
        "Use them to gather data, validate outputs, and look up vulnerabilities.",
        "",
    ]

    for tool_def in MCP_TOOLS:
        name = tool_def["name"]
        desc = tool_def["description"]
        schema = tool_def["input_schema"]
        props = schema.get("properties", {})
        required = schema.get("required", [])

        lines.append(f"## `{name}`")
        lines.append(f"{desc}")
        lines.append("")
        lines.append("**Parameters:**")

        for param_name, param_schema in props.items():
            req_marker = " *(required)*" if param_name in required else ""
            param_desc = param_schema.get("description", "")
            param_type = param_schema.get("type", "string")
            lines.append(f"- `{param_name}` ({param_type}){req_marker}: {param_desc}")

        lines.append("")

    # Add workflow context from skills
    lines.append("# Skill Workflow Context")
    lines.append("")
    lines.append(registry.build_all_skills_summary())

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Convenience bootstrap
# ---------------------------------------------------------------------------

@dataclass
class AgenticLoopConfig:
    """Configuration for the agentic loop setup."""
    skills_dir: Path | None = None
    deliverables_dir: Path = DELIVERABLES_DIR
    verbose: bool = False
    use_playwright: bool = True
    max_browser_calls: int = 80
    artifact_store: ArtifactStore | None = None


_BROWSER_TOOL_NAMES = frozenset({
    "browser_navigate",
    "browser_click",
    "browser_type",
    "browser_screenshot",
    "browser_evaluate",
    "browser_network_requests",
    "browser_set_auth",
})


def setup_agentic_loop(
    config: AgenticLoopConfig | None = None,
) -> tuple[SkillRegistry, SkillToolDispatcher, list[dict[str, Any]], str]:
    """Bootstrap the agentic loop: load skills, build dispatcher, and generate prompt.

    Returns:
        A tuple of:
        - registry: The loaded SkillRegistry
        - dispatcher: The SkillToolDispatcher for handling tool calls
        - tools: The MCP tool definition list
        - system_prompt_section: The skills section for the system prompt

    Usage::

        registry, dispatcher, tools, skills_prompt = setup_agentic_loop()

        # Pass ``tools`` to your LLM API call
        # Prepend ``skills_prompt`` to your system prompt
        # Use ``dispatcher.dispatch(name, input)`` to handle tool_use blocks
    """
    if config is None:
        config = AgenticLoopConfig()

    registry = SkillRegistry(config.skills_dir)

    if not registry.skill_names:
        logger.warning("No skills found! Run 'python -m src skills --setup' first.")

    use_pw = config.use_playwright
    dispatcher = SkillToolDispatcher(
        registry,
        use_playwright=use_pw,
        artifact_store=config.artifact_store,
    )

    # Configure Playwright budget
    if use_pw:
        PlaywrightManager.set_max_calls(config.max_browser_calls)

    # Filter out browser tools when Playwright is disabled
    if use_pw:
        tools = list(MCP_TOOLS)
    else:
        tools = [t for t in MCP_TOOLS if t["name"] not in _BROWSER_TOOL_NAMES]

    system_prompt_section = build_system_prompt_skills_section(registry)

    logger.info(
        "Agentic loop ready — %d skills, %d tools (playwright=%s)",
        len(registry.skill_names),
        len(tools),
        use_pw,
    )

    return registry, dispatcher, tools, system_prompt_section
