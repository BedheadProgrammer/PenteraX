"""SPAIDER Agent pipeline — orchestrates skills across pentesting phases.

Implements the sequential phase pipeline described in the project roadmap:

    Phase 0 (Recon)  →  Phase 1 (Analysis)  →  Phase 2 (Exploit)  →  Phase 3 (Report)

Each phase:
1. Loads the relevant prompt template
2. Injects skill outputs as template variables
3. Runs the agent (or simulates for testing)
4. Validates the deliverable via ResponseAnalysisSkill
5. Retries on validation failure (up to 3×)
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .exceptions import PipelineAbortedError
from .precollect import run_precollection
from .skills.skill_loader import SkillRegistry, SkillResult, PROJECT_ROOT
from .skills.skill_wrappers import (
    parse_nmap,
    validate_deliverable,
    validate_with_retry_context,
    lookup_cve,
    batch_lookup_cve,
    format_known_vulns_for_prompt,
    nmap_to_markdown,
)

logger = logging.getLogger("spaider.pipeline")

DELIVERABLES_DIR = PROJECT_ROOT / "deliverables"
PROMPTS_DIR = PROJECT_ROOT / "src" / "prompts"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class PipelineConfig:
    """Configuration for a full pipeline run."""
    target_url: str = "http://54.146.141.88:3000"
    repo_path: str = "./repos/juice-shop"
    output_dir: Path = DELIVERABLES_DIR
    max_retries: int = 3
    verbose: bool = False
    use_playwright: bool = True
    max_browser_calls: int = 50


@dataclass
class PhaseResult:
    """Result of a single pipeline phase."""
    phase_name: str
    success: bool
    deliverables: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    retries: int = 0
    errors: list[str] = field(default_factory=list)
    validation_passed: bool = False


@dataclass
class PipelineResult:
    """Result of a complete pipeline run."""
    phases: list[PhaseResult] = field(default_factory=list)
    total_duration_seconds: float = 0.0
    deliverables_generated: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Prompt template utilities
# ---------------------------------------------------------------------------

def load_prompt(template_path: Path, variables: dict[str, str]) -> str:
    """Load a prompt template and substitute ``{{VAR}}`` placeholders."""
    if not template_path.exists():
        logger.warning("Prompt template not found: %s", template_path)
        return ""

    text = template_path.read_text(encoding="utf-8")
    for key, value in variables.items():
        text = text.replace(f"{{{{{key}}}}}", value)
    return text


def ensure_dir(path: Path) -> Path:
    """Create a directory if it doesn't exist, return the path."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_deliverable(name: str, output_dir: Path = DELIVERABLES_DIR) -> str:
    """Read a deliverable file by name."""
    path = output_dir / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def save_deliverable(name: str, content: str, output_dir: Path = DELIVERABLES_DIR) -> Path:
    """Write a deliverable file atomically.

    Uses write-to-temp + ``os.replace()`` so a crash mid-write never
    leaves a half-written deliverable on disk.  On Windows,
    ``os.replace()`` may raise ``PermissionError`` if another process
    has the file open — we retry up to 3 times with short back-off
    (Race condition #9 / #14).
    """
    ensure_dir(output_dir)
    path = output_dir / name
    fd, tmp_path = tempfile.mkstemp(dir=str(output_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        # Atomic replace — retry on Windows PermissionError
        for attempt in range(3):
            try:
                os.replace(tmp_path, str(path))
                break
            except PermissionError:
                if attempt == 2:
                    raise
                time.sleep(0.1 * (attempt + 1))
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
    logger.info("Saved deliverable: %s", path)
    return path


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_phase_output(
    registry: SkillRegistry,
    deliverable_path: Path,
    schema_type: str,
    max_retries: int = 3,
    retry_callback: Callable[[str], str] | None = None,
    stop_event: threading.Event | None = None,
) -> tuple[bool, list[str]]:
    """Validate a deliverable and optionally retry the producing agent.

    Args:
        registry: SkillRegistry instance.
        deliverable_path: Path to the deliverable to validate.
        schema_type: Schema type for validation.
        max_retries: Maximum retry attempts.
        retry_callback: If provided, called with the retry-context string;
                        should return the new deliverable content.
        stop_event: If set, abort retries early (Phase 4 — Step 4.7).

    Returns:
        (passed: bool, errors: list[str])
    """
    for attempt in range(1, max_retries + 1):
        # Check for abort before each retry (Race condition #15)
        _check_stop(stop_event)

        result = validate_deliverable(registry, deliverable_path, schema_type)

        if result.success:
            logger.info("Validation passed for %s (attempt %d)", deliverable_path.name, attempt)
            return True, []

        errors = []
        if isinstance(result.output, dict):
            errors = result.output.get("errors", [])
        logger.warning("Validation failed for %s (attempt %d): %s",
                       deliverable_path.name, attempt, errors)

        retry_ctx = validate_with_retry_context(result, attempt, max_retries)
        if retry_ctx and retry_callback and attempt < max_retries:
            new_content = retry_callback(retry_ctx)
            deliverable_path.write_text(new_content, encoding="utf-8")
        else:
            return False, errors

    return False, ["Max retries exhausted"]


# ---------------------------------------------------------------------------
# Phase implementations
# ---------------------------------------------------------------------------

def _extract_tech_stack_from_recon(recon_data: str) -> list[dict[str, str]]:
    """Parse Technology Stack section from recon_report.md.

    Looks for a ``## Technology Stack`` section and extracts product/version
    pairs from markdown table rows or ``product version`` lines.
    Falls back to hardcoded Juice Shop defaults if parsing fails.
    """
    FALLBACK: list[dict[str, str]] = [
        {"product": "express", "version": "4.17.1"},
        {"product": "angular", "version": "1.6.0"},
        {"product": "jsonwebtoken", "version": "8.5.1"},
        {"product": "sequelize", "version": "5.22.5"},
    ]

    # Try to find a technology stack section
    section_match = re.search(
        r"##\s*Technology\s+Stack\b(.*?)(?=\n##\s|\Z)",
        recon_data,
        re.DOTALL | re.IGNORECASE,
    )
    if not section_match:
        logger.debug("No Technology Stack section found — using fallback tech stack")
        return FALLBACK

    section = section_match.group(1)
    parsed: list[dict[str, str]] = []

    # Try markdown table rows: | product | version | ...
    for row in re.finditer(
        r"\|\s*([\w.@/-]+)\s*\|\s*([\d][\d.]*\S*)\s*\|", section
    ):
        product, version = row.group(1).strip(), row.group(2).strip()
        if product.lower() not in ("product", "name", "component", "---", "---"):
            parsed.append({"product": product, "version": version})

    # Try bullet / plain lines: - express 4.17.1 or express: 4.17.1
    if not parsed:
        for line in re.finditer(
            r"[-*]?\s*([\w.@/-]+)[:\s]+([\d][\d.]*\S*)", section
        ):
            product, version = line.group(1).strip(), line.group(2).strip()
            if product.lower() not in ("version",):
                parsed.append({"product": product, "version": version})

    if parsed:
        logger.info("Extracted %d tech-stack entries from recon data", len(parsed))
        return parsed

    logger.debug("Could not parse tech stack entries — using fallback")
    return FALLBACK


def _check_stop(stop_event: threading.Event | None) -> None:
    """Raise ``PipelineAbortedError`` if the user requested a stop."""
    if stop_event is not None and stop_event.is_set():
        raise PipelineAbortedError("Pipeline aborted by user.")


def _assemble_fallback_recon_report(
    precollect_vars: dict[str, str],
    target_url: str,
) -> str:
    """Build a minimal ``recon_report.md`` from pre-collected data.

    When no ``agent_runner`` is available the pipeline still needs a
    deliverable on disk so downstream phases (analysis → exploit → report)
    can operate on *something*.  This function reformats the raw
    pre-collection outputs into the sections the validation schema expects:

        ## Technology Stack,  ## Endpoints,  ## Identified Sinks,  ## Network Scan
    """
    source = precollect_vars.get("SOURCE_ANALYSIS", "")
    nmap = precollect_vars.get("NMAP_RESULTS", "")
    http_probes = precollect_vars.get("HTTP_PROBE_RESULTS", "")

    parts: list[str] = [f"# Reconnaissance Report\n\n**Target:** {target_url}\n"]

    # ── Technology Stack ─────────────────────────────────────────────
    # Try to extract from pre-collected source analysis
    if "Task 1.5" in source and "package.json" in source.lower():
        # Extract the relevant subsection from source analysis
        parts.append("## Technology Stack\n")
        parts.append("_(Auto-extracted from pre-collection source analysis)_\n")
        # Find the Task 1.5 section
        idx = source.find("### Task 1.5")
        if idx >= 0:
            # Find next ### or end
            end_idx = source.find("###", idx + 10)
            snippet = source[idx:end_idx] if end_idx > 0 else source[idx:]
            parts.append(snippet.strip())
        parts.append("")
    else:
        parts.append("## Technology Stack\n")
        parts.append("| Component | Product | Version |")
        parts.append("|-----------|---------|---------|")
        parts.append("| Backend | Express | unknown |")
        parts.append("| Database | SQLite3 | unknown |")
        parts.append("")

    # ── Endpoints ────────────────────────────────────────────────────
    parts.append("## Endpoints\n")
    if http_probes and "|" in http_probes:
        parts.append("_(Auto-extracted from HTTP endpoint probes)_\n")
        # Extract the table from HTTP probes
        for line in http_probes.splitlines():
            if line.startswith("|"):
                parts.append(line)
        parts.append("")
    elif "Task 1.1" in source:
        parts.append("_(Auto-extracted from source code route analysis)_\n")
        idx = source.find("### Task 1.1")
        if idx >= 0:
            end_idx = source.find("### Task 1.2", idx + 10)
            snippet = source[idx:end_idx] if end_idx > 0 else source[idx:]
            parts.append(snippet.strip())
        parts.append("")
    else:
        parts.append("| Route | Method | Parameters | Source File |")
        parts.append("|-------|--------|------------|-------------|")
        parts.append("| (no endpoints discovered) | - | - | - |")
        parts.append("")

    # ── Identified Sinks ─────────────────────────────────────────────
    parts.append("## Identified Sinks\n")
    if "Task 1.2" in source:
        idx = source.find("### Task 1.2")
        if idx >= 0:
            end_idx = source.find("### Task 1.3", idx + 10)
            snippet = source[idx:end_idx] if end_idx > 0 else source[idx:]
            parts.append(snippet.strip())
    else:
        parts.append("_(No sinks identified during pre-collection)_")
    parts.append("")

    # ── Network Scan ─────────────────────────────────────────────────
    parts.append("## Network Scan\n")
    if nmap and "|" in nmap:
        for line in nmap.splitlines():
            if line.startswith("|") or line.startswith("**"):
                parts.append(line)
    else:
        parts.append("_(Network scan unavailable — nmap skipped or timed out)_")
    parts.append("")

    return "\n".join(parts)


def run_phase_recon(
    registry: SkillRegistry,
    config: PipelineConfig,
    agent_runner: Callable[..., str] | None = None,
    stop_event: threading.Event | None = None,
) -> PhaseResult:
    """Phase 0: Reconnaissance.

    - **Pre-collects** source analysis, nmap scan, HTTP probes (hybrid design)
    - Runs vulnerability lookup on discovered tech stack
    - Produces ``recon_report.md``

    The hybrid pre-collection approach (DESIGN_REVIEW §4) injects real,
    deterministic data into the prompt so the agent reasons over ground-truth
    rather than hallucinating recon results.  Pre-collection runs sequentially
    within this function — no new threads or shared state are created.
    """
    start = time.time()
    phase = PhaseResult(phase_name="recon", success=False)

    ensure_dir(config.output_dir)
    _check_stop(stop_event)

    # ── Hybrid pre-collection (DESIGN_REVIEW §4) ─────────────────────
    # Runs source analysis, nmap, and HTTP probing BEFORE the agent.
    # Each step checks stop_event and degrades gracefully on failure.
    # When no agent_runner is provided (test / validation mode), skip
    # expensive network operations (nmap, HTTP probes) since no LLM
    # will consume them — this avoids the 180s nmap timeout in tests.
    precollect_vars = run_precollection(
        target_url=config.target_url,
        repo_path=config.repo_path,
        stop_event=stop_event,
        skip_network=agent_runner is None,
    )

    # Build prompt variables
    prompt_vars = {
        "TARGET_URL": config.target_url,
        "REPO_PATH": config.repo_path,
        # Inject pre-collected data as template variables
        **precollect_vars,
    }

    # Inject skill workflow instructions into variables
    recon_skill_ctx = registry.build_prompt_context("network-recon")
    prompt_vars["NETWORK_RECON_SKILL"] = recon_skill_ctx

    vuln_skill_ctx = registry.build_prompt_context("vulnerability-lookup")
    prompt_vars["VULN_LOOKUP_SKILL"] = vuln_skill_ctx

    # Load prompt template
    prompt_text = load_prompt(PROMPTS_DIR / "recon.md", prompt_vars)

    # Execute agent (or use the callback)
    if agent_runner:
        try:
            output = agent_runner(prompt_text, "recon")
            # Only save agent text output if the deliverable wasn't already
            # saved via the save_deliverable tool during the agentic loop.
            # If the agent used the tool, the file on disk is likely better
            # than the agent's final conversational text response.
            recon_already_saved = (config.output_dir / "recon_report.md").exists()
            if recon_already_saved:
                existing = (config.output_dir / "recon_report.md").read_text(encoding="utf-8")
                # Prefer the longer version (tool-saved structured report vs brief text)
                if len(output.strip()) > len(existing.strip()):
                    save_deliverable("recon_report.md", output, config.output_dir)
                else:
                    logger.info("Keeping tool-saved recon_report.md (%d chars > agent text %d chars)",
                                len(existing), len(output))
            elif output.strip():
                save_deliverable("recon_report.md", output, config.output_dir)
            else:
                logger.warning(
                    "Agent returned empty output for recon_report.md — skipping save"
                )
            # Only count as delivered if file exists and is non-empty
            recon_path_check = config.output_dir / "recon_report.md"
            if recon_path_check.exists() and recon_path_check.stat().st_size > 0:
                phase.deliverables.append("recon_report.md")
        except Exception as e:
            phase.errors.append(f"Agent execution failed: {e}")
            phase.duration_seconds = time.time() - start
            return phase
    else:
        logger.info("No agent_runner provided — saving pre-collected data as recon deliverable")
        # Assemble pre-collected data into a minimal recon report so that
        # downstream phases (analysis, exploit, report) have data to work
        # with even when no LLM agent is available.
        fallback_report = _assemble_fallback_recon_report(
            precollect_vars, config.target_url
        )
        save_deliverable("recon_report.md", fallback_report, config.output_dir)
        phase.deliverables.append("recon_report.md")

    # Validate if deliverable exists
    recon_path = config.output_dir / "recon_report.md"
    if recon_path.exists():
        passed, errors = validate_phase_output(
            registry, recon_path, "recon_report", config.max_retries,
            stop_event=stop_event,
        )
        phase.validation_passed = passed
        if not passed:
            phase.errors.extend(errors)
        phase.success = True
        if "recon_report.md" not in phase.deliverables:
            phase.deliverables.append("recon_report.md")
    else:
        phase.errors.append("recon_report.md was not generated")

    phase.duration_seconds = time.time() - start
    return phase


def _run_single_analysis(
    analysis_type: str,
    template: str,
    deliverable_name: str,
    schema: str,
    registry: SkillRegistry,
    config: PipelineConfig,
    prompt_vars_base: dict[str, str],
    agent_runner: Callable[..., str] | None,
    stop_event: threading.Event | None,
) -> tuple[str, str | None, list[str]]:
    """Run a single analysis sub-phase (injection or XSS).

    Returns ``(deliverable_name | "", error_msg | None, validation_errors)``.
    Designed to run inside a ``ThreadPoolExecutor``.
    """
    _check_stop(stop_event)
    prompt_vars = {**prompt_vars_base}
    prompt_text = load_prompt(PROMPTS_DIR / template, prompt_vars)

    delivered = ""
    validation_errors: list[str] = []

    if agent_runner:
        try:
            output = agent_runner(prompt_text, f"analysis-{analysis_type}")
            # Only overwrite if the agent's text is longer than what the
            # save_deliverable tool already wrote during the agentic loop.
            already_saved = (config.output_dir / deliverable_name).exists()
            if already_saved:
                existing = (config.output_dir / deliverable_name).read_text(encoding="utf-8")
                if len(output.strip()) > len(existing.strip()):
                    save_deliverable(deliverable_name, output, config.output_dir)
                else:
                    logger.info("Keeping tool-saved %s (%d chars > agent text %d chars)",
                                deliverable_name, len(existing), len(output))
            elif output.strip():
                save_deliverable(deliverable_name, output, config.output_dir)
            else:
                logger.warning(
                    "Agent returned empty output for %s — skipping save",
                    deliverable_name,
                )
            # Only count as delivered if file exists and is non-empty
            path_check = config.output_dir / deliverable_name
            if path_check.exists() and path_check.stat().st_size > 0:
                delivered = deliverable_name
        except Exception as e:
            return "", f"Analysis-{analysis_type} agent failed: {e}", []

    # Validate
    path = config.output_dir / deliverable_name
    if path.exists():
        passed, errors = validate_phase_output(
            registry, path, schema, config.max_retries,
            stop_event=stop_event,
        )
        if not passed:
            validation_errors.extend(errors)
        if not delivered:
            delivered = deliverable_name

    return delivered, None, validation_errors


def run_phase_analysis(
    registry: SkillRegistry,
    config: PipelineConfig,
    agent_runner: Callable[..., str] | None = None,
    stop_event: threading.Event | None = None,
) -> PhaseResult:
    """Phase 1: Analysis (injection + XSS + auth + authz + ssrf).

    - Reads recon_report.md
    - Runs vulnerability lookups to enrich with CVE data
    - Produces hypotheses_injection.md, hypotheses_xss.md, hypotheses_auth.md, hypotheses_authz.md, and hypotheses_ssrf.md

    Injection, XSS, auth, authz, and ssrf analyses run **in parallel** via ThreadPoolExecutor
    (Phase 4 — Step 4.1).  Each sub-phase writes to a distinct deliverable
    file so there is no file contention (Race condition #5).
    """
    start = time.time()
    phase = PhaseResult(phase_name="analysis", success=False)

    _check_stop(stop_event)

    recon_data = read_deliverable("recon_report.md", config.output_dir)
    if not recon_data:
        phase.errors.append("recon_report.md not available — skipping analysis")
        phase.duration_seconds = time.time() - start
        return phase

    # Enrich with vulnerability lookups
    known_vulns = ""
    try:
        tech_stack = _extract_tech_stack_from_recon(recon_data)
        batch_result = batch_lookup_cve(registry, tech_stack)
        if batch_result.success and isinstance(batch_result.output, list):
            known_vulns = format_known_vulns_for_prompt(batch_result.output)
    except Exception as e:
        logger.warning("CVE batch lookup failed (non-fatal): %s", e)
        known_vulns = "CVE lookup unavailable."

    prompt_vars_base = {
        "RECON_DATA": recon_data,
        "KNOWN_VULNS": known_vulns,
        "TARGET_URL": config.target_url,
    }

    # Run injection + XSS + auth + authz + ssrf analysis in parallel
    sub_phases = [
        ("injection", "analysis-injection.md", "hypotheses_injection.md", "hypotheses"),
        ("xss", "analysis-xss.md", "hypotheses_xss.md", "hypotheses"),
        ("auth", "analysis-auth.md", "hypotheses_auth.md", "hypotheses"),
        ("authz", "analysis-authz.md", "hypotheses_authz.md", "hypotheses"),
        ("ssrf", "analysis-ssrf.md", "hypotheses_ssrf.md", "hypotheses"),
    ]

    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="analysis") as pool:
        futures = {
            pool.submit(
                _run_single_analysis,
                a_type, tmpl, deliv, sch,
                registry, config, prompt_vars_base, agent_runner, stop_event,
            ): a_type
            for a_type, tmpl, deliv, sch in sub_phases
        }

        for future in as_completed(futures):
            a_type = futures[future]
            try:
                delivered, error_msg, val_errors = future.result()
            except Exception as exc:
                phase.errors.append(f"Analysis-{a_type} crashed: {exc}")
                continue

            if error_msg:
                phase.errors.append(error_msg)
            if val_errors:
                phase.errors.extend(val_errors)
            if delivered and delivered not in phase.deliverables:
                phase.deliverables.append(delivered)
                phase.validation_passed = phase.validation_passed or (not val_errors)

    phase.success = len(phase.deliverables) > 0
    phase.duration_seconds = time.time() - start
    return phase


def _run_single_exploit(
    exploit_type: str,
    template: str,
    hyp_file: str,
    findings_file: str,
    registry: SkillRegistry,
    config: PipelineConfig,
    agent_runner: Callable[..., str] | None,
    stop_event: threading.Event | None,
) -> tuple[str, str | None, list[str]]:
    """Run a single exploit sub-phase (injection or XSS).

    Returns ``(deliverable_name | "", error_msg | None, validation_errors)``.
    Designed to run inside a ``ThreadPoolExecutor``.
    """
    _check_stop(stop_event)

    hypotheses = read_deliverable(hyp_file, config.output_dir)
    if not hypotheses:
        return "", f"{hyp_file} not available — skipping {exploit_type} exploit", []

    prompt_vars = {
        "HYPOTHESES": hypotheses,
        "TARGET_URL": config.target_url,
    }
    prompt_text = load_prompt(PROMPTS_DIR / template, prompt_vars)

    delivered = ""
    validation_errors: list[str] = []

    if agent_runner:
        try:
            output = agent_runner(prompt_text, f"exploit-{exploit_type}")
            # Only overwrite if the agent's text is longer than what the
            # save_deliverable tool already wrote during the agentic loop.
            already_saved = (config.output_dir / findings_file).exists()
            if already_saved:
                existing = (config.output_dir / findings_file).read_text(encoding="utf-8")
                if len(output.strip()) > len(existing.strip()):
                    save_deliverable(findings_file, output, config.output_dir)
                else:
                    logger.info("Keeping tool-saved %s (%d chars > agent text %d chars)",
                                findings_file, len(existing), len(output))
            elif output.strip():
                save_deliverable(findings_file, output, config.output_dir)
            else:
                logger.warning(
                    "Agent returned empty output for %s — skipping save",
                    findings_file,
                )
            # Only count as delivered if file exists and is non-empty
            path_check = config.output_dir / findings_file
            if path_check.exists() and path_check.stat().st_size > 0:
                delivered = findings_file
        except Exception as e:
            return "", f"Exploit-{exploit_type} agent failed: {e}", []

    # Validate
    path = config.output_dir / findings_file
    if path.exists():
        passed, errors = validate_phase_output(
            registry, path, "findings", config.max_retries,
            stop_event=stop_event,
        )
        if not passed:
            validation_errors.extend(errors)
        if not delivered:
            delivered = findings_file

    return delivered, None, validation_errors


def run_phase_exploit(
    registry: SkillRegistry,
    config: PipelineConfig,
    agent_runner: Callable[..., str] | None = None,
    stop_event: threading.Event | None = None,
) -> PhaseResult:
    """Phase 2: Exploitation.

    - Reads hypothesis files
    - Produces findings_injection.md, findings_xss.md, findings_auth.md, findings_authz.md, and findings_ssrf.md

    Injection, XSS, auth, authz, and ssrf exploits run **in parallel** via ThreadPoolExecutor
    (Phase 4 — Step 4.1).  Each sub-phase writes to a distinct deliverable
    file so there is no file contention (Race condition #5).
    """
    start = time.time()
    phase = PhaseResult(phase_name="exploit", success=False)
    _check_stop(stop_event)

    sub_phases = [
        ("injection", "exploit-injection.md", "hypotheses_injection.md", "findings_injection.md"),
        ("xss", "exploit-xss.md", "hypotheses_xss.md", "findings_xss.md"),
        ("auth", "exploit-auth.md", "hypotheses_auth.md", "findings_auth.md"),
        ("authz", "exploit-authz.md", "hypotheses_authz.md", "findings_authz.md"),
        ("ssrf", "exploit-ssrf.md", "hypotheses_ssrf.md", "findings_ssrf.md"),
    ]

    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="exploit") as pool:
        futures = {
            pool.submit(
                _run_single_exploit,
                e_type, tmpl, hyp, find,
                registry, config, agent_runner, stop_event,
            ): e_type
            for e_type, tmpl, hyp, find in sub_phases
        }

        for future in as_completed(futures):
            e_type = futures[future]
            try:
                delivered, error_msg, val_errors = future.result()
            except Exception as exc:
                phase.errors.append(f"Exploit-{e_type} crashed: {exc}")
                continue

            if error_msg:
                phase.errors.append(error_msg)
            if val_errors:
                phase.errors.extend(val_errors)
            if delivered and delivered not in phase.deliverables:
                phase.deliverables.append(delivered)
                phase.validation_passed = phase.validation_passed or (not val_errors)

    phase.success = len(phase.deliverables) > 0
    phase.duration_seconds = time.time() - start
    return phase


def run_phase_report(
    registry: SkillRegistry,
    config: PipelineConfig,
    agent_runner: Callable[..., str] | None = None,
    stop_event: threading.Event | None = None,
) -> PhaseResult:
    """Phase 3: Report generation.

    - Reads all findings files
    - Produces pentest_report.md
    """
    start = time.time()
    phase = PhaseResult(phase_name="report", success=False)
    _check_stop(stop_event)

    # Gather all findings
    findings_parts = []
    for name in ["findings_injection.md", "findings_xss.md", "findings_auth.md", "findings_authz.md", "findings_ssrf.md"]:
        content = read_deliverable(name, config.output_dir)
        if content:
            findings_parts.append(f"# {name}\n\n{content}")

    if not findings_parts:
        phase.errors.append("No findings files available — generating report with empty data")

    prompt_vars = {
        "FINDINGS": "\n\n---\n\n".join(findings_parts) if findings_parts else "No findings available.",
        "TARGET_URL": config.target_url,
    }
    prompt_text = load_prompt(PROMPTS_DIR / "report.md", prompt_vars)

    if agent_runner:
        try:
            output = agent_runner(prompt_text, "report")
            # Only overwrite if the agent's text is longer than what the
            # save_deliverable tool already wrote during the agentic loop.
            already_saved = (config.output_dir / "pentest_report.md").exists()
            if already_saved:
                existing = (config.output_dir / "pentest_report.md").read_text(encoding="utf-8")
                if len(output.strip()) > len(existing.strip()):
                    save_deliverable("pentest_report.md", output, config.output_dir)
                else:
                    logger.info("Keeping tool-saved pentest_report.md (%d chars > agent text %d chars)",
                                len(existing), len(output))
            elif output.strip():
                save_deliverable("pentest_report.md", output, config.output_dir)
            else:
                logger.warning(
                    "Agent returned empty output for pentest_report.md — skipping save"
                )
            # Only count as delivered if file exists and is non-empty
            report_path_check = config.output_dir / "pentest_report.md"
            if report_path_check.exists() and report_path_check.stat().st_size > 0:
                phase.deliverables.append("pentest_report.md")
        except Exception as e:
            phase.errors.append(f"Report agent failed: {e}")

    # Validate
    path = config.output_dir / "pentest_report.md"
    if path.exists():
        passed, errors = validate_phase_output(
            registry, path, "pentest_report", config.max_retries,
            stop_event=stop_event,
        )
        phase.validation_passed = passed
        if not passed:
            phase.errors.extend(errors)
        phase.success = True
        if "pentest_report.md" not in phase.deliverables:
            phase.deliverables.append("pentest_report.md")

    phase.duration_seconds = time.time() - start
    return phase


# ---------------------------------------------------------------------------
# Replay mode helpers
# ---------------------------------------------------------------------------

REPLAY_DIR = DELIVERABLES_DIR / "replay"

# The deliverable files produced by a full pipeline run
_REPLAY_FILES = [
    "recon_report.md",
    "hypotheses_injection.md",
    "hypotheses_xss.md",
    "hypotheses_auth.md",
    "hypotheses_authz.md",
    "hypotheses_ssrf.md",
    "findings_injection.md",
    "findings_xss.md",
    "findings_auth.md",
    "findings_authz.md",
    "findings_ssrf.md",
    "pentest_report.md",
]


def save_replay_snapshot(output_dir: Path = DELIVERABLES_DIR) -> list[str]:
    """Copy current deliverables into ``deliverables/replay/`` as a backup.

    Returns the list of files successfully copied.
    """
    ensure_dir(REPLAY_DIR)
    copied: list[str] = []
    for name in _REPLAY_FILES:
        src = output_dir / name
        if src.exists():
            dst = REPLAY_DIR / name
            shutil.copy2(str(src), str(dst))
            copied.append(name)
            logger.info("Replay snapshot: %s → %s", src, dst)
    return copied


def load_replay_deliverables(output_dir: Path = DELIVERABLES_DIR) -> list[str]:
    """Copy pre-recorded deliverables from ``deliverables/replay/`` into *output_dir*.

    Returns the list of files successfully restored.  Files that do not exist
    in the replay directory are silently skipped.
    """
    ensure_dir(output_dir)
    restored: list[str] = []
    for name in _REPLAY_FILES:
        src = REPLAY_DIR / name
        if src.exists():
            dst = output_dir / name
            shutil.copy2(str(src), str(dst))
            restored.append(name)
            logger.info("Replay restore: %s → %s", src, dst)
    if not restored:
        logger.warning(
            "No replay deliverables found in %s — replay directory is empty",
            REPLAY_DIR,
        )
    return restored


# ---------------------------------------------------------------------------
# Phase metadata — expected deliverables & agent names
# ---------------------------------------------------------------------------

_PHASE_META: dict[str, dict[str, Any]] = {
    "recon": {
        "agent_name": "recon-agent",
        "expected_deliverables": ["recon_report.md"],
    },
    "analysis": {
        "agent_name": "analysis-agent (injection + xss + auth + authz + ssrf)",
        "expected_deliverables": ["hypotheses_injection.md", "hypotheses_xss.md", "hypotheses_auth.md", "hypotheses_authz.md", "hypotheses_ssrf.md"],
    },
    "exploit": {
        "agent_name": "exploit-agent (injection + xss + auth + authz + ssrf)",
        "expected_deliverables": ["findings_injection.md", "findings_xss.md", "findings_auth.md", "findings_authz.md", "findings_ssrf.md"],
    },
    "report": {
        "agent_name": "report-agent",
        "expected_deliverables": ["pentest_report.md"],
    },
}


def _verify_deliverables(
    phase_key: str,
    output_dir: Path,
) -> tuple[list[str], list[str]]:
    """Check expected deliverables for a phase exist on disk.

    Returns ``(found, missing)`` — two lists of file names.
    """
    meta = _PHASE_META.get(phase_key, {})
    expected = meta.get("expected_deliverables", [])
    found: list[str] = []
    missing: list[str] = []
    for name in expected:
        if (output_dir / name).exists():
            found.append(name)
        else:
            missing.append(name)
    return found, missing


# ---------------------------------------------------------------------------
# Full pipeline orchestrator
# ---------------------------------------------------------------------------

def run_pipeline(
    config: PipelineConfig | None = None,
    agent_runner: Callable[..., str] | None = None,
    skills_dir: Path | None = None,
    stop_event: threading.Event | None = None,
    resume_from: str | None = None,
) -> PipelineResult:
    """Execute the full SPAIDER pentesting pipeline.

    Runs all four phases sequentially:
        Recon → Analysis → Exploit → Report

    Each phase is wrapped in try/catch so a failure in one phase doesn't
    prevent subsequent phases from running with whatever data is available.

    Args:
        config: Pipeline configuration. Uses defaults if None.
        agent_runner: Callable(prompt: str, phase_name: str) -> str
                      that runs an LLM agent and returns the deliverable content.
                      If None, phases will only validate existing deliverables.
        skills_dir: Override the skills directory path.
        stop_event: If set, abort the pipeline cooperatively.
        resume_from: Phase name to resume from (``recon``, ``analysis``,
                     ``exploit``, or ``report``).  Phases before this are
                     skipped — the pipeline uses existing deliverables on disk.

    Returns:
        PipelineResult with all phase results and generated deliverables.
    """
    if config is None:
        config = PipelineConfig()

    pipeline_start = time.time()
    pipeline_start_dt = datetime.now()
    result = PipelineResult()

    # Initialize skill registry
    registry = SkillRegistry(skills_dir)
    registry.freeze()  # Prevent reload during pipeline run (Race condition #8)

    logger.info("=" * 60)
    logger.info("PIPELINE START — %s", pipeline_start_dt.strftime("%Y-%m-%d %H:%M:%S"))
    logger.info("=" * 60)
    logger.info(
        "Skills loaded: %s", registry.skill_names
    )
    logger.info(
        "Target: %s | Repo: %s | Output: %s",
        config.target_url, config.repo_path, config.output_dir,
    )

    ensure_dir(config.output_dir)

    # Phase definitions — (label, key, function)
    phases: list[tuple[str, str, Callable]] = [
        ("Phase 0: Recon", "recon", run_phase_recon),
        ("Phase 1: Analysis", "analysis", run_phase_analysis),
        ("Phase 2: Exploit", "exploit", run_phase_exploit),
        ("Phase 3: Report", "report", run_phase_report),
    ]

    # Resume support — skip phases before the requested starting point
    _PHASE_KEYS = ["recon", "analysis", "exploit", "report"]
    if resume_from and resume_from in _PHASE_KEYS:
        skip_count = _PHASE_KEYS.index(resume_from)
        if skip_count > 0:
            logger.info(
                "Resuming from '%s' — skipping %d earlier phase(s)",
                resume_from,
                skip_count,
            )
            phases = phases[skip_count:]

    for phase_label, phase_key, phase_fn in phases:
        if stop_event and stop_event.is_set():
            logger.info("Pipeline aborted by user before %s", phase_label)
            break

        meta = _PHASE_META.get(phase_key, {})
        agent_name = meta.get("agent_name", phase_key)
        phase_start_dt = datetime.now()

        logger.info("=" * 60)
        logger.info(
            "[%s] Starting %s  (agent: %s)",
            phase_start_dt.strftime("%H:%M:%S"),
            phase_label,
            agent_name,
        )
        logger.info("=" * 60)

        # Always print phase-level progress to stdout (visible even without --verbose)
        print(f"  [{phase_start_dt.strftime('%H:%M:%S')}] >> {phase_label} starting...", flush=True)

        try:
            phase_result = phase_fn(registry, config, agent_runner, stop_event)
        except PipelineAbortedError:
            # Stop-event abort — break immediately without wasting time
            # on logging / deliverable gates for this phase.
            logger.info("Pipeline aborted by user during %s", phase_label)
            phase_result = PhaseResult(
                phase_name=phase_key,
                success=False,
                errors=["Pipeline aborted by user."],
            )
            result.phases.append(phase_result)
            break
        except Exception as e:
            logger.error("%s FAILED with exception: %s", phase_label, e)
            phase_result = PhaseResult(
                phase_name=phase_key,
                success=False,
                errors=[f"Unhandled exception: {e}"],
            )

        phase_end_dt = datetime.now()
        result.phases.append(phase_result)
        result.deliverables_generated.extend(phase_result.deliverables)

        status = "PASSED" if phase_result.success else "FAILED"
        status_icon = "[OK]" if phase_result.success else "[!!]"
        logger.info(
            "[%s] %s %s  (agent: %s, duration: %.1fs, deliverables: %s)",
            phase_end_dt.strftime("%H:%M:%S"),
            phase_label,
            status,
            agent_name,
            phase_result.duration_seconds,
            phase_result.deliverables,
        )

        # Always print phase completion to stdout
        print(
            f"  [{phase_end_dt.strftime('%H:%M:%S')}] {status_icon} {phase_label} {status} "
            f"({phase_result.duration_seconds:.1f}s, "
            f"{len(phase_result.deliverables)} deliverable(s))",
            flush=True,
        )
        if phase_result.errors:
            for err in phase_result.errors:
                logger.warning("  Error: %s", err)

        # ── Deliverable gate check ────────────────────────────────────
        # Verify expected deliverables exist on disk before advancing
        # to the next phase.  Missing files are logged as warnings but
        # do NOT block the pipeline — subsequent phases will degrade
        # gracefully with whatever data is available.
        found, missing = _verify_deliverables(phase_key, config.output_dir)
        if found:
            logger.info(
                "  Deliverable gate [%s]: found %s",
                phase_key,
                found,
            )
        if missing:
            logger.warning(
                "  Deliverable gate [%s]: MISSING %s — downstream phases may be degraded",
                phase_key,
                missing,
            )

    pipeline_end_dt = datetime.now()
    result.total_duration_seconds = time.time() - pipeline_start
    registry.unfreeze()  # Re-allow reload after pipeline completes

    # Shut down Playwright if it was started during this run
    try:
        from .skills.playwright_bridge import PlaywrightManager
        if PlaywrightManager.is_running():
            logger.info("Shutting down Playwright (calls made: %d)", PlaywrightManager.get_call_count())
            PlaywrightManager.shutdown()
    except ImportError:
        pass

    logger.info("=" * 60)
    logger.info(
        "PIPELINE COMPLETE — %s  (started: %s, duration: %.1fs, deliverables: %d)",
        pipeline_end_dt.strftime("%Y-%m-%d %H:%M:%S"),
        pipeline_start_dt.strftime("%H:%M:%S"),
        result.total_duration_seconds,
        len(result.deliverables_generated),
    )
    if result.deliverables_generated:
        logger.info("  Generated: %s", result.deliverables_generated)
    logger.info("=" * 60)
    return result
