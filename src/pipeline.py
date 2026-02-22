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
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

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
    target_url: str = "http://localhost:3000"
    repo_path: str = "./repos/juice-shop"
    output_dir: Path = DELIVERABLES_DIR
    max_retries: int = 3
    verbose: bool = False


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
    """Write a deliverable file."""
    ensure_dir(output_dir)
    path = output_dir / name
    path.write_text(content, encoding="utf-8")
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
) -> tuple[bool, list[str]]:
    """Validate a deliverable and optionally retry the producing agent.

    Args:
        registry: SkillRegistry instance.
        deliverable_path: Path to the deliverable to validate.
        schema_type: Schema type for validation.
        max_retries: Maximum retry attempts.
        retry_callback: If provided, called with the retry-context string;
                        should return the new deliverable content.

    Returns:
        (passed: bool, errors: list[str])
    """
    for attempt in range(1, max_retries + 1):
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

def run_phase_recon(
    registry: SkillRegistry,
    config: PipelineConfig,
    agent_runner: Callable[..., str] | None = None,
) -> PhaseResult:
    """Phase 0: Reconnaissance.

    - Runs nmap scan → parse_nmap.py for structured JSON
    - Runs vulnerability lookup on discovered tech stack
    - Produces ``recon_report.md``
    """
    start = time.time()
    phase = PhaseResult(phase_name="recon", success=False)

    ensure_dir(config.output_dir)

    # Build prompt variables
    prompt_vars = {
        "TARGET_URL": config.target_url,
        "REPO_PATH": config.repo_path,
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
            save_deliverable("recon_report.md", output, config.output_dir)
            phase.deliverables.append("recon_report.md")
        except Exception as e:
            phase.errors.append(f"Agent execution failed: {e}")
            phase.duration_seconds = time.time() - start
            return phase
    else:
        logger.info("No agent_runner provided — skipping agent execution for recon phase")

    # Validate if deliverable exists
    recon_path = config.output_dir / "recon_report.md"
    if recon_path.exists():
        passed, errors = validate_phase_output(
            registry, recon_path, "recon_report", config.max_retries
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


def run_phase_analysis(
    registry: SkillRegistry,
    config: PipelineConfig,
    agent_runner: Callable[..., str] | None = None,
) -> PhaseResult:
    """Phase 1: Analysis (injection + XSS).

    - Reads recon_report.md
    - Runs vulnerability lookups to enrich with CVE data
    - Produces hypotheses_injection.md and hypotheses_xss.md
    """
    start = time.time()
    phase = PhaseResult(phase_name="analysis", success=False)

    recon_data = read_deliverable("recon_report.md", config.output_dir)
    if not recon_data:
        phase.errors.append("recon_report.md not available — skipping analysis")
        phase.duration_seconds = time.time() - start
        return phase

    # Enrich with vulnerability lookups
    known_vulns = ""
    try:
        # Try common Juice Shop stack components
        tech_stack = [
            {"product": "express", "version": "4.17.1"},
            {"product": "angular", "version": "1.6.0"},
            {"product": "jsonwebtoken", "version": "8.5.1"},
            {"product": "sequelize", "version": "5.22.5"},
        ]
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

    # Run injection analysis
    for analysis_type, template, deliverable_name, schema in [
        ("injection", "analysis-injection.md", "hypotheses_injection.md", "hypotheses"),
        ("xss", "analysis-xss.md", "hypotheses_xss.md", "hypotheses"),
    ]:
        prompt_vars = {**prompt_vars_base}
        prompt_text = load_prompt(PROMPTS_DIR / template, prompt_vars)

        if agent_runner:
            try:
                output = agent_runner(prompt_text, f"analysis-{analysis_type}")
                save_deliverable(deliverable_name, output, config.output_dir)
                phase.deliverables.append(deliverable_name)
            except Exception as e:
                phase.errors.append(f"Analysis-{analysis_type} agent failed: {e}")
                continue

        # Validate
        path = config.output_dir / deliverable_name
        if path.exists():
            passed, errors = validate_phase_output(
                registry, path, schema, config.max_retries
            )
            phase.validation_passed = phase.validation_passed or passed
            if not passed:
                phase.errors.extend(errors)
            if deliverable_name not in phase.deliverables:
                phase.deliverables.append(deliverable_name)

    phase.success = len(phase.deliverables) > 0
    phase.duration_seconds = time.time() - start
    return phase


def run_phase_exploit(
    registry: SkillRegistry,
    config: PipelineConfig,
    agent_runner: Callable[..., str] | None = None,
) -> PhaseResult:
    """Phase 2: Exploitation.

    - Reads hypothesis files
    - Produces findings_injection.md and findings_xss.md
    """
    start = time.time()
    phase = PhaseResult(phase_name="exploit", success=False)

    for exploit_type, template, hyp_file, findings_file in [
        ("injection", "exploit-injection.md", "hypotheses_injection.md", "findings_injection.md"),
        ("xss", "exploit-xss.md", "hypotheses_xss.md", "findings_xss.md"),
    ]:
        hypotheses = read_deliverable(hyp_file, config.output_dir)
        if not hypotheses:
            phase.errors.append(f"{hyp_file} not available — skipping {exploit_type} exploit")
            continue

        prompt_vars = {
            "HYPOTHESES": hypotheses,
            "TARGET_URL": config.target_url,
        }
        prompt_text = load_prompt(PROMPTS_DIR / template, prompt_vars)

        if agent_runner:
            try:
                output = agent_runner(prompt_text, f"exploit-{exploit_type}")
                save_deliverable(findings_file, output, config.output_dir)
                phase.deliverables.append(findings_file)
            except Exception as e:
                phase.errors.append(f"Exploit-{exploit_type} agent failed: {e}")
                continue

        # Validate
        path = config.output_dir / findings_file
        if path.exists():
            passed, errors = validate_phase_output(
                registry, path, "findings", config.max_retries
            )
            phase.validation_passed = phase.validation_passed or passed
            if not passed:
                phase.errors.extend(errors)
            if findings_file not in phase.deliverables:
                phase.deliverables.append(findings_file)

    phase.success = len(phase.deliverables) > 0
    phase.duration_seconds = time.time() - start
    return phase


def run_phase_report(
    registry: SkillRegistry,
    config: PipelineConfig,
    agent_runner: Callable[..., str] | None = None,
) -> PhaseResult:
    """Phase 3: Report generation.

    - Reads all findings files
    - Produces pentest_report.md
    """
    start = time.time()
    phase = PhaseResult(phase_name="report", success=False)

    # Gather all findings
    findings_parts = []
    for name in ["findings_injection.md", "findings_xss.md"]:
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
            save_deliverable("pentest_report.md", output, config.output_dir)
            phase.deliverables.append("pentest_report.md")
        except Exception as e:
            phase.errors.append(f"Report agent failed: {e}")

    # Validate
    path = config.output_dir / "pentest_report.md"
    if path.exists():
        passed, errors = validate_phase_output(
            registry, path, "pentest_report", config.max_retries
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
# Full pipeline orchestrator
# ---------------------------------------------------------------------------

def run_pipeline(
    config: PipelineConfig | None = None,
    agent_runner: Callable[..., str] | None = None,
    skills_dir: Path | None = None,
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

    Returns:
        PipelineResult with all phase results and generated deliverables.
    """
    if config is None:
        config = PipelineConfig()

    pipeline_start = time.time()
    result = PipelineResult()

    # Initialize skill registry
    registry = SkillRegistry(skills_dir)
    logger.info(
        "Pipeline starting — skills loaded: %s", registry.skill_names
    )
    logger.info(
        "Target: %s | Repo: %s | Output: %s",
        config.target_url, config.repo_path, config.output_dir,
    )

    ensure_dir(config.output_dir)

    # Phase definitions
    phases = [
        ("Phase 0: Recon", run_phase_recon),
        ("Phase 1: Analysis", run_phase_analysis),
        ("Phase 2: Exploit", run_phase_exploit),
        ("Phase 3: Report", run_phase_report),
    ]

    for phase_label, phase_fn in phases:
        logger.info("=" * 60)
        logger.info("Starting %s", phase_label)
        logger.info("=" * 60)

        try:
            phase_result = phase_fn(registry, config, agent_runner)
        except Exception as e:
            logger.error("%s FAILED with exception: %s", phase_label, e)
            phase_result = PhaseResult(
                phase_name=phase_label,
                success=False,
                errors=[f"Unhandled exception: {e}"],
            )

        result.phases.append(phase_result)
        result.deliverables_generated.extend(phase_result.deliverables)

        status = "PASSED" if phase_result.success else "FAILED"
        logger.info(
            "%s %s (%.1fs, deliverables: %s)",
            phase_label, status,
            phase_result.duration_seconds,
            phase_result.deliverables,
        )
        if phase_result.errors:
            for err in phase_result.errors:
                logger.warning("  Error: %s", err)

    result.total_duration_seconds = time.time() - pipeline_start
    logger.info("=" * 60)
    logger.info(
        "Pipeline complete in %.1fs — %d deliverables generated",
        result.total_duration_seconds,
        len(result.deliverables_generated),
    )
    return result
