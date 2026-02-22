"""SPAIDER Agent — Agentic Cybersecurity Pipeline."""

from .agent_loop import (
    setup_agentic_loop,
    AgenticLoopConfig,
    SkillToolDispatcher,
    MCP_TOOLS,
    build_system_prompt_skills_section,
)
from .pipeline import run_pipeline, PipelineConfig, PipelineResult
from .skills.skill_loader import SkillRegistry, SkillMetadata, SkillResult
from .skills.skill_wrappers import (
    parse_nmap,
    validate_deliverable,
    lookup_cve,
    batch_lookup_cve,
    format_known_vulns_for_prompt,
)

__all__ = [
    # Agentic loop
    "setup_agentic_loop",
    "AgenticLoopConfig",
    "SkillToolDispatcher",
    "MCP_TOOLS",
    "build_system_prompt_skills_section",
    # Pipeline
    "run_pipeline",
    "PipelineConfig",
    "PipelineResult",
    # Skills
    "SkillRegistry",
    "SkillMetadata",
    "SkillResult",
    "parse_nmap",
    "validate_deliverable",
    "lookup_cve",
    "batch_lookup_cve",
    "format_known_vulns_for_prompt",
]
