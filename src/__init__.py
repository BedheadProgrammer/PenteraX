"""PenteraX — Agentic Cybersecurity Pipeline."""

from .agent_loop import (
    setup_agentic_loop,
    AgenticLoopConfig,
    SkillToolDispatcher,
    MCP_TOOLS,
    build_system_prompt_skills_section,
)
from .agent_runner import AgentRunner
from .config import AppConfig
from .exceptions import (
    PenteraXError,
    BudgetExhaustedError,
    PipelineAbortedError,
    PreflightError,
    ValidationError,
)
from .gui_events import (
    LogEvent,
    PhaseStatusEvent,
    BudgetEvent,
    PipelineCompleteEvent,
)
from .logging_handler import QueueLoggingHandler, setup_logging
from .pipeline import run_pipeline, PipelineConfig, PipelineResult, load_replay_deliverables, save_replay_snapshot
from .precollect import run_precollection, collect_source_analysis, collect_nmap_scan, collect_http_probes
from .preflight import run_preflight, PreflightResult
from .skills.skill_loader import SkillRegistry, SkillMetadata, SkillResult
from .skills.skill_wrappers import (
    parse_nmap,
    validate_deliverable,
    lookup_cve,
    batch_lookup_cve,
    format_known_vulns_for_prompt,
)

__all__ = [
    # Config & exceptions
    "AppConfig",
    "PenteraXError",
    "BudgetExhaustedError",
    "PipelineAbortedError",
    "PreflightError",
    "ValidationError",
    # Agent runner
    "AgentRunner",
    # GUI events
    "LogEvent",
    "PhaseStatusEvent",
    "BudgetEvent",
    "PipelineCompleteEvent",
    # Logging
    "QueueLoggingHandler",
    "setup_logging",
    # Preflight
    "run_preflight",
    "PreflightResult",
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
    "load_replay_deliverables",
    "save_replay_snapshot",
    # Pre-collection
    "run_precollection",
    "collect_source_analysis",
    "collect_nmap_scan",
    "collect_http_probes",
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
