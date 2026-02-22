"""Skills package — loaded dynamically by the SkillRegistry."""

from .skill_loader import SkillRegistry, SkillMetadata, SkillResult, discover_skills
from .skill_wrappers import (
    parse_nmap,
    run_nmap,
    run_whatweb,
    run_sqlmap,
    validate_deliverable,
    validate_with_retry_context,
    lookup_cve,
    batch_lookup_cve,
    format_known_vulns_for_prompt,
    format_technologies_for_prompt,
    format_sqlmap_finding,
    nmap_to_markdown,
)

__all__ = [
    "SkillRegistry",
    "SkillMetadata",
    "SkillResult",
    "discover_skills",
    "parse_nmap",
    "run_nmap",
    "run_whatweb",
    "run_sqlmap",
    "validate_deliverable",
    "validate_with_retry_context",
    "lookup_cve",
    "batch_lookup_cve",
    "format_known_vulns_for_prompt",
    "format_technologies_for_prompt",
    "format_sqlmap_finding",
    "nmap_to_markdown",
]
