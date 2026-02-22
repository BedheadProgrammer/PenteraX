"""Skill loader and registry for the SPAIDER Agent pipeline.

Discovers skills from the skills/ directory, parses YAML frontmatter from SKILL.md,
and exposes each skill as a callable object that agents and the pipeline can invoke.

Skills follow the Anthropic skill-creator pattern:
    skill-name/
    ├── SKILL.md          # Frontmatter (name, description) + workflow instructions
    ├── scripts/          # Executable scripts for deterministic tasks
    └── references/       # Documentation loaded into context as needed
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("spaider.skills")

# Root of the project
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_DIR = PROJECT_ROOT / "skills"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SkillMetadata:
    """Parsed SKILL.md frontmatter."""
    name: str
    description: str
    skill_dir: Path
    scripts_dir: Path
    references_dir: Path
    workflow_text: str = ""           # Body of SKILL.md after frontmatter
    scripts: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class SkillResult:
    """Standard result envelope returned by every skill invocation."""
    success: bool
    skill_name: str
    output: Any            # Parsed JSON or raw text
    exit_code: int = 0
    errors: list[str] = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""


# ---------------------------------------------------------------------------
# SKILL.md parser
# ---------------------------------------------------------------------------

def _parse_skill_md(skill_md_path: Path) -> tuple[dict, str]:
    """Parse YAML frontmatter and body from a SKILL.md file.

    Returns (frontmatter_dict, body_text).
    """
    text = skill_md_path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}, text

    # Find closing ---
    end = text.find("---", 3)
    if end == -1:
        return {}, text

    frontmatter_raw = text[3:end].strip()
    body = text[end + 3:].strip()

    try:
        frontmatter = yaml.safe_load(frontmatter_raw)
    except yaml.YAMLError:
        logger.warning("Failed to parse YAML frontmatter in %s", skill_md_path)
        frontmatter = {}

    return frontmatter or {}, body


# ---------------------------------------------------------------------------
# Skill discovery
# ---------------------------------------------------------------------------

def discover_skills(skills_dir: Path | None = None) -> list[SkillMetadata]:
    """Walk the skills directory and return metadata for every valid skill."""
    root = skills_dir or SKILLS_DIR
    if not root.exists():
        logger.warning("Skills directory not found: %s", root)
        return []

    skills: list[SkillMetadata] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        skill_md = child / "SKILL.md"
        if not skill_md.exists():
            continue

        frontmatter, body = _parse_skill_md(skill_md)

        scripts_dir = child / "scripts"
        references_dir = child / "references"

        meta = SkillMetadata(
            name=frontmatter.get("name", child.name),
            description=frontmatter.get("description", ""),
            skill_dir=child,
            scripts_dir=scripts_dir,
            references_dir=references_dir,
            workflow_text=body,
            scripts=[p.name for p in scripts_dir.glob("*.py")] if scripts_dir.exists() else [],
            references=[p.name for p in references_dir.iterdir()] if references_dir.exists() else [],
        )
        skills.append(meta)
        logger.info("Discovered skill: %s (%d scripts, %d refs)",
                     meta.name, len(meta.scripts), len(meta.references))

    return skills


# ---------------------------------------------------------------------------
# Skill execution
# ---------------------------------------------------------------------------

def run_skill_script(
    skill: SkillMetadata,
    script_name: str,
    args: list[str] | None = None,
    timeout: int = 120,
    cwd: Path | None = None,
) -> SkillResult:
    """Execute a skill's Python script as a subprocess.

    Args:
        skill: The skill metadata.
        script_name: e.g. ``parse_nmap.py``
        args: CLI arguments to pass after the script path.
        timeout: Max seconds to wait.
        cwd: Working directory.

    Returns:
        A SkillResult with parsed JSON output (if the script produced valid
        JSON on stdout) or raw text otherwise.
    """
    script_path = skill.scripts_dir / script_name
    if not script_path.exists():
        return SkillResult(
            success=False,
            skill_name=skill.name,
            output=None,
            exit_code=-1,
            errors=[f"Script not found: {script_path}"],
        )

    cmd = [sys.executable, str(script_path)] + (args or [])
    logger.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
    except subprocess.TimeoutExpired:
        return SkillResult(
            success=False,
            skill_name=skill.name,
            output=None,
            exit_code=-1,
            errors=[f"Script timed out after {timeout}s"],
        )

    # Try to parse stdout as JSON
    output: Any = proc.stdout
    try:
        output = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        pass  # Keep raw text

    return SkillResult(
        success=proc.returncode == 0,
        skill_name=skill.name,
        output=output,
        exit_code=proc.returncode,
        errors=[proc.stderr] if proc.stderr and proc.returncode != 0 else [],
        raw_stdout=proc.stdout,
        raw_stderr=proc.stderr,
    )


# ---------------------------------------------------------------------------
# SkillRegistry — singleton-style access point
# ---------------------------------------------------------------------------

class SkillRegistry:
    """Central registry that loads, indexes, and exposes all skills.

    Usage::

        registry = SkillRegistry()          # auto-discovers skills/
        recon = registry.get("network-recon")
        result = registry.run("network-recon", "parse_nmap.py",
                              args=["/tmp/nmap_scan.xml", "--markdown"])
    """

    def __init__(self, skills_dir: Path | None = None):
        self._skills: dict[str, SkillMetadata] = {}
        self.reload(skills_dir)

    # -- discovery ----------------------------------------------------------

    def reload(self, skills_dir: Path | None = None) -> None:
        """(Re)discover skills from disk."""
        self._skills.clear()
        for meta in discover_skills(skills_dir):
            self._skills[meta.name] = meta
        logger.info("SkillRegistry loaded %d skills: %s",
                     len(self._skills), list(self._skills.keys()))

    # -- query --------------------------------------------------------------

    @property
    def skill_names(self) -> list[str]:
        return list(self._skills.keys())

    def get(self, name: str) -> SkillMetadata | None:
        return self._skills.get(name)

    def get_workflow(self, name: str) -> str:
        """Return the workflow instructions (SKILL.md body) for a skill."""
        meta = self.get(name)
        return meta.workflow_text if meta else ""

    def get_reference(self, skill_name: str, ref_filename: str) -> str:
        """Load a reference document for a given skill."""
        meta = self.get(skill_name)
        if not meta:
            return ""
        ref_path = meta.references_dir / ref_filename
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8")
        return ""

    def list_all(self) -> list[dict[str, Any]]:
        """Return a JSON-serialisable summary of all registered skills."""
        return [
            {
                "name": m.name,
                "description": m.description,
                "scripts": m.scripts,
                "references": m.references,
            }
            for m in self._skills.values()
        ]

    # -- execution ----------------------------------------------------------

    def run(
        self,
        skill_name: str,
        script_name: str,
        args: list[str] | None = None,
        timeout: int = 120,
        cwd: Path | None = None,
    ) -> SkillResult:
        """Run a skill script by name.

        Raises KeyError if the skill is not registered.
        """
        meta = self._skills.get(skill_name)
        if meta is None:
            raise KeyError(f"Skill not found: {skill_name!r}. "
                           f"Available: {self.skill_names}")
        return run_skill_script(meta, script_name, args=args,
                                timeout=timeout, cwd=cwd)

    # -- prompt context generation ------------------------------------------

    def build_prompt_context(self, skill_name: str) -> str:
        """Build a text block suitable for injection into an agent prompt.

        Combines the skill description, workflow instructions, and all reference
        docs into a single context string that an LLM agent can consume.
        """
        meta = self.get(skill_name)
        if not meta:
            return ""

        parts = [
            f"## Skill: {meta.name}",
            f"**Description:** {meta.description}",
            "",
            meta.workflow_text,
        ]

        # Append reference docs
        if meta.references_dir.exists():
            for ref_file in sorted(meta.references_dir.iterdir()):
                if ref_file.is_file():
                    parts.append(f"\n### Reference: {ref_file.name}\n")
                    parts.append(ref_file.read_text(encoding="utf-8"))

        return "\n".join(parts)

    def build_all_skills_summary(self) -> str:
        """Build a summary of all skills suitable for a system prompt."""
        lines = ["# Available SPAIDER Skills\n"]
        for meta in self._skills.values():
            lines.append(f"## {meta.name}")
            lines.append(f"{meta.description}")
            if meta.scripts:
                lines.append(f"**Scripts:** {', '.join(meta.scripts)}")
            lines.append("")
        return "\n".join(lines)
