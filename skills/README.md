# SPAIDER Skills

Modular skills to help Agents perform cybersecurity tasks
Each skill follows the [Anthropic skill-creator](https://github.com/anthropics/skills/tree/main/skills/skill-creator) pattern.

## Available Skills

| Skill | Purpose | Pipeline Phase |
|-------|---------|---------------|
| [network-recon](network-recon/) | Structured JSON from nmap scans | Phase 0b: External Recon |
| [response-analysis](response-analysis/) | Deliverable validation + retry (PenteraX §5.9) | Between all phases |
| [vulnerability-lookup](vulnerability-lookup/) | CVE/exploit lookup for identified versions | Phase 1: Analysis |

## Skill Structure

Each skill follows the standard structure:

```
skill-name/
├── SKILL.md          # Frontmatter (name, description) + workflow instructions
├── scripts/          # Executable scripts for deterministic tasks
└── references/       # Documentation loaded into context as needed
```

## Creating New Skills

To create additional skills, use the [skill-creator](https://github.com/anthropics/skills/tree/main/skills/skill-creator) skill from Anthropic's skills repository, or manually create a directory matching the structure above.

The `SKILL.md` file requires YAML frontmatter with `name` and `description` fields — the
description is the primary trigger mechanism that determines when the skill activates.

## How Skills Integrate with the Pipeline

Skills are referenced from agent prompts via template variables and shell commands:

1. **NetworkReconSkill** — Called by the recon agent to parse nmap output into JSON
2. **ResponseAnalysisSkill** — Called by `pipeline.ts` between phases to validate deliverables
3. **VulnerabilityLookupSkill** — Called by analysis agents to enrich hypotheses with CVE data
