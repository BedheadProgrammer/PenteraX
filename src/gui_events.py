"""Event dataclasses for the GUI ←→ pipeline communication queue.

All events are lightweight, immutable data carriers pushed onto a
``queue.Queue`` by the background pipeline thread and consumed by the
GUI main thread via ``root.after()`` polling.

These are defined early (Phase 2) so that ``agent_runner`` and
``logging_handler`` can emit them without circular imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Log events
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LogEvent:
    """A single log record forwarded to the GUI."""

    level: str  # DEBUG, INFO, WARNING, ERROR
    message: str
    timestamp: float


# ---------------------------------------------------------------------------
# Phase / pipeline lifecycle events
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PhaseStatusEvent:
    """Emitted when a pipeline phase changes state."""

    phase_name: str  # recon, analysis, exploit, report
    status: str  # started, completed, failed


@dataclass(frozen=True)
class BudgetEvent:
    """Emitted after each Claude API call with running totals."""

    total_cost_usd: float
    phase_name: str


@dataclass(frozen=True)
class PipelineCompleteEvent:
    """Emitted once when the entire pipeline finishes (success or failure)."""

    success: bool
    total_duration: float
    deliverables: list[str] = field(default_factory=list)
