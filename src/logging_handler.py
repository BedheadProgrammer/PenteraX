"""Logging ←→ GUI bridge and file logging setup.

Provides:
- ``QueueLoggingHandler`` — forwards Python ``logging`` records to a
  ``queue.Queue`` as ``LogEvent`` objects so the GUI main thread can
  consume them safely via ``root.after()`` polling.
- ``setup_logging()`` — configures the root logger with both the queue
  handler and a ``RotatingFileHandler`` writing to
  ``deliverables/pipeline.log``.
"""

from __future__ import annotations

import logging
import queue
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .gui_events import LogEvent

# ---------------------------------------------------------------------------
# Queue-based handler (for the GUI)
# ---------------------------------------------------------------------------


class QueueLoggingHandler(logging.Handler):
    """Puts ``LogEvent`` objects onto a ``queue.Queue`` for GUI consumption.

    Attach to the **root logger** so every existing
    ``logger.info()``/``logger.warning()`` call in *pipeline.py*,
    *skill_loader.py*, *agent_runner.py*, etc. is captured automatically
    (they all propagate to root).
    """

    def __init__(self, event_queue: queue.Queue) -> None:
        super().__init__()
        self.event_queue = event_queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.event_queue.put(
                LogEvent(
                    level=record.levelname,
                    message=self.format(record),
                    timestamp=record.created,
                )
            )
        except Exception:  # noqa: BLE001
            self.handleError(record)


# ---------------------------------------------------------------------------
# Logging configuration helper
# ---------------------------------------------------------------------------

_LOG_FORMAT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
_LOG_DATEFMT = "%H:%M:%S"


def setup_logging(
    *,
    verbose: bool = False,
    log_dir: Path | None = None,
    event_queue: queue.Queue | None = None,
) -> None:
    """Configure the root logger for PenteraX.

    Parameters
    ----------
    verbose:
        If *True*, set level to ``DEBUG`` (turn-by-turn agent output);
        otherwise ``WARNING`` for console (phase-level progress only).
        The file handler always captures ``DEBUG`` regardless.
    log_dir:
        Directory for ``pipeline.log``.  If *None* logging to file is
        skipped.
    event_queue:
        If provided, a ``QueueLoggingHandler`` is attached so the GUI
        receives live log events.
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # root captures everything; handlers filter

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT)

    # Console handler --------------------------------------------------
    # Default: WARNING (phase-level progress only)
    # Verbose: DEBUG   (agent turn-by-turn output)
    console_level = logging.DEBUG if verbose else logging.WARNING
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        console = logging.StreamHandler()
        console.setLevel(console_level)
        console.setFormatter(formatter)
        root.addHandler(console)
    else:
        # Update existing console handler level
        for h in root.handlers:
            if isinstance(h, logging.StreamHandler) and not isinstance(h, (RotatingFileHandler, QueueLoggingHandler)):
                h.setLevel(console_level)

    # File handler (rotating) -----------------------------------------
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "pipeline.log"
        file_handler = RotatingFileHandler(
            str(log_path),
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    # Queue handler (for GUI) -----------------------------------------
    if event_queue is not None:
        q_handler = QueueLoggingHandler(event_queue)
        q_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        q_handler.setFormatter(formatter)
        root.addHandler(q_handler)
