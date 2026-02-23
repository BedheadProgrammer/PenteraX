"""PenteraX — CustomTkinter desktop GUI.

Layout (Phase 5 — polished)::

    ┌──────────────────────────────────────────────────────────┐
    │  PenteraX — Agentic Pentest Pipeline                     │
    ├──────────────────┬───────────────────────────────────────┤
    │  CONFIG PANEL    │  ┌─Log Stream─┬─Report Viewer─┐      │
    │                  │  │                             │      │
    │  Target URL:[__] │  │ [scrolling log output]      │      │
    │  API Key:  [__]  │  │                             │      │
    │  Output Dir:[__] │  │                             │      │
    │  Max Retries:[_] │  └─────────────────────────────┘      │
    │  Budget ($):[__] │                                       │
    │  Resume from:[v] ├───────────────────────────────────────┤
    │  ☐ Replay Mode   │  PHASE STATUS                         │
    │                  │  ⏳ Recon      running… (12s)          │
    │  [Run Preflight] │  ✓  Analysis   completed (45s)        │
    │  [Start Pipeline]│  —  Exploit    waiting                 │
    │  [Stop]          │  —  Report     waiting                 │
    │  [Save Report]   │                                       │
    │                  │  MODE: LIVE / [REPLAY]                 │
    │  BUDGET: $X.XX   │                                       │
    │  ELAPSED: MM:SS  │                                       │
    └──────────────────┴───────────────────────────────────────┘

Thread architecture:
1. **GUI main thread** — all Tkinter widget updates.
2. **Pipeline daemon thread** — ``threading.Thread(target=..., daemon=True)``.
3. **Communication:** ``queue.Queue`` (thread-safe).
4. **Stop button:** sets ``threading.Event``; agent runner checks before
   each API call.
"""

from __future__ import annotations

import json
import logging
import queue
import shutil
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog
from typing import Any

try:
    import customtkinter as ctk
except ImportError:  # allow importing the module for type-checking
    ctk = None  # type: ignore[assignment]

from .config import AppConfig, PROJECT_ROOT
from .exceptions import PipelineAbortedError, PreflightError
from .gui_events import (
    BudgetEvent,
    LogEvent,
    PhaseStatusEvent,
    PipelineCompleteEvent,
)
from .logging_handler import QueueLoggingHandler, setup_logging
from .pipeline import (
    DELIVERABLES_DIR,
    PipelineConfig,
    run_pipeline,
    load_replay_deliverables,
    save_replay_snapshot,
)
from .preflight import run_preflight

logger = logging.getLogger("penterax.gui")

# ---------------------------------------------------------------------------
# Settings persistence helpers
# ---------------------------------------------------------------------------

_SETTINGS_DIR = Path.home() / ".penterax"
_SETTINGS_FILE = _SETTINGS_DIR / "settings.json"

# Keys that are persisted (never persist the API key)
_PERSIST_KEYS = ("target_url", "output_dir", "max_budget_usd", "max_retries", "theme")


def _load_settings() -> dict[str, Any]:
    """Load persisted GUI settings from disk, returning an empty dict on failure."""
    try:
        if _SETTINGS_FILE.exists():
            return json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        pass
    return {}


def _save_settings(data: dict[str, Any]) -> None:
    """Persist GUI settings to disk."""
    try:
        _SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
        _SETTINGS_FILE.write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8"
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not save settings: %s", exc)


# ---------------------------------------------------------------------------
# GUI Application
# ---------------------------------------------------------------------------

_PHASE_NAMES = ["recon", "analysis", "exploit", "report"]
_RESUME_OPTIONS = ["(all phases)", "recon", "analysis", "exploit", "report"]
_QUEUE_POLL_MS = 100  # milliseconds between queue polls

# Spinner animation frames for phase-in-progress indicator
_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class PenteraXApp(ctk.CTk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()

        self.title("PenteraX — Agentic Pentest Pipeline")
        self.geometry("1200x750")
        self.minsize(1000, 600)

        # State ---------------------------------------------------------------
        self._event_queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._pipeline_thread: threading.Thread | None = None
        self._running = False  # tracks whether a pipeline is active
        self._start_time: float | None = None
        self._elapsed_after_id: str | None = None
        self._spinner_after_id: str | None = None
        self._spinner_idx: int = 0
        self._active_phases: set[str] = set()  # phases currently in progress
        self._phase_durations: dict[str, float] = {}  # phase_name → duration
        self._is_replay: bool = False  # whether current run is replay mode

        # Load saved settings ------------------------------------------------
        saved = _load_settings()
        self._theme = saved.get("theme", "dark")
        ctk.set_appearance_mode(self._theme)
        ctk.set_default_color_theme("blue")

        # Build UI -----------------------------------------------------------
        self._build_ui(saved)

        # Window close handler (Race condition #4) ---------------------------
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Start polling the event queue
        self.after(_QUEUE_POLL_MS, self._poll_queue)

    # --------------------------------------------------------------------- #
    # UI construction                                                        #
    # --------------------------------------------------------------------- #

    def _build_ui(self, saved: dict[str, Any]) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ── Left panel (config + controls) ──────────────────────────────
        left = ctk.CTkScrollableFrame(self, width=290)
        left.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)

        ctk.CTkLabel(left, text="Configuration", font=ctk.CTkFont(size=16, weight="bold")).pack(
            pady=(12, 8), padx=12, anchor="w"
        )

        # Target URL
        ctk.CTkLabel(left, text="Target URL").pack(anchor="w", padx=12)
        self._target_var = ctk.StringVar(value=saved.get("target_url", ""))
        ctk.CTkEntry(left, textvariable=self._target_var, placeholder_text="http://54.146.141.88:3000").pack(
            fill="x", padx=12, pady=(0, 6)
        )

        # API Key
        ctk.CTkLabel(left, text="Anthropic API Key").pack(anchor="w", padx=12)
        self._apikey_var = ctk.StringVar(value="")
        ctk.CTkEntry(left, textvariable=self._apikey_var, show="•", placeholder_text="sk-ant-...").pack(
            fill="x", padx=12, pady=(0, 6)
        )

        # Output Dir
        ctk.CTkLabel(left, text="Output Directory").pack(anchor="w", padx=12)
        self._outdir_var = ctk.StringVar(value=saved.get("output_dir", str(DELIVERABLES_DIR)))
        ctk.CTkEntry(left, textvariable=self._outdir_var).pack(fill="x", padx=12, pady=(0, 6))

        # Max Retries
        ctk.CTkLabel(left, text="Max Retries").pack(anchor="w", padx=12)
        self._retries_var = ctk.StringVar(value=str(saved.get("max_retries", 3)))
        ctk.CTkEntry(left, textvariable=self._retries_var, width=80).pack(anchor="w", padx=12, pady=(0, 6))

        # Budget
        ctk.CTkLabel(left, text="Budget ($)").pack(anchor="w", padx=12)
        self._budget_var = ctk.StringVar(value=str(saved.get("max_budget_usd", 10.0)))
        ctk.CTkEntry(left, textvariable=self._budget_var, width=80).pack(anchor="w", padx=12, pady=(0, 6))

        # Resume-from dropdown
        ctk.CTkLabel(left, text="Resume From").pack(anchor="w", padx=12)
        self._resume_var = ctk.StringVar(value=_RESUME_OPTIONS[0])
        ctk.CTkOptionMenu(
            left,
            variable=self._resume_var,
            values=_RESUME_OPTIONS,
            width=200,
        ).pack(anchor="w", padx=12, pady=(0, 6))

        # Replay mode checkbox
        self._replay_var = ctk.BooleanVar(value=False)
        self._replay_check = ctk.CTkCheckBox(
            left,
            text="Replay Mode (no API calls)",
            variable=self._replay_var,
            command=self._on_replay_toggle,
        )
        self._replay_check.pack(anchor="w", padx=12, pady=(4, 8))

        # Buttons
        btn_frame = ctk.CTkFrame(left, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=(8, 4))

        self._preflight_btn = ctk.CTkButton(btn_frame, text="Run Preflight", command=self._on_preflight)
        self._preflight_btn.pack(fill="x", pady=2)

        self._start_btn = ctk.CTkButton(
            btn_frame, text="Start Pipeline", command=self._on_start, fg_color="green"
        )
        self._start_btn.pack(fill="x", pady=2)

        self._stop_btn = ctk.CTkButton(
            btn_frame, text="Stop", command=self._on_stop, fg_color="red", state="disabled"
        )
        self._stop_btn.pack(fill="x", pady=2)

        self._save_report_btn = ctk.CTkButton(
            btn_frame, text="Save Report…", command=self._on_save_report
        )
        self._save_report_btn.pack(fill="x", pady=(8, 2))

        self._save_replay_btn = ctk.CTkButton(
            btn_frame, text="Save Replay Snapshot", command=self._on_save_replay
        )
        self._save_replay_btn.pack(fill="x", pady=2)

        # Theme toggle
        self._theme_btn = ctk.CTkButton(
            btn_frame, text="Toggle Theme", command=self._toggle_theme, width=100
        )
        self._theme_btn.pack(fill="x", pady=(8, 2))

        # Budget / elapsed / mode labels
        self._budget_label = ctk.CTkLabel(left, text="BUDGET: $0.00", font=ctk.CTkFont(size=13))
        self._budget_label.pack(anchor="w", padx=12, pady=(10, 0))
        self._elapsed_label = ctk.CTkLabel(left, text="ELAPSED: 00:00", font=ctk.CTkFont(size=13))
        self._elapsed_label.pack(anchor="w", padx=12, pady=(2, 0))
        self._mode_label = ctk.CTkLabel(left, text="MODE: LIVE", font=ctk.CTkFont(size=13, weight="bold"))
        self._mode_label.pack(anchor="w", padx=12, pady=(2, 8))

        # ── Right panel (tabbed: log + report viewer + phase status) ────
        right = ctk.CTkFrame(self)
        right.grid(row=0, column=1, sticky="nsew", padx=(4, 8), pady=8)
        right.grid_rowconfigure(0, weight=3)
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        # Tabbed view: Log Stream | Report Viewer
        self._tabview = ctk.CTkTabview(right)
        self._tabview.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 4))
        self._tabview.add("Log Stream")
        self._tabview.add("Report Viewer")

        # -- Log Stream tab --
        log_tab = self._tabview.tab("Log Stream")
        log_tab.grid_rowconfigure(0, weight=1)
        log_tab.grid_columnconfigure(0, weight=1)
        self._log_box = ctk.CTkTextbox(
            log_tab, state="disabled", wrap="word",
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self._log_box.grid(row=0, column=0, sticky="nsew")

        # -- Report Viewer tab --
        report_tab = self._tabview.tab("Report Viewer")
        report_tab.grid_rowconfigure(0, weight=1)
        report_tab.grid_columnconfigure(0, weight=1)
        self._report_box = ctk.CTkTextbox(
            report_tab, state="disabled", wrap="word",
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self._report_box.grid(row=0, column=0, sticky="nsew")

        # Phase status panel
        phase_frame = ctk.CTkFrame(right)
        phase_frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=(4, 8))
        ctk.CTkLabel(phase_frame, text="Phase Status", font=ctk.CTkFont(size=14, weight="bold")).pack(
            anchor="w", padx=8, pady=(6, 4)
        )

        self._phase_labels: dict[str, ctk.CTkLabel] = {}
        for name in _PHASE_NAMES:
            lbl = ctk.CTkLabel(
                phase_frame,
                text=f"  —  {name.capitalize():15s}  waiting",
                font=ctk.CTkFont(family="Consolas", size=13),
            )
            lbl.pack(anchor="w", padx=12)
            self._phase_labels[name] = lbl

    # --------------------------------------------------------------------- #
    # Actions                                                                #
    # --------------------------------------------------------------------- #

    def _build_config(self) -> AppConfig:
        """Construct an ``AppConfig`` from the GUI fields."""
        return AppConfig(
            target_url=self._target_var.get().strip(),
            anthropic_api_key=self._apikey_var.get().strip(),
            output_dir=Path(self._outdir_var.get().strip()) if self._outdir_var.get().strip() else DELIVERABLES_DIR,
            max_retries=int(self._retries_var.get() or 3),
            max_budget_usd=float(self._budget_var.get() or 10.0),
        )

    def _get_resume_from(self) -> str | None:
        """Return the resume-from phase name, or *None* for a full run."""
        val = self._resume_var.get()
        if val == _RESUME_OPTIONS[0]:
            return None
        return val

    # ---------- Replay mode toggle ----------------------------------------

    def _on_replay_toggle(self) -> None:
        """Update the mode label when replay checkbox changes."""
        if self._replay_var.get():
            self._mode_label.configure(text="MODE: [REPLAY]", text_color="orange")
        else:
            self._mode_label.configure(text="MODE: LIVE", text_color=("gray10", "gray90"))

    # ---------- Preflight -------------------------------------------------

    def _on_preflight(self) -> None:
        """Run pre-flight checks in a short-lived thread."""
        cfg = self._build_config()
        errors = cfg.validate()
        if errors:
            self._log(f"Config errors: {'; '.join(errors)}", "ERROR")
            return
        self._log("Running pre-flight checks…", "INFO")
        threading.Thread(target=self._preflight_worker, args=(cfg,), daemon=True).start()

    def _preflight_worker(self, cfg: AppConfig) -> None:
        result = run_preflight(cfg)
        for check in result.checks:
            lvl = "INFO" if check.passed else ("ERROR" if check.critical else "WARNING")
            icon = "✓" if check.passed else "✗"
            self._event_queue.put(
                LogEvent(level=lvl, message=f"  [{icon}] {check.name}: {check.message}", timestamp=time.time())
            )
        if result.all_critical_passed:
            self._event_queue.put(LogEvent(level="INFO", message="Pre-flight: ALL CRITICAL PASSED", timestamp=time.time()))
        else:
            self._event_queue.put(LogEvent(level="ERROR", message="Pre-flight: CRITICAL CHECKS FAILED", timestamp=time.time()))

    # ---------- Start pipeline -------------------------------------------

    def _on_start(self) -> None:
        """Launch the pipeline in a background thread (Race condition #3)."""
        if self._running:
            return

        replay = self._replay_var.get()
        cfg = self._build_config()

        # In replay mode, skip API key validation
        if not replay:
            errors = cfg.validate()
            if errors:
                self._log(f"Config errors: {'; '.join(errors)}", "ERROR")
                return

        self._running = True
        self._is_replay = replay
        self._stop_event.clear()
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._preflight_btn.configure(state="disabled")
        self._save_report_btn.configure(state="disabled")
        self._save_replay_btn.configure(state="disabled")
        self._start_time = time.time()
        self._active_phases.clear()
        self._phase_durations.clear()
        self._tick_elapsed()

        # Reset phase indicators
        for name in _PHASE_NAMES:
            self._phase_labels[name].configure(
                text=f"  —  {name.capitalize():15s}  waiting",
                text_color=("gray10", "gray90"),
            )

        if replay:
            self._log("Pipeline starting in REPLAY MODE…", "WARNING")
            self._mode_label.configure(text="MODE: [REPLAY]", text_color="orange")
        else:
            self._log("Pipeline starting…", "INFO")
        self._save_current_settings()

        # Setup logging to pipe into our queue
        setup_logging(
            verbose=cfg.verbose,
            log_dir=cfg.output_dir,
            event_queue=self._event_queue,
        )

        resume_from = self._get_resume_from()
        if resume_from:
            self._log(f"Resuming from phase: {resume_from}", "INFO")

        self._pipeline_thread = threading.Thread(
            target=self._pipeline_worker,
            args=(cfg, replay, resume_from),
            daemon=True,
        )
        self._pipeline_thread.start()

    def _pipeline_worker(
        self, cfg: AppConfig, replay: bool, resume_from: str | None
    ) -> None:
        """Runs in a daemon thread — NEVER touch widgets here."""
        start = time.time()
        success = False
        deliverables: list[str] = []
        try:
            pipeline_cfg = cfg.to_pipeline_config()

            # In replay mode, load pre-recorded deliverables first
            if replay:
                restored = load_replay_deliverables(pipeline_cfg.output_dir)
                if not restored:
                    self._event_queue.put(
                        LogEvent(
                            level="ERROR",
                            message="No replay deliverables found in deliverables/replay/. "
                                    "Run a full pipeline first, then click 'Save Replay Snapshot'.",
                            timestamp=time.time(),
                        )
                    )
                    return
                for r in restored:
                    self._event_queue.put(
                        LogEvent(level="INFO", message=f"  Restored: {r}", timestamp=time.time())
                    )

            # Build agent runner (None for replay mode)
            agent_runner_fn = None
            if not replay:
                from .agent_runner import AgentRunner
                from .agent_loop import MCP_TOOLS, SkillToolDispatcher
                from .artifact_store import ArtifactStore
                from .skills.skill_loader import SkillRegistry

                runner = AgentRunner(
                    api_key=cfg.anthropic_api_key,
                    max_budget_usd=cfg.max_budget_usd,
                    stop_event=self._stop_event,
                    event_queue=self._event_queue,
                )

                # Wire agentic loop (tools + dispatcher)
                artifact_store = ArtifactStore()
                registry = SkillRegistry()
                dispatcher = SkillToolDispatcher(registry, artifact_store=artifact_store)
                runner._tools = MCP_TOOLS
                runner._tool_dispatcher = dispatcher
                agent_runner_fn = runner.run

            result = run_pipeline(
                config=pipeline_cfg,
                agent_runner=agent_runner_fn,
                stop_event=self._stop_event,
                resume_from=resume_from,
            )
            deliverables = result.deliverables_generated
            success = all(p.success for p in result.phases)

            # Emit phase status events for any phases the pipeline reported
            for phase in result.phases:
                status = "completed" if phase.success else "failed"
                self._event_queue.put(
                    PhaseStatusEvent(phase_name=phase.phase_name, status=status)
                )

        except PipelineAbortedError:
            self._event_queue.put(
                LogEvent(level="WARNING", message="Pipeline aborted by user.", timestamp=time.time())
            )
        except Exception as exc:
            self._event_queue.put(
                LogEvent(level="ERROR", message=f"Pipeline error: {exc}", timestamp=time.time())
            )
        finally:
            elapsed = time.time() - start
            self._event_queue.put(
                PipelineCompleteEvent(
                    success=success,
                    total_duration=elapsed,
                    deliverables=deliverables,
                )
            )

    # ---------- Stop pipeline --------------------------------------------

    def _on_stop(self) -> None:
        """Request pipeline termination (cooperative stop)."""
        if not self._running:
            return
        self._log("Stop requested — waiting for current operation…", "WARNING")
        self._stop_event.set()

    # ---------- Save Report ----------------------------------------------

    def _on_save_report(self) -> None:
        """Export pentest_report.md to a user-chosen location."""
        output_dir = Path(self._outdir_var.get().strip()) if self._outdir_var.get().strip() else DELIVERABLES_DIR
        report_path = output_dir / "pentest_report.md"
        if not report_path.exists():
            self._log("No pentest_report.md found — run the pipeline first.", "WARNING")
            return

        dest = filedialog.asksaveasfilename(
            title="Save Report As",
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("All Files", "*.*")],
            initialfile="pentest_report.md",
        )
        if not dest:
            return
        try:
            shutil.copy2(str(report_path), dest)
            self._log(f"Report saved to: {dest}", "INFO")
        except Exception as exc:
            self._log(f"Failed to save report: {exc}", "ERROR")

    # ---------- Save Replay Snapshot ------------------------------------

    def _on_save_replay(self) -> None:
        """Copy current deliverables into deliverables/replay/."""
        output_dir = Path(self._outdir_var.get().strip()) if self._outdir_var.get().strip() else DELIVERABLES_DIR
        try:
            copied = save_replay_snapshot(output_dir)
            if copied:
                self._log(f"Replay snapshot saved ({len(copied)} files): {', '.join(copied)}", "INFO")
            else:
                self._log("No deliverables to snapshot — run the pipeline first.", "WARNING")
        except Exception as exc:
            self._log(f"Failed to save replay snapshot: {exc}", "ERROR")

    # ---------- Theme toggle ---------------------------------------------

    def _toggle_theme(self) -> None:
        self._theme = "light" if self._theme == "dark" else "dark"
        ctk.set_appearance_mode(self._theme)
        self._save_current_settings()

    # --------------------------------------------------------------------- #
    # Queue polling (Race condition #2 mitigation)                          #
    # --------------------------------------------------------------------- #

    def _poll_queue(self) -> None:
        """Drain the event queue and update widgets — runs on the main thread."""
        try:
            while True:
                event = self._event_queue.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        finally:
            self.after(_QUEUE_POLL_MS, self._poll_queue)

    def _handle_event(self, event: Any) -> None:
        if isinstance(event, LogEvent):
            self._append_log(f"[{event.level}] {event.message}")

        elif isinstance(event, PhaseStatusEvent):
            self._update_phase_status(event)

        elif isinstance(event, BudgetEvent):
            self._budget_label.configure(text=f"BUDGET: ${event.total_cost_usd:.2f}")

        elif isinstance(event, PipelineCompleteEvent):
            self._on_pipeline_done(event)

    def _update_phase_status(self, event: PhaseStatusEvent) -> None:
        """Update a phase label with status and start/stop the spinner."""
        lbl = self._phase_labels.get(event.phase_name)
        if lbl is None:
            return

        if event.status == "started":
            self._active_phases.add(event.phase_name)
            self._phase_durations[event.phase_name] = time.time()
            if not self._spinner_after_id:
                self._tick_spinner()
        elif event.status in ("completed", "failed"):
            self._active_phases.discard(event.phase_name)
            # Calculate duration
            started_at = self._phase_durations.get(event.phase_name)
            dur_str = ""
            if started_at:
                dur = time.time() - started_at
                dur_str = f" ({dur:.1f}s)"

            if event.status == "completed":
                lbl.configure(
                    text=f"  ✓  {event.phase_name.capitalize():15s}  completed{dur_str}",
                    text_color="green",
                )
            else:
                lbl.configure(
                    text=f"  ✗  {event.phase_name.capitalize():15s}  failed{dur_str}",
                    text_color="red",
                )

            # Stop spinner if no more active phases
            if not self._active_phases and self._spinner_after_id:
                self.after_cancel(self._spinner_after_id)
                self._spinner_after_id = None

    def _tick_spinner(self) -> None:
        """Animate spinner on all in-progress phase labels."""
        if not self._active_phases:
            self._spinner_after_id = None
            return
        frame = _SPINNER_FRAMES[self._spinner_idx % len(_SPINNER_FRAMES)]
        self._spinner_idx += 1

        for name in list(self._active_phases):
            lbl = self._phase_labels.get(name)
            if lbl:
                started_at = self._phase_durations.get(name)
                dur_str = ""
                if started_at:
                    dur = time.time() - started_at
                    dur_str = f" ({dur:.0f}s)"
                lbl.configure(
                    text=f"  {frame}  {name.capitalize():15s}  running…{dur_str}",
                    text_color="orange",
                )

        self._spinner_after_id = self.after(150, self._tick_spinner)

    def _on_pipeline_done(self, event: PipelineCompleteEvent) -> None:
        status = "SUCCESS" if event.success else "FINISHED (with errors)"
        self._append_log(
            f"\n{'='*50}\nPipeline {status} in {event.total_duration:.1f}s\n"
            f"Deliverables: {', '.join(event.deliverables) or 'none'}\n{'='*50}"
        )

        # Stop spinner
        self._active_phases.clear()
        if self._spinner_after_id:
            self.after_cancel(self._spinner_after_id)
            self._spinner_after_id = None

        # Re-enable controls
        self._running = False
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._preflight_btn.configure(state="normal")
        self._save_report_btn.configure(state="normal")
        self._save_replay_btn.configure(state="normal")
        if self._elapsed_after_id:
            self.after_cancel(self._elapsed_after_id)
            self._elapsed_after_id = None

        # Load the report into the Report Viewer tab (if available)
        self._load_report_viewer()

    def _load_report_viewer(self) -> None:
        """Load pentest_report.md into the Report Viewer tab."""
        output_dir = Path(self._outdir_var.get().strip()) if self._outdir_var.get().strip() else DELIVERABLES_DIR
        report_path = output_dir / "pentest_report.md"
        self._report_box.configure(state="normal")
        self._report_box.delete("1.0", "end")
        if report_path.exists():
            try:
                content = report_path.read_text(encoding="utf-8")
                self._report_box.insert("1.0", content)
                self._log("Report loaded into Report Viewer tab.", "INFO")
                # Auto-switch to the Report Viewer tab
                self._tabview.set("Report Viewer")
            except Exception as exc:
                self._report_box.insert("1.0", f"Error loading report: {exc}")
        else:
            self._report_box.insert("1.0", "No pentest_report.md found.\n\nRun the pipeline to generate a report.")
        self._report_box.configure(state="disabled")

    # --------------------------------------------------------------------- #
    # Helpers                                                                #
    # --------------------------------------------------------------------- #

    def _log(self, message: str, level: str = "INFO") -> None:
        """Push a log event onto the queue (safe from any thread)."""
        self._event_queue.put(LogEvent(level=level, message=message, timestamp=time.time()))

    def _append_log(self, text: str) -> None:
        """Append text to the log textbox (must be called on main thread)."""
        self._log_box.configure(state="normal")
        self._log_box.insert("end", text + "\n")
        self._log_box.see("end")
        self._log_box.configure(state="disabled")

    def _tick_elapsed(self) -> None:
        """Update the elapsed-time label every second."""
        if self._start_time and self._running:
            secs = int(time.time() - self._start_time)
            mins, s = divmod(secs, 60)
            self._elapsed_label.configure(text=f"ELAPSED: {mins:02d}:{s:02d}")
            self._elapsed_after_id = self.after(1000, self._tick_elapsed)

    def _save_current_settings(self) -> None:
        data = {
            "target_url": self._target_var.get().strip(),
            "output_dir": self._outdir_var.get().strip(),
            "max_budget_usd": float(self._budget_var.get() or 10.0),
            "max_retries": int(self._retries_var.get() or 3),
            "theme": self._theme,
        }
        _save_settings(data)

    # --------------------------------------------------------------------- #
    # Window close (Race condition #4)                                      #
    # --------------------------------------------------------------------- #

    def _on_close(self) -> None:
        """Handle window close — gracefully stop the pipeline thread."""
        if self._running and self._pipeline_thread is not None:
            self._stop_event.set()
            self._pipeline_thread.join(timeout=5)
        self._save_current_settings()
        self.destroy()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Launch the PenteraX GUI."""
    if ctk is None:
        print("customtkinter is not installed. Install it with: pip install customtkinter")
        return 1
    app = PenteraXApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
