"""PenteraX application configuration.

Provides ``AppConfig`` — the single source of truth for application-level
settings (API keys, target URL, budget, output paths).  GUI and CLI both
create an ``AppConfig`` and convert it to a ``PipelineConfig`` via the
``to_pipeline_config()`` adapter before handing it to the pipeline.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from dotenv import load_dotenv

from .exceptions import PenteraXError
from .pipeline import PipelineConfig, DELIVERABLES_DIR

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# AppConfig
# ---------------------------------------------------------------------------


@dataclass
class AppConfig:
    """Application-level configuration.

    Loaded from environment variables / ``.env`` file, or set explicitly by
    the GUI / CLI.  Use ``to_pipeline_config()`` to create the ``PipelineConfig``
    that ``run_pipeline()`` expects.
    """

    target_url: str = "http://54.146.141.88:3000"
    anthropic_api_key: str = ""
    nvd_api_key: str | None = None
    output_dir: Path = field(default_factory=lambda: DELIVERABLES_DIR)
    max_retries: int = 3
    max_budget_usd: float = 10.0
    verbose: bool = False

    # ---- adapters ----------------------------------------------------------

    def to_pipeline_config(self) -> PipelineConfig:
        """Create a ``PipelineConfig`` from this application config."""
        return PipelineConfig(
            target_url=self.target_url,
            output_dir=self.output_dir,
            max_retries=self.max_retries,
            verbose=self.verbose,
        )

    # ---- validation -------------------------------------------------------

    def validate(self) -> list[str]:
        """Return a list of error strings (empty == valid)."""
        errors: list[str] = []
        if not self.target_url:
            errors.append("target_url is required")
        if not self.anthropic_api_key:
            errors.append("anthropic_api_key is required")
        # output_dir must be writable
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            test_file = self.output_dir / ".write_test"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink()
        except OSError as exc:
            errors.append(f"output_dir not writable: {exc}")
        return errors

    # ---- factory -----------------------------------------------------------

    @classmethod
    def from_env(cls, dotenv_path: Path | None = None) -> "AppConfig":
        """Load configuration from environment / ``.env`` file.

        Parameters
        ----------
        dotenv_path:
            Explicit path to a ``.env`` file.  Falls back to
            ``PROJECT_ROOT / ".env"`` if *None*.
        """
        env_file = dotenv_path or (PROJECT_ROOT / ".env")
        load_dotenv(dotenv_path=env_file, override=False)

        return cls(
            target_url=os.getenv("TARGET_URL", "http://54.146.141.88:3000"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
            nvd_api_key=os.getenv("NVD_API_KEY") or None,
            output_dir=Path(os.getenv("OUTPUT_DIR", str(DELIVERABLES_DIR))),
            max_retries=int(os.getenv("MAX_RETRIES", "3")),
            max_budget_usd=float(os.getenv("MAX_BUDGET_USD", "10.0")),
            verbose=os.getenv("VERBOSE", "").lower() in ("1", "true", "yes"),
        )
