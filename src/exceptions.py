"""PenteraX custom exceptions.

All custom exception types for the pipeline are defined here.
Import from this module everywhere to avoid circular dependencies.
"""


class PenteraXError(Exception):
    """Base exception for all PenteraX errors."""


class BudgetExhaustedError(PenteraXError):
    """Raised when the Claude API spend exceeds the configured budget."""

    def __init__(self, spent: float, limit: float) -> None:
        self.spent = spent
        self.limit = limit
        super().__init__(
            f"Budget exhausted: ${spent:.2f} spent, ${limit:.2f} limit"
        )


class PipelineAbortedError(PenteraXError):
    """Raised when the user clicks Stop or sends Ctrl+C."""


class PreflightError(PenteraXError):
    """Raised when a critical pre-flight check fails."""

    def __init__(self, failed_checks: list[str]) -> None:
        self.failed_checks = failed_checks
        summary = "; ".join(failed_checks)
        super().__init__(f"Pre-flight failed: {summary}")


class ValidationError(PenteraXError):
    """Raised when a deliverable fails validation."""
