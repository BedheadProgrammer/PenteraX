"""Claude SDK integration — wraps the Anthropic API with budget tracking and resilience.

``AgentRunner.run(prompt, phase_name)`` matches the
``Callable[[str, str], str]`` signature expected by ``run_pipeline(agent_runner=...)``.

Features:
- Running cost accounting with ``threading.Lock`` (Race condition #1).
- Exponential-backoff retry on transient API errors.
- Context-window overflow guard (truncates skill reference material).
- Cooperative stop via ``threading.Event`` (raises ``PipelineAbortedError``).
- Structured logging for each API call (phase, tokens, cost, duration).
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any

import anthropic

from .exceptions import BudgetExhaustedError, PipelineAbortedError
from .gui_events import BudgetEvent, LogEvent

logger = logging.getLogger("penterax.agent_runner")

# ---------------------------------------------------------------------------
# Pricing (USD per token) — Claude 3.5 Sonnet / claude-sonnet-4-20250514
# Update these when model pricing changes.
# ---------------------------------------------------------------------------

_MODEL = "claude-sonnet-4-20250514"
_MAX_TOKENS = 16384  # max output tokens per call

# Pricing per 1 M tokens (input / output)
_INPUT_PRICE_PER_M = 3.00  # $3.00 per 1 M input tokens
_OUTPUT_PRICE_PER_M = 15.00  # $15.00 per 1 M output tokens

_INPUT_PRICE = _INPUT_PRICE_PER_M / 1_000_000
_OUTPUT_PRICE = _OUTPUT_PRICE_PER_M / 1_000_000

# Retry schedule — base delays in seconds (actual = base * 2^attempt)
_RETRY_BASE_DELAYS = [2, 8, 32]
_RETRYABLE_EXCEPTIONS = (
    anthropic.RateLimitError,
    anthropic.APIConnectionError,
    anthropic.InternalServerError,
)

# Rough context-window budget (tokens).  We leave head-room for the response.
_CONTEXT_WINDOW = 200_000
_MAX_PROMPT_TOKENS_ESTIMATE = _CONTEXT_WINDOW - _MAX_TOKENS  # ~184 k


# ---------------------------------------------------------------------------
# AgentRunner
# ---------------------------------------------------------------------------


class AgentRunner:
    """Thread-safe Claude SDK wrapper with budget tracking.

    Parameters
    ----------
    api_key:
        Anthropic API key.
    max_budget_usd:
        Hard spend cap.  ``BudgetExhaustedError`` is raised when exceeded.
    stop_event:
        Optional ``threading.Event``.  When set, the runner aborts before the
        next API call with ``PipelineAbortedError``.
    event_queue:
        Optional ``queue.Queue`` to push ``BudgetEvent`` / ``LogEvent``
        objects for GUI consumption.
    tools:
        Optional list of MCP-style tool definitions to pass to the API.
    tool_dispatcher:
        Optional callable that handles tool-use blocks.  Signature:
        ``(tool_name: str, tool_input: dict) -> dict``.
    system_prompt:
        Optional system prompt prepended to every call.
    """

    def __init__(
        self,
        api_key: str,
        max_budget_usd: float = 10.0,
        stop_event: threading.Event | None = None,
        event_queue: queue.Queue | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_dispatcher: Any | None = None,
        system_prompt: str | None = None,
    ) -> None:
        self.client = anthropic.Anthropic(api_key=api_key)
        self.max_budget_usd = max_budget_usd
        self.total_cost_usd: float = 0.0

        self._budget_lock = threading.Lock()  # Race condition #1
        self._stop_event = stop_event
        self._event_queue = event_queue
        self._tools = tools
        self._tool_dispatcher = tool_dispatcher
        self._system_prompt = system_prompt

    # --------------------------------------------------------------------- #
    # Public interface                                                        #
    # --------------------------------------------------------------------- #

    def run(self, prompt: str, phase_name: str) -> str:
        """Execute a prompt against Claude and return the text response.

        This method matches the ``Callable[[str, str], str]`` expected by
        ``run_pipeline(agent_runner=...)``.  Pass the bound method::

            runner = AgentRunner(api_key=key)
            result = run_pipeline(config, agent_runner=runner.run)

        If tools are configured, the runner enters an agentic tool-use loop
        until the model produces a final text response (or hits the budget).
        """
        self._check_stop()
        self._check_budget(phase_name)

        # Guard against enormous prompts by trimming if necessary
        prompt = self._maybe_truncate(prompt)

        # Build the initial messages list
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": prompt},
        ]

        # Enter the agentic loop (handles tool use if tools are configured)
        return self._agentic_loop(messages, phase_name)

    # --------------------------------------------------------------------- #
    # Agentic tool-use loop                                                   #
    # --------------------------------------------------------------------- #

    def _agentic_loop(self, messages: list[dict[str, Any]], phase_name: str) -> str:
        """Run the Claude conversation loop, handling tool use blocks.

        Continues calling the API until the model returns a text-only response
        (no tool_use blocks) or the budget / stop event triggers.
        """
        max_tool_rounds = 25  # safety cap to avoid infinite loops

        for _round in range(max_tool_rounds):
            self._check_stop()
            self._check_budget(phase_name)

            response = self._call_api(messages, phase_name)

            # Separate text blocks from tool_use blocks
            text_parts: list[str] = []
            tool_use_blocks: list[Any] = []

            for block in response.content:
                if block.type == "text":
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    tool_use_blocks.append(block)

            # If there are no tool_use blocks, we're done
            if not tool_use_blocks:
                return "\n".join(text_parts)

            # If no dispatcher configured, just return the text we have
            if not self._tool_dispatcher:
                logger.warning(
                    "Model requested tool use but no dispatcher configured — "
                    "returning text portion only."
                )
                return "\n".join(text_parts) if text_parts else ""

            # Append the assistant's response to the conversation
            messages.append({"role": "assistant", "content": response.content})

            # Process each tool use and build tool results
            tool_results: list[dict[str, Any]] = []
            for tool_block in tool_use_blocks:
                self._check_stop()
                tool_name = tool_block.name
                tool_input = tool_block.input
                logger.info(
                    "[%s] Tool call: %s(%s)",
                    phase_name,
                    tool_name,
                    list(tool_input.keys()),
                )

                try:
                    result = self._tool_dispatcher.dispatch(tool_name, tool_input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_block.id,
                        "content": _format_tool_result(result),
                    })
                except Exception as exc:
                    logger.error(
                        "[%s] Tool %s failed: %s", phase_name, tool_name, exc
                    )
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_block.id,
                        "content": f"Error: {exc}",
                        "is_error": True,
                    })

            # Feed tool results back as the next user message
            messages.append({"role": "user", "content": tool_results})

        # Exhausted tool rounds — return whatever text we accumulated
        logger.warning(
            "[%s] Reached max tool rounds (%d) — returning partial response.",
            phase_name,
            max_tool_rounds,
        )
        return "\n".join(text_parts) if text_parts else ""

    # --------------------------------------------------------------------- #
    # API call with retry                                                     #
    # --------------------------------------------------------------------- #

    def _call_api(
        self,
        messages: list[dict[str, Any]],
        phase_name: str,
    ) -> Any:
        """Call the Anthropic API with exponential-backoff retry."""
        last_exc: Exception | None = None

        for attempt, delay in enumerate(
            _RETRY_BASE_DELAYS + [0], start=1
        ):
            self._check_stop()
            self._check_budget(phase_name)

            t0 = time.monotonic()
            try:
                kwargs: dict[str, Any] = {
                    "model": _MODEL,
                    "max_tokens": _MAX_TOKENS,
                    "messages": messages,
                }
                if self._system_prompt:
                    kwargs["system"] = self._system_prompt
                if self._tools:
                    kwargs["tools"] = self._tools

                response = self.client.messages.create(**kwargs)

                elapsed = time.monotonic() - t0
                self._account(response, phase_name, elapsed)
                return response

            except _RETRYABLE_EXCEPTIONS as exc:
                last_exc = exc
                if delay == 0:
                    # Last attempt — no more retries
                    break
                logger.warning(
                    "[%s] API error (attempt %d/%d): %s — retrying in %ds",
                    phase_name,
                    attempt,
                    len(_RETRY_BASE_DELAYS),
                    exc,
                    delay,
                )
                time.sleep(delay)

        raise RuntimeError(
            f"Claude API call failed after {len(_RETRY_BASE_DELAYS)} retries: "
            f"{last_exc}"
        ) from last_exc

    # --------------------------------------------------------------------- #
    # Budget tracking                                                         #
    # --------------------------------------------------------------------- #

    def _account(self, response: Any, phase_name: str, elapsed: float) -> None:
        """Update running cost from API response usage and emit events."""
        usage = response.usage
        input_tokens = usage.input_tokens
        output_tokens = usage.output_tokens

        call_cost = (input_tokens * _INPUT_PRICE) + (output_tokens * _OUTPUT_PRICE)

        with self._budget_lock:
            self.total_cost_usd += call_cost

        logger.info(
            "[%s] tokens_in=%d  tokens_out=%d  cost=$%.4f  total=$%.4f  elapsed=%.1fs",
            phase_name,
            input_tokens,
            output_tokens,
            call_cost,
            self.total_cost_usd,
            elapsed,
        )

        # Push events for the GUI
        if self._event_queue is not None:
            self._event_queue.put(
                BudgetEvent(
                    total_cost_usd=self.total_cost_usd,
                    phase_name=phase_name,
                )
            )

    def _check_budget(self, phase_name: str) -> None:
        """Raise ``BudgetExhaustedError`` if the spend cap is exceeded."""
        with self._budget_lock:
            if self.total_cost_usd >= self.max_budget_usd:
                raise BudgetExhaustedError(self.total_cost_usd, self.max_budget_usd)

    # --------------------------------------------------------------------- #
    # Stop-event propagation                                                  #
    # --------------------------------------------------------------------- #

    def _check_stop(self) -> None:
        """Raise ``PipelineAbortedError`` if the user requested a stop."""
        if self._stop_event is not None and self._stop_event.is_set():
            raise PipelineAbortedError("Pipeline aborted by user.")

    # --------------------------------------------------------------------- #
    # Context-window guard                                                    #
    # --------------------------------------------------------------------- #

    @staticmethod
    def _maybe_truncate(prompt: str) -> str:
        """Rough guard: truncate very large prompts to stay within context.

        Uses a ~4 chars/token heuristic.  If the prompt exceeds the
        estimated token budget, the tail is trimmed and a warning is logged.
        """
        estimated_tokens = len(prompt) // 4
        if estimated_tokens <= _MAX_PROMPT_TOKENS_ESTIMATE:
            return prompt

        # Trim from the end (skill reference material is appended last)
        max_chars = _MAX_PROMPT_TOKENS_ESTIMATE * 4
        logger.warning(
            "Prompt too large (~%d tokens, limit ~%d). Truncating tail.",
            estimated_tokens,
            _MAX_PROMPT_TOKENS_ESTIMATE,
        )
        return prompt[:max_chars] + "\n\n[... truncated to fit context window ...]"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format_tool_result(result: dict[str, Any]) -> str:
    """Convert a tool-dispatch result dict to a string for the API."""
    import json

    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, indent=2, default=str)
    except (TypeError, ValueError):
        return str(result)
