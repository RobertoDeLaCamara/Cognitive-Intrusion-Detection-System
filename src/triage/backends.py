"""LLM backends for the triage agent.

:class:`ClaudeCLIBackend` drives Claude Code in non-interactive mode
(``claude -p``), the same agent loop the CLI uses, with structured output
enforced by ``--json-schema``. Least privilege is set on the command line:

* ``--tools ""`` removes every built-in tool (shell, files, web);
* in ``workflow`` mode MCP tools are removed too (``--disallowedTools mcp__*``);
* in ``agent`` mode the only tools are the read-only ``cnds`` MCP server,
  loaded with ``--strict-mcp-config`` so no other server leaks in;
* ``--max-budget-usd`` caps the spend of a single triage call, and
  ``--no-session-persistence`` keeps alert data out of local transcripts;
* the process runs in an empty temporary directory, so nothing in the repo
  (``.env``, ``CLAUDE.md``) is reachable or loaded;
* ``--permission-mode dontAsk`` denies anything that would need approval.

Anything that implements :class:`TriageBackend` can replace it (tests use a
static backend; a local model behind the same contract is a later option).
"""

import asyncio
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from .schema import OUTPUT_SCHEMA

logger = logging.getLogger(__name__)


@dataclass
class BackendResult:
    output: Optional[Dict[str, Any]]          # parsed structured output, or None
    model: Optional[str] = None
    cost_usd: Optional[float] = None
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


class TriageBackend(Protocol):
    name: str

    async def run(self, prompt: str, mode: str) -> BackendResult: ...


def build_cli_command(
    mode: str,
    claude_bin: str = "claude",
    model: str = "",
    bare: bool = True,
    max_turns: int = 8,
    mcp_config: str = "",
    max_budget_usd: float = 0.25,
) -> List[str]:
    """Return the argv for one triage call. The prompt goes on stdin."""
    if mode not in ("workflow", "agent"):
        raise ValueError(f"unknown triage mode {mode!r}")
    if mode == "agent" and not mcp_config:
        raise ValueError("agent mode requires TRIAGE_MCP_CONFIG (cnds MCP server config)")

    cmd = [claude_bin]
    if bare:
        cmd.append("--bare")
    cmd += [
        "-p",
        "--output-format", "json",
        "--json-schema", json.dumps(OUTPUT_SCHEMA, separators=(",", ":")),
        "--tools", "",
        "--permission-mode", "dontAsk",
        "--max-turns", str(int(max_turns)),
        "--max-budget-usd", f"{float(max_budget_usd):.2f}",
        "--no-session-persistence",
    ]
    if model:
        cmd += ["--model", model]
    if mode == "agent":
        cmd += [
            "--mcp-config", mcp_config,
            "--strict-mcp-config",
            "--allowedTools", "mcp__cnds",
        ]
    else:
        cmd += ["--disallowedTools", "mcp__*"]
    return cmd


def parse_cli_output(stdout: str) -> BackendResult:
    """Parse ``claude -p --output-format json`` output into a BackendResult."""
    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        return BackendResult(output=None, error=f"unparseable CLI output: {exc}")

    if not isinstance(payload, dict):
        return BackendResult(output=None, error="CLI output is not a JSON object")

    cost = payload.get("total_cost_usd")
    duration = payload.get("duration_ms")
    model = None
    usage = payload.get("modelUsage") or payload.get("model_usage")
    if isinstance(usage, dict) and usage:
        model = next(iter(usage))

    if payload.get("is_error"):
        return BackendResult(
            output=None, model=model, cost_usd=cost, duration_ms=duration,
            error=str(payload.get("result") or payload.get("subtype") or "CLI reported an error")[:500],
            raw=payload,
        )

    output = payload.get("structured_output")
    if output is None:
        # Fall back to a JSON object in the text result (older CLI versions).
        try:
            output = json.loads(payload.get("result") or "")
        except (json.JSONDecodeError, TypeError):
            return BackendResult(
                output=None, model=model, cost_usd=cost, duration_ms=duration,
                error="no structured_output in CLI result", raw=payload,
            )

    return BackendResult(output=output, model=model, cost_usd=cost, duration_ms=duration, raw=payload)


class ClaudeCLIBackend:
    """Run one triage call through ``claude -p`` in a throwaway directory."""

    name = "claude-cli"

    def __init__(
        self,
        claude_bin: str = "claude",
        model: str = "",
        bare: bool = True,
        max_turns: int = 8,
        timeout_secs: int = 180,
        mcp_config: str = "",
        max_budget_usd: float = 0.25,
    ) -> None:
        self.claude_bin = claude_bin
        self.model = model
        self.bare = bare
        self.max_turns = max_turns
        self.timeout_secs = timeout_secs
        self.mcp_config = mcp_config
        self.max_budget_usd = max_budget_usd

    async def run(self, prompt: str, mode: str) -> BackendResult:
        cmd = build_cli_command(
            mode, self.claude_bin, self.model, self.bare, self.max_turns,
            self.mcp_config, self.max_budget_usd,
        )
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="cnds-triage-") as workdir:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=workdir,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=os.environ.copy(),
                )
            except FileNotFoundError:
                return BackendResult(output=None, error=f"claude binary not found: {self.claude_bin}")

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(prompt.encode()), timeout=self.timeout_secs
                )
            except asyncio.TimeoutError:
                proc.terminate()
                await proc.wait()
                return BackendResult(
                    output=None, error=f"timeout after {self.timeout_secs}s",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )

        result = parse_cli_output(stdout.decode(errors="replace"))
        if result.duration_ms is None:
            result.duration_ms = int((time.monotonic() - started) * 1000)
        if proc.returncode != 0 and result.error is None and result.output is None:
            result.error = f"claude exited {proc.returncode}: {stderr.decode(errors='replace')[-300:]}"
        return result


class StaticBackend:
    """Returns a fixed answer. For tests and dry runs."""

    name = "static"

    def __init__(self, output: Optional[Dict[str, Any]] = None, error: Optional[str] = None,
                 cost_usd: float = 0.0) -> None:
        self.output = output
        self.error = error
        self.cost_usd = cost_usd
        self.prompts: List[str] = []

    async def run(self, prompt: str, mode: str) -> BackendResult:
        self.prompts.append(prompt)
        return BackendResult(
            output=self.output, error=self.error, model="static",
            cost_usd=self.cost_usd, duration_ms=0,
        )
