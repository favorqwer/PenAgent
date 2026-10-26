"""Tool definitions and the single command-transport layer.

Five tools, bound per phase from a whitelist:

* ``execute_kali_command`` - one bounded command on Kali (SSH)
* ``http_probe``           - structured HTTP request via curl on Kali
* ``record_finding``       - explicit, model-driven fact recording
* ``read_artifact``        - read a slice of an on-target file
* ``finish_task``          - the agent declares the task finished (with evidence)

The transport at the top is the only place that talks to the SSH layer, so
`--dry-run` and tests can swap in a scripted shell.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from agent.findings import clip
from agent.settings import cfg

EXIT_STATUS = re.compile(r"\[Exit Status: (-?\d+)\]")
TIMED_OUT = re.compile(r"\[Command timed out after ([\d.]+)s\]")
FAILED_PREFIXES = ("Command execution failed:", "Command not allowed:")


# --- transport ------------------------------------------------------------

_OVERRIDE = None


def set_shell_override(shell) -> None:
    """Inject a scripted shell (dry-run and tests)."""
    global _OVERRIDE
    _OVERRIDE = shell


def reset_shell_override() -> None:
    global _OVERRIDE
    _OVERRIDE = None


def get_shell():
    if _OVERRIDE is not None:
        return _OVERRIDE
    from actions.shell_manager import ShellManager

    return ShellManager.get_instance().get_shell()


def default_timeout() -> int:
    """Operator-configured per-command cap (CLI --command-timeout)."""
    from actions.shell_manager import ShellManager

    return int(getattr(ShellManager, "command_timeout", 120) or 120)


def _transport_execute(command: str, timeout: Optional[float] = None) -> str:
    shell = get_shell()
    try:
        return shell.execute_cmd(command, timeout=timeout)
    except TypeError:
        # Any third-party shell stub that does not accept a timeout.
        return shell.execute_cmd(command)


def close_shell() -> None:
    if _OVERRIDE is None:
        from actions.shell_manager import ShellManager

        ShellManager.get_instance().close()


@dataclass
class ToolOutcome:
    """Structured result of one tool call.

    ``ok`` comes from the real exit code the SSH layer reported, not from
    keyword sniffing on the output: the shell appends ``[Exit Status: N]``
    exactly when a command failed.
    """

    text: str
    ok: bool
    exit_code: Optional[int] = None
    timed_out: bool = False
    duration: float = 0.0
    cached: bool = False
    error: str = ""
    payload: str = ""
    """Raw output without the elapsed/timeout suffix.

    Fingerprints and the repeat-command cache use this, otherwise a command that
    prints identical output twice would look different just because the elapsed
    time changed.
    """

    @property
    def status(self) -> str:
        return "success" if self.ok else "error"


def classify_shell_output(text: str) -> tuple:
    """(ok, exit_code, timed_out) from what the SSH layer returned."""
    text = text or ""
    timeout_match = TIMED_OUT.search(text)
    exit_match = EXIT_STATUS.search(text)
    exit_code = int(exit_match.group(1)) if exit_match else None
    if timeout_match:
        return False, exit_code, True
    if any(text.startswith(prefix) or prefix in text[:400] for prefix in FAILED_PREFIXES):
        return False, exit_code, False
    if exit_code is None:
        return True, 0, False
    return exit_code == 0, exit_code, False


def _limit() -> int:
    return int(cfg("context.max_tool_output", 6000))


class ExecuteInput(BaseModel):
    command: str = Field(
        ...,
        description="Exact shell command to run on Kali, e.g. 'nmap -sV -T4 100.84.151.2'",
    )
    intent: str = Field(
        default="",
        description="One short sentence: what this command is meant to prove or discover",
    )
    timeout: Optional[int] = Field(
        default=None,
        ge=5,
        le=900,
        description="Requested timeout (capped by the operator's --command-timeout)",
    )


@tool("execute_kali_command", args_schema=ExecuteInput)
def execute_kali_command(command: str, intent: str = "", timeout: Optional[int] = None) -> str:
    """Execute exactly one shell command on the remote Kali attack machine via SSH.

    Returns combined stdout/stderr. Interactive tools (msfconsole, ftp, smbclient)
    are handled automatically through a persistent PTY. Long output is truncated
    head+tail; run narrower commands instead of piping huge files.
    """
    return execute_shell(command, timeout=timeout).text


def execute_shell(command: str, timeout: Optional[int] = None) -> ToolOutcome:
    """Run one command and classify the result from its real exit status."""
    command = (command or "").strip()
    if not command:
        return ToolOutcome(text="Error executing command: empty command", ok=False, error="empty command")

    cap = default_timeout()
    effective = min(int(timeout) if timeout else cap, cap)
    started = time.time()
    raw = _transport_execute(command, timeout=effective)
    elapsed = round(time.time() - started, 2)
    output = (raw or "").strip()
    if len(output) > _limit():
        output = clip(output, _limit())
    text = f"{output}\n[elapsed: {elapsed}s, timeout: {effective}s]"
    ok, exit_code, timed_out = classify_shell_output(output)
    return ToolOutcome(
        text=text,
        ok=ok,
        exit_code=exit_code,
        timed_out=timed_out,
        duration=elapsed,
        error="timed out" if timed_out else ("" if ok else f"exit {exit_code}" if exit_code else "failed"),
        payload=output,
    )


class HttpInput(BaseModel):
    url: str = Field(..., description="Full URL including scheme, e.g. http://100.84.151.2/admin/")
    method: str = Field(default="GET", description="HTTP method")
    data: Optional[str] = Field(default=None, description="Request body (form or raw string)")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Extra request headers")
    timeout: int = Field(default=30, ge=5, le=120, description="HTTP timeout, capped by --command-timeout")


def _quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


@tool("http_probe", args_schema=HttpInput)
def http_probe(
    url: str,
    method: str = "GET",
    data: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
) -> str:
    """Send one HTTP request from Kali using curl and return status line, headers and body.

    Use this instead of shell-quoting curl yourself. Follow redirects off by default,
    disable certificate verification, and cap the output size.
    """
    return http_request(url, method=method, data=data, headers=headers, timeout=timeout).text


def http_request(
    url: str,
    method: str = "GET",
    data: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
) -> ToolOutcome:
    parts = ["curl", "-sS", "-i", "-k", "--max-time", str(timeout), "-X", method.upper(), _quote(url)]
    for key, value in (headers or {}).items():
        parts += ["-H", _quote(f"{key}: {value}")]
    if data is not None:
        parts += ["--data", _quote(data)]
    cap = default_timeout()
    effective = min(timeout + 10, cap)
    command = " ".join(parts) + " | head -c 12000"
    started = time.time()
    output = (_transport_execute(command, timeout=effective) or "").strip()
    elapsed = round(time.time() - started, 2)
    text = clip(output, _limit())
    failed = not text or "curl: (" in text
    return ToolOutcome(
        text=text,
        ok=not failed,
        exit_code=None if failed else 0,
        duration=elapsed,
        error="curl error" if failed else "",
        payload=text,
    )


class FindingInput(BaseModel):
    kind: Literal["port", "service", "vulnerability", "credential", "flag", "note"] = Field(
        ..., description="Type of finding"
    )
    identifier: str = Field(..., description="Port number, CVE id, URL path, credential or flag")
    description: str = Field(default="", description="What was observed and why it matters")
    confidence: Literal["confirmed", "probable", "tentative"] = Field(default="probable")


@tool("record_finding", args_schema=FindingInput)
def record_finding(
    kind: str,
    identifier: str,
    description: str = "",
    confidence: str = "probable",
) -> str:
    """Persist a factual discovery so later phases and the final report can use it.

    Record only what you actually observed in command output.
    """
    return f"recorded {kind}: {identifier}"


class ReadArtifactInput(BaseModel):
    path: str = Field(..., description="Path to file on Kali attack machine or local logs, e.g. /tmp/scan.nmap")
    lines: int = Field(default=60, description="Max lines to read")
    offset: int = Field(default=0, description="Start line offset (0-indexed)")


def artifact_command(path: str, lines: int = 60, offset: int = 0) -> str:
    """Shell command that reads a slice of an artifact on Kali.

    Shared by the tool, the executor and the action log so the command that is
    *displayed* is the command that actually runs.
    """
    return f"sed -n '{offset + 1},{offset + lines}p' {path} 2>/dev/null || head -n {lines} {path}"


@tool("read_artifact", args_schema=ReadArtifactInput)
def read_artifact(path: str, lines: int = 60, offset: int = 0) -> str:
    """Read a segment of a local scan report or output file without spending a full bash execution."""
    return execute_shell(artifact_command(str(path).strip(), lines, offset)).text


class FinishInput(BaseModel):
    success: bool = Field(..., description="True only if the task objective was achieved")
    summary: str = Field(..., description="One or two sentences describing the outcome")
    evidence: str = Field(
        default="",
        description="Verbatim decisive output proving the outcome (e.g. 'uid=0(root) gid=0(root)')",
    )


@tool("finish_task", args_schema=FinishInput)
def finish_task(success: bool, summary: str, evidence: str = "") -> str:
    """Declare the current task finished. This does not execute anything.

    Call it exactly once, after you have enough evidence. Never claim success
    without quoting evidence from the observations.
    """
    return "acknowledged"


ALL_TOOLS = {
    "execute_kali_command": execute_kali_command,
    "http_probe": http_probe,
    "record_finding": record_finding,
    "read_artifact": read_artifact,
    "finish_task": finish_task,
}


def run_tool(name: str, args: Dict[str, Any]) -> ToolOutcome:
    """Single entry point for the execution node, returning structured results."""
    if name == "execute_kali_command":
        return execute_shell(str(args.get("command", "")), timeout=args.get("timeout"))
    if name == "http_probe":
        return http_request(
            str(args.get("url", "")),
            method=str(args.get("method", "GET")),
            data=args.get("data"),
            headers=args.get("headers"),
            timeout=int(args.get("timeout") or 30),
        )
    if name == "read_artifact":
        path = str(args.get("path", "")).strip()
        lines = int(args.get("lines", 60))
        offset = int(args.get("offset", 0))
        return execute_shell(artifact_command(path, lines, offset))
    return ToolOutcome(text=f"Unknown tool: {name}", ok=False, error="unknown tool")


def tools_for_phase(allowed: List[str]) -> List:
    return [ALL_TOOLS[name] for name in allowed if name in ALL_TOOLS]


def tool_names(allowed: List[str]) -> str:
    return ", ".join(name for name in allowed if name in ALL_TOOLS)
