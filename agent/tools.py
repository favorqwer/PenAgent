"""Tool definitions exposed to the execution agent.

Four tools, bound per phase from a whitelist:

* ``execute_kali_command`` - one bounded command on Kali (SSH)
* ``http_probe``           - structured HTTP request via curl on Kali
* ``record_finding``       - explicit, model-driven fact recording
* ``finish_task``          - the agent declares the task finished (with evidence)
"""

from __future__ import annotations

import time
from typing import Dict, List, Literal, Optional

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from agent import shell
from agent.findings import clip
from agent.settings import cfg


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
    command = (command or "").strip()
    if not command:
        return "Error executing command: empty command"
    cap = shell.default_timeout()
    effective = min(int(timeout) if timeout else cap, cap)
    started = time.time()
    output = shell.execute(command, timeout=effective)
    elapsed = round(time.time() - started, 2)
    output = (output or "").strip()
    if len(output) > _limit():
        output = clip(output, _limit())
    return f"{output}\n[elapsed: {elapsed}s, timeout: {effective}s]"


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
    parts = ["curl", "-sS", "-i", "-k", "--max-time", str(timeout), "-X", method.upper(), _quote(url)]
    for key, value in (headers or {}).items():
        parts += ["-H", _quote(f"{key}: {value}")]
    if data is not None:
        parts += ["--data", _quote(data)]
    cap = shell.default_timeout()
    effective = min(timeout + 10, cap)
    command = " ".join(parts) + " | head -c 12000"
    output = shell.execute(command, timeout=effective)
    return clip((output or "").strip(), _limit())


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
    "finish_task": finish_task,
}


def tools_for_phase(allowed: List[str]) -> List:
    return [ALL_TOOLS[name] for name in allowed if name in ALL_TOOLS]


def tool_names(allowed: List[str]) -> str:
    return ", ".join(name for name in allowed if name in ALL_TOOLS)
