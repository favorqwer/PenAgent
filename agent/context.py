"""Context budget: what the model gets to see.

Three responsibilities, all about one observation's journey into a prompt:

* trim the transcript to the configured character/message budget;
* compress one long observation to head + signal lines + tail;
* archive the raw output when it is too long to keep.

Nothing here decides anything - it only shapes text.
"""

from __future__ import annotations

import re
import time
import uuid
from pathlib import Path
from typing import Any, List

from langchain_core.messages import HumanMessage

from agent.findings import CVE, FLAG, GNMAP_PORT, PORT_LINE, UID, clip
from utils.log_common import build_logger

logger = build_logger()

# Lines that by themselves prove a result; kept when a long output is compressed.
DECISIVE_LINE = re.compile(
    r"uid=\d+\(|flag\{|root@[\w\-]+:.*#|meterpreter\s*>"
    r"|\d{1,5}/(?:tcp|udp)\s+open"
    r"|CVE-\d{4}-\d{4,7}"
    r"|^\s*/\S+\s+\(Status:\s*\d{3}\)",
    re.IGNORECASE | re.MULTILINE,
)

HINT_LINE = re.compile(
    r"^(?:HTTP/\d(?:\.\d)?\s+\d{3}|Server:\s*\S|Location:\s*\S|Set-Cookie:\s*\S)",
    re.MULTILINE | re.IGNORECASE,
)

HIGH_SIGNAL_PATTERN = re.compile(
    r"^\+\s+|\[[\+\!\*\$i]\]|[\[\(]Status:\s*\d{3}|\bCODE:\d{3}\b|\[\d{3}\s+OK\]"
    r"|\bHTTP/\d(?:\.\d)?\s+\d{3}\b|\bServer:\s*\S+"
    r"|\b(?:open|filtered)\s+port|\d{1,5}/(?:tcp|udp)\s+(?:open|filtered)"
    r"|\|\s+[\w\-/]+\.(?:py|sh|c|txt|rb|pl)\b"
    r"|\b(?:login|password|passwd|credential|token|flag\{|uid=\d+\(|cve-\d{4}-\d+)\b"
    r"|\b(?:vulnerab\w*|exploit\w*|injection|back-end DBMS)\b",
    re.IGNORECASE,
)


def _message_size(message: Any) -> int:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        size = len(content)
    elif isinstance(content, list):
        size = sum(len(str(part)) for part in content)
    else:
        size = len(str(content))
    for call in getattr(message, "tool_calls", None) or []:
        size += len(str(call.get("args") or {}))
    return size


def trim_for_context(messages: List[Any], max_chars: int, max_messages: int) -> List[Any]:
    """Keep the system prompt, the task kickoff and the newest complete turns.

    A tool call and its observations are trimmed as one unit: dropping half of a
    pair makes the provider reject the request. Dropped calls are summarised in
    one note so the model still knows which commands it already ran.
    """
    if not messages or max_chars <= 0:
        return messages

    head: List[Any] = []
    index = 0
    while index < len(messages) and getattr(messages[index], "type", "") == "system":
        head.append(messages[index])
        index += 1
    if index < len(messages) and getattr(messages[index], "type", "") == "human":
        head.append(messages[index])
        index += 1

    units: List[List[Any]] = []
    current: List[Any] = []
    for message in messages[index:]:
        kind = getattr(message, "type", "")
        starts_turn = kind == "ai" and bool(getattr(message, "tool_calls", None))
        if starts_turn or kind in ("human", "system"):
            if current:
                units.append(current)
            current = [message]
        else:
            current.append(message)
    if current:
        units.append(current)

    kept: List[List[Any]] = []
    used = sum(_message_size(message) for message in head)
    count = len(head)
    for unit in reversed(units):
        size = sum(_message_size(message) for message in unit)
        if kept and (used + size > max_chars or count + len(unit) > max_messages):
            break
        used += size
        count += len(unit)
        kept.append(unit)
    kept.reverse()

    dropped = units[: len(units) - len(kept)]
    if not dropped:
        return head + [message for unit in kept for message in unit]

    commands: List[str] = []
    for unit in dropped:
        for message in unit:
            for call in getattr(message, "tool_calls", None) or []:
                if call.get("name") == "execute_kali_command":
                    commands.append(str((call.get("args") or {}).get("command", ""))[:120])
    note = f"[context trimmed] {len(dropped)} earlier turn(s) omitted to fit the budget."
    if commands:
        note += "\nCommands already executed (do NOT re-run):\n" + "\n".join(
            f"- {item}" for item in commands[-8:]
        )
    return head + [HumanMessage(content=note)] + [message for unit in kept for message in unit]


def observation_digest(text: str, limit: int = 1800) -> str:
    """Compress one long observation: head, high-signal lines, tail."""
    text = (text or "").strip()
    if len(text) <= limit:
        return text

    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if len(lines) <= 20:
        return clip(text, limit)

    head = lines[:8]
    tail = lines[-8:]
    middle = lines[8:-8]

    signals: List[str] = []
    for line in middle:
        if (
            HIGH_SIGNAL_PATTERN.search(line)
            or PORT_LINE.match(line)
            or GNMAP_PORT.search(line)
            or CVE.search(line)
            or FLAG.search(line)
            or UID.search(line)
            or DECISIVE_LINE.search(line)
            or HINT_LINE.match(line)
        ):
            signals.append(line)
            if len(signals) >= 40:
                break

    parts = head[:]
    if signals:
        parts.append(f"... [extracted {len(signals)} high-signal lines] ...")
        parts.extend(signals)
    else:
        parts.append(f"... [truncated {len(middle)} lines of low-signal output] ...")
    parts.extend(tail)

    assembled = "\n".join(parts)
    return clip(assembled, limit) + f"\n[digest: {len(text)} chars of raw output kept in state]"


def observations_digest(messages, limit: int = 8000) -> str:
    """Only factual material: tool outputs and the commands that produced them.

    Deliberately excludes assistant claims (finish_task evidence, reasoning text),
    otherwise a hallucinated "uid=0" would count as proof.
    """
    parts = []
    for message in messages or []:
        kind = getattr(message, "type", "")
        if kind == "tool":
            content = message.content if isinstance(message.content, str) else str(message.content)
            parts.append(content)
        elif kind == "ai":
            for call in getattr(message, "tool_calls", None) or []:
                if call.get("name") in ("execute_kali_command", "http_probe"):
                    args = call.get("args") or {}
                    parts.append("$ " + str(args.get("command") or args.get("url") or ""))
    return clip(chr(10).join(parts), limit)


def save_raw_log(phase: str, command: str, text: str) -> str:
    """Archive one raw observation; returns the path ("" when writing failed)."""
    log_dir = Path("data/raw_logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{phase or 'cmd'}_{int(time.time())}_{uuid.uuid4().hex[:6]}.log"
    path = log_dir / filename
    try:
        path.write_text(f"# Command: {command}\n# Phase: {phase}\n\n{text}", encoding="utf-8", errors="replace")
        return str(path)
    except Exception as exc:
        logger.warning(f"Failed to write raw command log {path}: {exc}")
        return ""
