"""Deterministic fact extraction and evidence checks.

This module is the "hard evidence" layer: it decides what is objectively true
from command output, independently of whatever the LLM claims.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

PORT_LINE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\s*(.*)$", re.MULTILINE)
GNMAP_PORT = re.compile(r"(\d{1,5})/open/(?:tcp|udp)")
SERVICE_LINE = re.compile(r"^(\d{1,5})/tcp\s+open\s+(\S+)\s*(.*)$", re.MULTILINE)
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
FLAG = re.compile(r"flag\{[^}]{4,}\}", re.IGNORECASE)
UID = re.compile(r"uid=(\d+)\(([^)]*)\)")
UID_ANY = re.compile(r"uid=\d+\(")
ROOT_PROMPT = re.compile(r"^(?:root@|#\s)", re.MULTILINE)
SERVER_HEADER = re.compile(r"^Server:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
HTTP_STATUS = re.compile(r"^HTTP/\d\.\d\s+(\d{3})", re.MULTILINE)
DIR_HIT = re.compile(r"^\s*(/\S+)\s+\(Status:\s*(\d{3})\)", re.MULTILINE)
HTML_TITLE = re.compile(r"<title>([^<]{2,120})</title>", re.IGNORECASE)

ERROR_MARKERS = (
    "command not found",
    "permission denied",
    "no such file or directory",
    "connection refused",
    "could not resolve",
    "network is unreachable",
    "operation timed out",
    "timed out",
    "error executing",
    "[stderr]",
    "[exit status:",
    "traceback (most recent call last)",
    "failed to connect",
    "authentication failed",
    "login incorrect",
)

# Commands whose failure is a legitimate reconnaissance answer, not an error.
BENIGN_EMPTY = ("nmap", "gobuster", "dirb", "nikto", "whatweb", "curl", "searchsploit")


def clip(text: str, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 2 :]
    return f"{head}\n... [truncated {len(text) - limit} chars] ...\n{tail}"


def _service_name(banner: str) -> str:
    parts = banner.strip().split()
    return parts[0] if parts else "unknown"


def extract_findings(
    output: str,
    command: str = "",
    phase: str = "",
) -> Dict[str, Any]:
    """Parse one command's output into a state delta."""
    output = output or ""
    ports: List[int] = []
    services: Dict[str, Dict[str, str]] = {}
    vulns: List[Dict[str, Any]] = []
    flags: List[str] = []
    credentials: List[str] = []

    for match in PORT_LINE.finditer(output):
        port = int(match.group(1))
        rest = (match.group(3) or "").strip()
        if port not in ports:
            ports.append(port)
        service = _service_name(rest)
        services[str(port)] = {
            "service": service,
            "banner": rest,
            "cpe": rest,
            "raw": match.group(0).strip(),
        }

    for match in SERVICE_LINE.finditer(output):
        port = match.group(1)
        name = match.group(2)
        version = (match.group(3) or "").strip()
        entry = services.setdefault(str(port), {})
        entry.setdefault("service", name)
        if version:
            entry["banner"] = version
            entry["cpe"] = version

    for header in SERVER_HEADER.findall(output):
        for port, entry in services.items():
            if str(entry.get("service", "")).lower() in ("http", "https") or "http" in str(entry.get("banner", "")).lower():
                entry.setdefault("banner", header.strip())
                break

    for cve in sorted({c.upper() for c in CVE.findall(output)}):
        vulns.append(
            {
                "cve": cve,
                "phase": phase,
                "command": command,
                "evidence": clip(output, 500),
            }
        )

    if "directory listing" in output.lower() or re.search(r"Index of /", output):
        vulns.append(
            {
                "name": "Directory listing enabled",
                "phase": phase,
                "command": command,
                "evidence": clip(output, 300),
            }
        )

    for path, status in DIR_HIT.findall(output):
        if status in ("200", "301", "302", "401", "403"):
            vulns.append(
                {
                    "name": f"Web path {path} (HTTP {status})",
                    "identifier": f"{path}:{status}",
                    "phase": phase,
                    "command": command,
                }
            )

    for found in FLAG.findall(output):
        flags.append(found)

    uid = UID.search(output)
    if uid and uid.group(1) == "0":
        credentials.append(f"root shell confirmed via: {uid.group(0)}")

    return {
        "open_ports": ports,
        "services": services,
        "vulnerabilities": vulns[:12],
        "flags": flags[:5],
        "credentials": credentials[:5],
    }


def has_execution_evidence(output: str) -> bool:
    output = output or ""
    return bool(
        UID_ANY.search(output)
        or FLAG.search(output)
        or re.search(r"meterpreter\s*>", output, re.IGNORECASE)
        or re.search(r"root@[\w\-]+:.*#", output)
    )


def has_compromise_evidence(output: str) -> bool:
    output = output or ""
    uid = UID.search(output)
    if uid and uid.group(1) == "0":
        return True
    if FLAG.search(output):
        return True
    if re.search(r"root@[\w\-]+:.*#", output):
        return True
    if re.search(r"meterpreter\s*>", output, re.IGNORECASE):
        return True
    return False


def has_error(output: str) -> bool:
    lowered = (output or "").lower()
    return any(marker in lowered for marker in ERROR_MARKERS)


def is_benign_empty(output: str, command: str) -> bool:
    """A scan that legitimately reports 'nothing found' is not a failure."""
    if not (output or "").strip():
        return False
    lowered = output.lower()
    if command and command.split()[0] in BENIGN_EMPTY:
        if "0 hosts up" in lowered or "no open ports" in lowered:
            return True
        if "0 / 0" in lowered and "found" in lowered:
            return True
    return False


def evidence_verdict(
    phase: str,
    action: str,
    output: str,
    command: str = "",
    digest: str = "",
) -> Dict[str, Any]:
    """Layer-2 of the verdict: objective checks on the raw output and transcript.

    ``digest`` matters because agents often redirect scanner output to files and
    only print a compact summary; evidence may live in either place.
    """
    output = output or ""
    haystack = output + chr(10) + (digest or "")

    if has_compromise_evidence(haystack):
        return {"passed": True, "kind": "compromise", "detail": "root/flag evidence"}
    if has_execution_evidence(haystack) and phase == "exploiter":
        return {"passed": True, "kind": "execution", "detail": "command execution evidence"}
    if has_error(output) and not is_benign_empty(output, command):
        return {"passed": False, "kind": "error", "detail": "error marker in output"}
    if phase == "exploiter":
        return {"passed": False, "kind": "no-compromise", "detail": "no uid=0/flag evidence"}
    if phase == "collector":
        if PORT_LINE.search(haystack) or GNMAP_PORT.search(haystack):
            return {"passed": True, "kind": "ports", "detail": "port table parsed"}
        if is_benign_empty(output, command):
            return {"passed": True, "kind": "empty-scan", "detail": "valid empty scan result"}
    if phase == "scanner":
        if CVE.search(haystack) or DIR_HIT.search(haystack) or HTML_TITLE.search(haystack):
            return {"passed": True, "kind": "vuln-signal", "detail": "vulnerability signal"}
        if is_benign_empty(output, command):
            return {"passed": True, "kind": "empty-scan", "detail": "valid empty scan result"}
    return {"passed": False, "kind": "inconclusive", "detail": "no positive evidence"}


def summarize_text(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return clip(text, limit)


def render_facts(state: Dict[str, Any], limit: int = 12000, include_tried: bool = True) -> str:
    lines: List[str] = []
    ports = state.get("open_ports") or []
    if ports:
        lines.append(f"Open ports: {sorted(ports)}")
    services = state.get("services") or {}
    if services:
        lines.append("Services:")
        for port in sorted(services, key=lambda p: int(p) if str(p).isdigit() else 0):
            info = services[port]
            if isinstance(info, str):
                info = {"service": info}
            banner = info.get("banner") or ""
            lines.append(f"  - {port}/tcp {info.get('service', '?')} {banner}".rstrip())
    vulns = state.get("vulnerabilities") or []
    if vulns:
        lines.append("Findings:")
        for vuln in vulns[:12]:
            label = vuln.get("cve") or vuln.get("name") or vuln.get("identifier") or "finding"
            detail = vuln.get("evidence") or ""
            lines.append(f"  - {label} {('| ' + detail[:160]) if detail else ''}".rstrip())
    creds = state.get("credentials") or []
    if creds:
        lines.append(f"Credentials/access: {creds}")
    flags = state.get("flags") or []
    if flags:
        lines.append(f"Flags captured: {flags}")
    tried = state.get("tried_vectors") or []
    if tried and include_tried:
        lines.append("Already attempted and failed (do NOT repeat):")
        for item in tried[-12:]:
            lines.append(f"  - {item}")
    if state.get("is_compromised"):
        lines.append("Status: TARGET COMPROMISED")
    text = "\n".join(lines) or "No findings yet."
    return clip(text, limit)


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


def transcript_digest(messages, limit: int = 8000) -> str:
    """Compact an LLM message list into an evidence transcript."""
    lines: List[str] = []
    for message in messages or []:
        kind = getattr(message, "type", "")
        if kind == "ai":
            for call in getattr(message, "tool_calls", None) or []:
                args = call.get("args") or {}
                name = call.get("name")
                if name == "finish_task":
                    lines.append(f"[finish_task] {args}")
                elif name == "execute_kali_command":
                    lines.append(f"$ {args.get('command', '')}")
                elif name == "record_finding":
                    lines.append(f"[record_finding] {args}")
                elif name == "http_probe":
                    lines.append(f"[http] {args.get('method', 'GET')} {args.get('url', '')}")
            if isinstance(message.content, str) and message.content.strip():
                lines.append(f"[assistant] {message.content.strip()[:600]}")
        elif kind == "tool":
            content = message.content if isinstance(message.content, str) else str(message.content)
            lines.append(f"  -> {content.strip()[:1500]}")
        elif kind == "human":
            content = message.content if isinstance(message.content, str) else str(message.content)
            lines.append(f"[instruction] {content.strip()[:800]}")
    return clip("\n".join(lines), limit)
