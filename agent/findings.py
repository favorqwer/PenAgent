"""Deterministic fact extraction.

This module only *extracts* and *quotes*: ports, services, CVEs, flags, root
proof, and compact digests of long output. It never decides whether a task
succeeded - that judgement belongs to the evaluator model, because penetration
results are too varied for a closed rule set (a scan that finds nothing is a
valid answer, a page body can contain "permission denied", and so on).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

PORT_LINE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\s*(.*)$", re.MULTILINE)
GNMAP_PORT = re.compile(r"(\d{1,5})/open/(?:tcp|udp)")
SERVICE_LINE = re.compile(r"^(\d{1,5})/tcp\s+open\s+(\S+)\s*(.*)$", re.MULTILINE)
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
FLAG = re.compile(r"flag\{[^}]{4,}\}", re.IGNORECASE)
UID = re.compile(r"uid=(\d+)\(([^)]*)\)")
ROOT_PROMPT = re.compile(r"^(?:root@|#\s)", re.MULTILINE)
SERVER_HEADER = re.compile(r"^Server:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
HTTP_STATUS = re.compile(r"^HTTP/\d\.\d\s+(\d{3})", re.MULTILINE)
DIR_HIT = re.compile(r"^\s*(/\S+)\s+\(Status:\s*(\d{3})\)", re.MULTILINE)
HTML_TITLE = re.compile(r"<title>([^<]{2,120})</title>", re.IGNORECASE)


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


def render_facts(
    state: Dict[str, Any],
    limit: int = 12000,
    include_tried: bool = True,
    ports: Optional[Iterable[int]] = None,
) -> str:
    """Render the fact table for a prompt.

    ``ports`` narrows the service list to what a task actually targets; pushing
    the whole table into every task prompt was the main context cost.
    """
    wanted = {str(port) for port in (ports or []) if str(port).isdigit()}
    lines: List[str] = []
    all_ports = state.get("open_ports") or []
    if all_ports:
        lines.append(f"Open ports: {sorted(all_ports)}")
        if wanted:
            narrowed = sorted(int(p) for p in all_ports if str(p) in wanted)
            if narrowed:
                lines.append(f"Ports this task targets: {narrowed}")
    services = state.get("services") or {}
    if services:
        lines.append("Services:")
        for port in sorted(services, key=lambda p: int(p) if str(p).isdigit() else 0):
            if wanted and str(port) not in wanted:
                continue
            info = services[port]
            if isinstance(info, str):
                info = {"service": info}
            banner = info.get("banner") or ""
            lines.append(f"  - {port}/tcp {info.get('service', '?')} {banner}".rstrip())
    vulns = state.get("vulnerabilities") or []
    if vulns:
        lines.append("Findings:")
        for vuln in vulns[:8]:
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
