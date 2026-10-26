"""Command risk classification, safety guardrails, and HITL policy.

Two core execution modes:
1. Autonomous Mode (default): Zero-friction execution with a strict hard kill-switch
   for destructive commands (rm -rf, DROP TABLE, mkfs, iptables -F, etc.).
2. Supervised Mode (--hitl): Step-by-step confirmation for every command.
"""

from __future__ import annotations

import re
from typing import List, Tuple

RISK_SAFE = "safe"
RISK_READ = "read"
RISK_PROBE = "probe"
RISK_INTRUSIVE = "intrusive"
RISK_DESTRUCTIVE = "destructive"
RISK_UNKNOWN = "unknown"

RISK_ORDER = [RISK_SAFE, RISK_READ, RISK_PROBE, RISK_INTRUSIVE, RISK_DESTRUCTIVE, RISK_UNKNOWN]

# Hard kill-switch: catastrophic commands strictly forbidden under all modes
DESTRUCTIVE_REGEX = re.compile(
    r"\brm\s+-[rf]"
    r"|\bmkfs\b"
    r"|\bdd\s+if="
    r"|\b(?:shutdown|reboot|poweroff|init\s+0)\b"
    r"|\biptables\s+-F\b"
    r"|\bDROP\s+(?:TABLE|DATABASE)\b"
    r"|\bTRUNCATE\s+TABLE\b"
    r"|:\(\)\s*\{.*\}\s*;\s*:"  # fork bomb
    r"|>\s*/etc/"
    r"|\bchmod\s+000\b"
    r"|\bkill\s+-9\s+1\b",
    re.IGNORECASE,
)

DESTRUCTIVE_PATTERNS = (
    r"\brm\s+-[rf]",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bpoweroff\b",
    r"\binit\s+0\b",
    r"\biptables\s+-F\b",
    r"\bDROP\s+(TABLE|DATABASE)\b",
    r"\bTRUNCATE\s+TABLE\b",
    r":\(\)\s*\{.*\}\s*;\s*:",
    r">\s*/etc/",
    r"\bchmod\s+000\b",
    r"\bkill\s+-9\s+1\b",
)

READ_TOOLS = {
    "whois", "dig", "host", "nslookup", "ping", "traceroute", "id", "whoami",
    "uname", "hostname", "ls", "cat", "pwd", "env", "ps", "netstat", "ss",
    "searchsploit", "curl", "wget", "whatweb", "nmap", "ip", "ifconfig",
    "route", "arp", "getent", "echo", "which", "find", "head", "tail", "grep",
    "awk", "sed", "sort", "uniq", "wc", "file", "strings", "dpkg",
}

PROBE_TOOLS = {
    "gobuster", "dirb", "ffuf", "nikto", "wfuzz", "feroxbuster", "enum4linux",
    "smbclient", "smbmap", "nbtscan", "dnsenum", "fierce", "amass", "dmitry",
    "sslscan", "testssl", "tcpdump", "tshark", "wpscan", "droopescan",
}

INTRUSIVE_TOOLS = {
    "hydra", "medusa", "ncrack", "john", "hashcat", "sqlmap", "msfconsole",
    "msfvenom", "nc", "ncat", "netcat", "socat", "impacket-", "responder",
    "weevely", "metasploit", "armitage", "crackmapexec", "evil-winrm",
    "psexec", "chisel", "ligolo", "sshpass",
}

SUDO = re.compile(r"(^|\s)sudo\s+")
SHELL_SPLIT = re.compile(r"(\|\||&&|[|;`]|\$\()")


def is_destructive(command: str) -> bool:
    """True if command matches any unrecoverable system destruction pattern."""
    return bool(DESTRUCTIVE_REGEX.search(command or ""))


def _segments(command: str) -> List[str]:
    text = SUDO.sub(" ", command or "")
    text = text.replace("$(", " ")
    parts = [p.strip() for p in SHELL_SPLIT.split(text) if p and p.strip()]
    return [p for p in parts if p not in ("||", "&&", "|", ";", "`")]


def _first_token(segment: str) -> str:
    token = segment.split()[0] if segment.split() else ""
    return token.rsplit("/", 1)[-1].lower()


def classify_command(command: str) -> Tuple[str, str]:
    """Classify command risk level. Higher risk wins across piped segments."""
    command = (command or "").strip()
    if not command:
        return RISK_UNKNOWN, "empty command"

    if is_destructive(command):
        return RISK_DESTRUCTIVE, "high impact command"

    lowered = command.lower()
    if "nmap" in lowered and "--script" in lowered:
        if any(w in lowered for w in ("exploit", "vuln", "dos", "fuzzer", "attack")):
            return RISK_INTRUSIVE, "nmap with intrusive/exploit NSE scripts"
        return RISK_PROBE, "nmap NSE scripts"

    if re.search(r"\b(python\d?|bash|sh|perl|ruby|php)\b.*?(?:exploit|poc|payload|attack)", lowered):
        return RISK_INTRUSIVE, "script interpreter executing exploit/payload file"

    if lowered.startswith("curl") and re.search(
        r"(\s-x\s|\s-d\s|--data|--upload-file|\s-t\s|\s-f\s|\s-u\s|--user|--cookie)",
        lowered,
    ):
        return RISK_INTRUSIVE, "curl with data/upload/credentials"

    worst = RISK_READ
    reason = "read-only"
    segments = _segments(command) or [command]
    for segment in segments:
        token = _first_token(segment)
        if not token:
            continue
        if any(token.startswith(tool) for tool in INTRUSIVE_TOOLS):
            return RISK_INTRUSIVE, f"intrusive tool: {token}"
        if token in PROBE_TOOLS:
            if RISK_ORDER.index(RISK_PROBE) > RISK_ORDER.index(worst):
                worst, reason = RISK_PROBE, f"probe tool: {token}"
            continue
        if token in READ_TOOLS:
            continue
        return RISK_UNKNOWN, f"unclassified command: {token}"

    return worst, reason


def requires_approval(risk: str, auto_approve: List[str] = None) -> bool:
    """In HITL mode, determine if the command requires operator confirmation."""
    if auto_approve is None:
        return True
    return risk not in set(auto_approve)


def describe_risk(risk: str) -> str:
    return {
        RISK_SAFE: "safe (read-only reconnaissance)",
        RISK_READ: "read-only (no state change)",
        RISK_PROBE: "active probing (no exploitation)",
        RISK_INTRUSIVE: "intrusive (credentials/exploit traffic)",
        RISK_DESTRUCTIVE: "high impact (system state change)",
        RISK_UNKNOWN: "unclassified (requires approval)",
    }.get(risk, risk)
