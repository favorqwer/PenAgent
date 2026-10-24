"""Phase configuration table.

Adding a phase = adding a row here plus one edge in the engagement graph.
The phase subgraph implementation is shared by all phases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from agent.settings import cfg


@dataclass(frozen=True)
class PhaseConfig:
    key: str
    name: str
    goal: str
    entry: str
    exit_success: str
    tools_hint: str
    allowed_tools: Tuple[str, ...]
    max_tasks: int
    max_steps: int
    next_phase: str


def _max_tasks(phase: str, fallback: int) -> int:
    table = cfg("budgets.max_tasks_per_phase", {}) or {}
    return int(table.get(phase, fallback))


PHASES: Dict[str, PhaseConfig] = {
    "collector": PhaseConfig(
        key="collector",
        name="Reconnaissance",
        goal=(
            "Discover every open port, running service, service version and operating-system "
            "signal on the target, and map the reachable attack surface."
        ),
        entry="Target is reachable; nothing is known yet (or only prior-session knowledge).",
        exit_success="Open ports are enumerated with service/version fingerprints for each.",
        tools_hint=(
            "nmap (port scanning, -sV, -O, NSE discovery), whois, dig, whatweb, curl -I, "
            "enum4linux / smbclient for SMB, searchsploit for fingerprints."
        ),
        allowed_tools=("execute_kali_command", "finish_task", "record_finding"),
        max_tasks=_max_tasks("collector", 3),
        max_steps=int(cfg("budgets.max_steps_per_task", 8)),
        next_phase="scanner",
    ),
    "scanner": PhaseConfig(
        key="scanner",
        name="Vulnerability Scanning",
        goal=(
            "Turn the observed services into concrete, testable entry points: known CVEs, "
            "misconfigurations, exposed paths, default credentials and weak authentication."
        ),
        entry="At least one open port with a service fingerprint is known.",
        exit_success="At least one concrete attack path is identified with evidence.",
        tools_hint=(
            "nmap NSE scripts, nikto, gobuster/dirb/ffuf, searchsploit, wpscan, whatweb, "
            "sslscan, curl for manual verification."
        ),
        allowed_tools=("execute_kali_command", "finish_task", "record_finding", "http_probe"),
        max_tasks=_max_tasks("scanner", 4),
        max_steps=int(cfg("budgets.max_steps_per_task", 8)),
        next_phase="exploiter",
    ),
    "exploiter": PhaseConfig(
        key="exploiter",
        name="Exploitation",
        goal=(
            "Exploit an identified weakness to obtain command execution, read a protected "
            "resource, or escalate privileges, and prove it with verifiable evidence."
        ),
        entry="At least one concrete attack path is known.",
        exit_success="Command execution or equivalent access is proven (uid=, root shell, flag).",
        tools_hint=(
            "curl PoC requests, searchsploit -m + python, metasploit (msfconsole), sqlmap, "
            "hydra, nc, custom python scripts. Always verify with id / whoami."
        ),
        allowed_tools=("execute_kali_command", "finish_task", "record_finding", "http_probe"),
        max_tasks=_max_tasks("exploiter", 5),
        max_steps=int(cfg("budgets.max_steps_per_task", 8)),
        next_phase="done",
    ),
}

PHASE_ORDER: List[str] = ["collector", "scanner", "exploiter"]


def get_phase(key: str) -> PhaseConfig:
    return PHASES[key]


def phase_max_tasks(key: str) -> int:
    table = cfg("budgets.max_tasks_per_phase", {}) or {}
    fallback = PHASES[key].max_tasks if key in PHASES else 3
    return int(table.get(key, fallback))


def phase_max_steps(key: str) -> int:
    return int(cfg("budgets.max_steps_per_task", PHASES[key].max_steps if key in PHASES else 8))


def next_phase_key(key: str) -> str:
    config = PHASES.get(key)
    return config.next_phase if config else "done"


def phase_index(key: str) -> int:
    return PHASE_ORDER.index(key) if key in PHASE_ORDER else len(PHASE_ORDER)
