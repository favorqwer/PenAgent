"""Phase configuration table.

Adding a phase = adding a row here plus one edge in the engagement graph.
The phase subgraph implementation is shared by all phases.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from agent.schema import TaskSpec
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
        allowed_tools=("execute_kali_command", "finish_task", "record_finding", "read_artifact"),
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
        allowed_tools=("execute_kali_command", "finish_task", "record_finding", "http_probe", "read_artifact"),
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
        allowed_tools=("execute_kali_command", "finish_task", "record_finding", "http_probe", "read_artifact"),
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


def budget_hit(state: Dict[str, Any]) -> str:
    """Why the engagement must stop, or "" while there is budget left."""
    deadline = float(state.get("deadline_ts") or 0)
    if deadline and time.time() > deadline:
        return "deadline"
    used = int(state.get("commands_used", 0))
    if used >= int(state.get("max_commands", 250)):
        return "command budget"
    allowance = int(state.get("phase_allowance") or 0)
    start = int(state.get("phase_start_commands") or 0)
    if allowance and used - start >= allowance:
        return "phase command budget"
    return ""


def phase_index(key: str) -> int:
    return PHASE_ORDER.index(key) if key in PHASE_ORDER else len(PHASE_ORDER)


# --- fallback plans -------------------------------------------------------
# Used only when the planner call fails. One implementation, so the two paths
# cannot drift apart: derive tasks from the facts we already have, otherwise
# fall back to the phase template.

_DEFAULT_ROWS: Dict[str, List[Tuple[str, List[str], str, str]]] = {
    "collector": [
        ("t1", [], "对 {target} 做全端口扫描，找出所有开放端口", "Shell"),
        ("t2", ["t1"], "对 {target} 上已开放的端口做服务与版本识别", "Enumerate"),
    ],
    "scanner": [
        ("t1", [], "检索 {target} 上已知服务版本对应的公开漏洞与利用方式", "Enumerate"),
        ("t2", [], "对 {target} 的 Web 端口做目录与敏感路径枚举", "Web"),
    ],
    "exploiter": [
        ("t1", [], "利用 {target} 上最可能的漏洞并验证命令执行", "Exploit"),
    ],
}


def _service_label(info: Any) -> str:
    if isinstance(info, dict):
        info = info.get("service") or info.get("banner") or ""
    return str(info).strip()[:80] or "unknown service"


def default_tasks(phase: str, state: Dict[str, Any]) -> List[TaskSpec]:
    """Fallback tasks for one phase, derived from the facts in ``state``."""
    target = str(state.get("target") or "")
    ports = [int(p) for p in (state.get("open_ports") or [])]
    services = state.get("services") or {}

    if ports and phase == "scanner":
        return [
            TaskSpec(
                id=f"t{index}",
                dependent_task_ids=[],
                instruction=f"对 {target}:{port} 进行服务识别与漏洞验证（{_service_label(services.get(str(port)))}）",
                action="Enumerate",
            )
            for index, port in enumerate(ports[:3])
        ]
    if ports and phase == "exploiter":
        return [
            TaskSpec(
                id="t1",
                dependent_task_ids=[],
                instruction=f"利用 {target} 上最可能的漏洞点验证命令执行与权限提升",
                action="Exploit",
            )
        ]
    rows = _DEFAULT_ROWS.get(phase) or _DEFAULT_ROWS["collector"]
    return [
        TaskSpec(
            id=task_id,
            dependent_task_ids=list(deps),
            instruction=text.format(target=target),
            action=action,
        )
        for task_id, deps, text, action in rows
    ]
