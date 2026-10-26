"""Engagement-level nodes: scope, phase transitions, backtracking, reporting."""

from __future__ import annotations

import time
from typing import Any, Dict, List

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.types import Command

from agent import memory, telemetry
from agent import report as report_module
from agent.findings import clip, render_facts
from agent.llm import chat
from agent.phases import budget_hit, PHASE_ORDER, get_phase, phase_index
from agent.telemetry import emit
from agent.prompts import REPORTER_SYSTEM, REPORTER_USER
from agent.settings import cfg
from utils.log_common import build_logger

logger = build_logger()


DEFAULT_CONSTRAINTS = [
    "Stay in scope: only the declared target.",
    "No destructive actions (no deleting data, no DoS, no shutting services down).",
    "Do not install packages on the attack machine.",
]


def scope_node(state: Dict[str, Any]) -> Dict[str, Any]:
    target = (state.get("target") or "").strip()
    goal = (state.get("goal") or state.get("task_description") or "").strip()
    if not goal:
        goal = "Assess the target, obtain the highest practical level of access and document it."

    constraints = list(DEFAULT_CONSTRAINTS)
    for item in state.get("constraints") or []:
        if item and item not in constraints:
            constraints.append(item)

    minutes = float(cfg("budgets.deadline_minutes", 60))
    max_commands = int(state.get("max_commands") or cfg("budgets.max_commands", 250))

    prior = memory.load_target_memory(target)

    emit({"kind": "scope", "target": target, "goal": goal, "prior": bool(prior)})
    return {
        "target": target,
        "goal": goal,
        "success_criteria": state.get("success_criteria")
        or "Command execution or privileged access proven with verifiable evidence.",
        "constraints": constraints,
        "phase": "collector",
        "phase_index": 0,
        "phase_outcome": "",
        "deadline_ts": time.time() + minutes * 60,
        "max_commands": max_commands,
        "max_backtracks": int(cfg("budgets.max_backtracks", 1)),
        "backtrack_count": int(state.get("backtrack_count", 0)),
        "target_memory": memory.render_target_memory(prior),
        "final_report": "",
    }


def to_scanner_node(state: Dict[str, Any]) -> Command:
    return Command(
        goto="scanner",
        update={"phase": "scanner", "phase_index": phase_index("scanner"), "phase_outcome": ""},
    )


def to_exploiter_node(state: Dict[str, Any]) -> Command:
    return Command(
        goto="exploiter",
        update={"phase": "exploiter", "phase_index": phase_index("exploiter"), "phase_outcome": ""},
    )


def backtrack_node(state: Dict[str, Any]) -> Command:
    count = int(state.get("backtrack_count", 0)) + 1
    note = (
        "## Backtrack\n"
        "Exploitation did not succeed. Returning to vulnerability scanning to find a different "
        "entry point. The vectors listed under 'already attempted and failed' must not be retried."
    )
    return Command(
        goto="scanner",
        update={
            "phase": "scanner",
            "phase_index": phase_index("scanner"),
            "phase_outcome": "",
            "backtrack_count": count,
            "phase_summaries": [note],
        },
    )


def route_after_collector(state: Dict[str, Any]) -> str:
    if budget_hit(state) or state.get("is_compromised"):
        return "reporter"
    if not state.get("open_ports"):
        return "reporter"
    return "scanner"


def route_after_scanner(state: Dict[str, Any]) -> str:
    if budget_hit(state) or state.get("is_compromised"):
        return "reporter"
    if state.get("vulnerabilities") or state.get("open_ports"):
        return "exploiter"
    return "reporter"


def route_after_exploiter(state: Dict[str, Any]) -> str:
    if state.get("is_compromised"):
        return "reporter"
    if budget_hit(state):
        return "reporter"
    if int(state.get("backtrack_count", 0)) < int(state.get("max_backtracks", 1)):
        return "backtrack"
    return "reporter"


def reporter_node(state: Dict[str, Any]) -> Dict[str, Any]:
    degradation: List[str] = []
    report = report_module.deterministic(state)
    try:
        enhanced = chat(
            [
                SystemMessage(content=REPORTER_SYSTEM),
                HumanMessage(
                    content=REPORTER_USER.format(
                        target=state.get("target", ""),
                        goal=state.get("goal", ""),
                        success_criteria=state.get("success_criteria", ""),
                        compromised="YES" if state.get("is_compromised") else "NO",
                        facts=render_facts(state, 8000),
                        summaries="\n\n".join(state.get("phase_summaries") or []) or "none",
                        failed="\n".join(state.get("tried_vectors") or []) or "none",
                        commands=int(state.get("commands_used", 0)),
                    )
                ),
            ],
            node="reporter",
        )
    except Exception as exc:  # noqa: BLE001 - the deterministic report is the fallback
        logger.warning(f"[reporter] LLM report enhancement failed: {exc}")
        enhanced = ""
        degradation.append(f"LLM report enhancement failed ({exc}); deterministic report shown.")
    if enhanced and len(enhanced) > 200:
        report = enhanced

    report += report_module.usage_section()
    path = report_module.save(state.get("thread_id", "run"), report)
    if path is None:
        degradation.append("The report could not be written to disk; it only exists in the final state.")
    if degradation:
        report += "\n\n## Run degradations\n" + "\n".join(f"- {item}" for item in degradation)
    emit({"kind": "report", "path": path or "", "compromised": bool(state.get("is_compromised"))})

    thread_id = state.get("thread_id") or "run"
    memory.save_target_memory(
        state.get("target", ""),
        {
            "open_ports": state.get("open_ports") or [],
            "services": state.get("services") or {},
            "vulnerabilities": state.get("vulnerabilities") or [],
            "tried_vectors": state.get("tried_vectors") or [],
            "is_compromised": bool(state.get("is_compromised")),
            "last_phase": "done",
            "report_path": path or "",
        },
    )

    return {
        "final_report": report + (f"\n\n_report saved to {path}_" if path else ""),
        "phase": "done",
        "phase_outcome": "done",
    }
