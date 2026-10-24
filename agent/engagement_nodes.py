"""Engagement-level nodes: scope, phase transitions, backtracking, reporting."""

from __future__ import annotations

import time
from typing import Any, Dict, List

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.types import Command

from agent import memory
from agent.findings import clip, render_facts
from agent.llm import chat
from agent.phases import PHASE_ORDER, get_phase, phase_index
from agent.progress import emit
from agent.prompts import REPORTER_SYSTEM, REPORTER_USER
from agent.settings import cfg


DEFAULT_CONSTRAINTS = [
    "Stay in scope: only the declared target.",
    "No destructive actions (no deleting data, no DoS, no shutting services down).",
    "Do not install packages on the attack machine.",
]


def _budget_hit(state: Dict[str, Any]) -> str:
    deadline = float(state.get("deadline_ts") or 0)
    if deadline and time.time() > deadline:
        return "deadline"
    if int(state.get("commands_used", 0)) >= int(state.get("max_commands", 250)):
        return "command budget"
    return ""


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
    if _budget_hit(state) or state.get("is_compromised"):
        return "reporter"
    if not state.get("open_ports"):
        return "reporter"
    return "scanner"


def route_after_scanner(state: Dict[str, Any]) -> str:
    if _budget_hit(state) or state.get("is_compromised"):
        return "reporter"
    if state.get("vulnerabilities") or state.get("open_ports"):
        return "exploiter"
    return "reporter"


def route_after_exploiter(state: Dict[str, Any]) -> str:
    if state.get("is_compromised"):
        return "reporter"
    if _budget_hit(state):
        return "reporter"
    if int(state.get("backtrack_count", 0)) < int(state.get("max_backtracks", 1)):
        return "backtrack"
    return "reporter"


def _deterministic_report(state: Dict[str, Any]) -> str:
    facts = render_facts(state, 8000, include_tried=False)
    summaries = "\n\n".join(state.get("phase_summaries") or []) or "No phase summaries recorded."
    tried = state.get("tried_vectors") or []
    compromised = bool(state.get("is_compromised"))
    lines = [
        "# PenAgent Assessment Report",
        "",
        "## Executive summary",
        f"Target `{state.get('target', '')}`. Objective: {state.get('goal', '')}",
        f"Result: {'the objective was achieved (compromise confirmed).' if compromised else 'no verified compromise was achieved.'}",
        f"Commands executed: {int(state.get('commands_used', 0))}.",
        "",
        "## Attack surface",
        facts,
        "",
        "## Phase summaries",
        summaries,
        "",
        "## Failed attempts",
        *([f"- {item}" for item in tried] or ["- none recorded"]),
        "",
        "## Evidence",
        *(
            [f"- flag: {flag}" for flag in (state.get("flags") or [])]
            + [f"- access: {item}" for item in (state.get("credentials") or [])]
            or ["- no verifiable compromise artifact captured"]
        ),
    ]
    return "\n".join(lines)


def _audit(state: Dict[str, Any], report: str) -> str:
    if not state.get("is_compromised"):
        return report
    evidence = " ".join(
        [
            " ".join(state.get("flags") or []),
            " ".join(state.get("credentials") or []),
            " ".join(str(v.get("evidence", "")) for v in (state.get("vulnerabilities") or []) if isinstance(v, dict)),
        ]
    )
    if "uid=0" in evidence or "root" in evidence.lower() or "flag{" in evidence.lower():
        return report
    warning = (
        "\n\n> **Evidence audit warning**: the run marked the target as compromised, but no "
        "`uid=0` / root shell / flag artifact was found in the recorded evidence. "
        "Treat the compromise claim as unverified.\n"
    )
    return report + warning


def reporter_node(state: Dict[str, Any]) -> Dict[str, Any]:
    report = _deterministic_report(state)
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
    except Exception:  # noqa: BLE001
        enhanced = ""
    if enhanced and len(enhanced) > 200:
        report = enhanced

    report = _audit(state, report)
    path = memory.save_report(state.get("thread_id", "run"), report)
    emit({"kind": "report", "path": path or "", "compromised": bool(state.get("is_compromised"))})

    thread_id = state.get("thread_id") or "run"
    memory.project_session(
        session_id=thread_id,
        name=f"agent-{state.get('target', '')}",
        init_description=state.get("goal", ""),
        current_role_name="Exploitation",
        current_planner_id=(state.get("plan_ids") or [""])[-1],
        history_planner_ids=list(state.get("plan_ids") or []),
    )
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
