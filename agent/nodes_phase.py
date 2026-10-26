"""Phase subgraph nodes: planning, task selection, replanning, handover."""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List

from langchain_core.messages import HumanMessage, SystemMessage

from agent import memory
from agent.schema import PlanSpec
from agent.findings import clip, render_facts
from agent.llm import chat, structured
from agent.phases import (
    budget_hit,
    default_tasks,
    get_phase,
    next_phase_key,
    phase_max_steps,
    phase_max_tasks,
)
from agent.plan import (
    get_task,
    merge_plan,
    order_plan,
    plan_metrics,
    select_next_task,
    select_ready_tasks,
)
from agent.telemetry import emit
from agent.prompts import PLANNER_SYSTEM, PLANNER_USER, REPLAN_NOTE, SUMMARIZER_SYSTEM, SUMMARIZER_USER
from agent.settings import cfg
from agent.schema import PenTask
from utils.log_common import build_logger

logger = build_logger()


def _render_tasks(plan: List[PenTask], statuses: List[str], with_results: bool = True) -> str:
    lines: List[str] = []
    for task in plan or []:
        if task.get("status") not in statuses:
            continue
        label = f"- [{task.get('status')}] {task.get('instruction', '')}"
        if with_results and task.get("result"):
            label += f"\n    result: {task['result']}"
        lines.append(label)
    return "\n".join(lines) or "None."


def _previous_summary(state: Dict[str, Any]) -> str:
    summaries = state.get("phase_summaries") or []
    return summaries[-1] if summaries else "None (first phase)."


def _failure_brief(state: Dict[str, Any]) -> str:
    """What failed and why, in the evidence's own words - no classification."""
    failed = [t for t in (state.get("plan") or []) if t.get("status") in ("failed", "blocked")]
    if not failed:
        return ""
    task = failed[-1]
    commands = list(task.get("commands") or [])
    verdict = state.get("task_verdict") or {}
    lines = [
        "THE LAST ATTEMPT FAILED (change the tool, parameters or angle; do not repeat it)",
        f"Task: {task.get('instruction', '')}",
    ]
    if commands:
        lines.append(f"Last command: {commands[-1]}")
    reason = str(verdict.get("reason") or "").strip()
    evidence = str(verdict.get("evidence") or "").strip()
    if reason:
        lines.append(f"Why it did not work: {reason}")
    if evidence:
        lines.append(f"Last observed output: {evidence[:600]}")
    return "\n".join(lines) + "\n"


def _plan_prompt(state: Dict[str, Any], replan: bool) -> str:
    conf = get_phase(state.get("phase", "collector"))
    constraints = "; ".join(state.get("constraints") or []) or "stay in scope"
    failure_brief = _failure_brief(state) if replan else ""
    return PLANNER_USER.format(
        target=state.get("target", ""),
        goal=state.get("goal", ""),
        constraints=constraints,
        phase_name=conf.name,
        phase_key=conf.key,
        phase_goal=conf.goal,
        entry=conf.entry,
        exit_success=conf.exit_success,
        facts=render_facts(state, int(cfg("context.max_planner_facts", 12000))),
        summary=_previous_summary(state),
        completed=_render_tasks(state.get("plan") or [], ["success"]),
        failed=_render_tasks(state.get("plan") or [], ["failed", "blocked"]),
        max_tasks=phase_max_tasks(conf.key),
        replan_note=REPLAN_NOTE if replan else "",
        failure_brief=failure_brief,
    )


def _phase_allowance(state: Dict[str, Any], phase: str) -> int:
    """Commands this phase may spend: its share of the global budget."""
    total = int(state.get("max_commands") or cfg("budgets.max_commands", 250))
    share = (cfg("budgets.phase_share", {}) or {}).get(phase, 0)
    try:
        allowance = int(total * float(share))
    except (TypeError, ValueError):
        allowance = 0
    return max(allowance, 1) if share else 0


def planner_node(state: Dict[str, Any]) -> Dict[str, Any]:
    conf = get_phase(state.get("phase", "collector"))
    version = int(state.get("plan_version", 0)) + 1
    plan_id = state.get("plan_id") or uuid.uuid4().hex

    try:
        spec = structured(
            PlanSpec,
            [SystemMessage(content=PLANNER_SYSTEM), HumanMessage(content=_plan_prompt(state, replan=False))],
            node="planner",
        )
        plan = merge_plan([], spec, version, phase_max_tasks(conf.key))
    except Exception as exc:  # noqa: BLE001 - a default plan keeps the phase alive
        logger.warning(f"[planner] {conf.key} plan generation failed, using the default plan: {exc}")
        plan = []
    if not plan:
        plan = merge_plan([], PlanSpec(tasks=default_tasks(conf.key, state)), version, phase_max_tasks(conf.key))

    emit({"kind": "plan", "phase": conf.key, "version": version, "tasks": plan})

    return {
        "plan": plan,
        "plan_id": plan_id,
        "plan_version": version,
        "replan_count": 0,
        "max_replans": int(cfg("budgets.max_replans", 2)),
        "max_tasks": phase_max_tasks(conf.key),
        "current_task": {},
        "task_attempt": 0,
        "task_verdict": {},
        "task_result": "",
        "max_steps": phase_max_steps(conf.key),
        "phase_outcome": "",
        "phase_start_commands": int(state.get("commands_used", 0)),
        "phase_allowance": _phase_allowance(state, conf.key),
        "plan_ids": [plan_id],
    }


def select_task_node(state: Dict[str, Any]) -> Dict[str, Any]:
    ordered = order_plan(state.get("plan") or [])

    budget = budget_hit(state)
    if budget:
        for task in ordered:
            if task.get("status") in ("pending", "running", None):
                task["status"] = "failed"
                task["result"] = f"Aborted: {budget} exhausted"
        return {"plan": ordered, "current_task": {}, "phase_outcome": "budget"}

    ready_tasks = select_ready_tasks(ordered)
    task = select_next_task(ordered)

    update: Dict[str, Any] = {"plan": ordered, "ready_tasks": ready_tasks}
    if task is not None:
        emit({"kind": "task", "phase": state.get("phase", ""), "task": task})
        update.update(
            {
                "current_task": task,
                "task_attempt": 0,
                "task_verdict": {},
                "task_result": "",
                "max_steps": phase_max_steps(state.get("phase", "collector")),
            }
        )
    else:
        update["current_task"] = {}
    return update


def replan_node(state: Dict[str, Any]) -> Dict[str, Any]:
    conf = get_phase(state.get("phase", "collector"))
    replan_count = int(state.get("replan_count", 0))
    max_replans = int(state.get("max_replans", cfg("budgets.max_replans", 2)))
    version = int(state.get("plan_version", 1)) + 1

    if replan_count >= max_replans:
        return {"current_task": {}, "phase_outcome": "replan_exhausted"}

    plan = list(state.get("plan") or [])
    try:
        spec = structured(
            PlanSpec,
            [SystemMessage(content=PLANNER_SYSTEM), HumanMessage(content=_plan_prompt(state, replan=True))],
            node="planner",
        )
        new_plan = merge_plan(plan, spec, version, phase_max_tasks(conf.key))
    except Exception as exc:  # noqa: BLE001 - fall through to "replan exhausted"
        logger.warning(f"[planner] {conf.key} replan failed (attempt {replan_count + 1}): {exc}")
        new_plan = []

    if not new_plan or not any(t.get("status") == "pending" for t in new_plan):
        return {
            "plan": new_plan or plan,
            "replan_count": replan_count + 1,
            "plan_version": version,
            "current_task": {},
            "phase_outcome": "replan_exhausted",
        }

    plan_id = state.get("plan_id") or uuid.uuid4().hex
    emit({"kind": "replan", "phase": conf.key, "version": version, "tasks": new_plan})

    return {
        "plan": new_plan,
        "plan_id": plan_id,
        "plan_version": version,
        "replan_count": replan_count + 1,
        "current_task": {},
        "task_attempt": 0,
        "task_verdict": {},
        "task_result": "",
        "phase_outcome": "",
    }


def _fallback_summary(state: Dict[str, Any]) -> str:
    conf = get_phase(state.get("phase", "collector"))
    rows = []
    for task in state.get("plan") or []:
        if task.get("status") == "success":
            rows.append(f"- {task.get('instruction')}: {task.get('result', '')[:200]}")
    failed = [
        f"- {task.get('instruction')}: {task.get('result', '')[:160]}"
        for task in (state.get("plan") or [])
        if task.get("status") in ("failed", "blocked")
    ]
    parts = [f"## {conf.name} summary", "Completed:", *(rows or ["- none"]), "Failed:", *(failed or ["- none"])]
    return "\n".join(parts)


def handover_node(state: Dict[str, Any]) -> Dict[str, Any]:
    conf = get_phase(state.get("phase", "collector"))
    plan = list(state.get("plan") or [])
    metrics = plan_metrics(plan)
    compromised = bool(state.get("is_compromised"))

    results = _render_tasks(plan, ["success"])
    failed = _render_tasks(plan, ["failed", "blocked"])
    try:
        summary = chat(
            [
                SystemMessage(content=SUMMARIZER_SYSTEM),
                HumanMessage(
                    content=SUMMARIZER_USER.format(
                        phase_name=conf.name,
                        phase_key=conf.key,
                        phase_goal=conf.goal,
                        results=results,
                        facts=render_facts(state, 6000),
                        failed=failed,
                    )
                ),
            ],
            node="summarizer",
        )
    except Exception as exc:  # noqa: BLE001 - the deterministic summary is the fallback
        logger.warning(f"[handover] {conf.key} summary failed, using the deterministic one: {exc}")
        summary = ""
    if not summary.strip():
        summary = _fallback_summary(state)

    phase_outcome = "success" if any(t.get("status") == "success" for t in plan) else "exhausted"
    if compromised:
        phase_outcome = "success"
    emit({"kind": "handover", "phase": conf.key, "summary": summary.strip(), "outcome": phase_outcome})

    plan_id = state.get("plan_id") or ""
    memory.save_target_memory(
        state.get("target", ""),
        {
            "open_ports": state.get("open_ports") or [],
            "services": state.get("services") or {},
            "vulnerabilities": state.get("vulnerabilities") or [],
            "tried_vectors": state.get("tried_vectors") or [],
            "is_compromised": compromised,
            "last_phase": conf.key,
        },
    )

    section = f"## {conf.name}\n{summary.strip()}"
    return {
        "phase_summaries": [section],
        "phase_metrics": [{"id": f"{plan_id}-metrics", "phase": conf.key, **metrics}],
        "phase_outcome": phase_outcome,
        "plan": [],
        "current_task": {},
        "plan_ids": [plan_id] if plan_id else [],
    }


def next_phase(state: Dict[str, Any]) -> str:
    return next_phase_key(state.get("phase", "collector"))
