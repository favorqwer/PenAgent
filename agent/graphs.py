"""Graph assembly: engagement -> phase -> task (three nested levels)."""

from __future__ import annotations

from typing import Any, Dict

from langgraph.graph import END, START, StateGraph

from agent import memory
from agent.engagement_nodes import (
    backtrack_node,
    reporter_node,
    route_after_collector,
    route_after_exploiter,
    route_after_scanner,
    scope_node,
    to_exploiter_node,
    to_scanner_node,
)
from agent.phase_nodes import (
    handover_node,
    planner_node,
    replan_node,
    select_task_node,
)
from agent.settings import cfg
from agent.state import EngagementState, PhaseState, TaskState
from agent.task_nodes import (
    evaluate_node,
    gate_node,
    gen_node,
    route_after_gate,
    route_after_gen,
    route_after_run,
    run_node,
)


def _max_attempts() -> int:
    return int(cfg("budgets.max_task_attempts", 2))


def route_after_select(state: Dict[str, Any]) -> str:
    return "task" if state.get("current_task") else "handover"


def route_after_task(state: Dict[str, Any]) -> str:
    if state.get("task_success"):
        return "select_task"

    task = state.get("current_task") or {}
    if task.get("status") == "pending" and int(state.get("task_attempt", 0)) < _max_attempts():
        return "task"

    replan_count = int(state.get("replan_count", 0))
    max_replans = int(state.get("max_replans", cfg("budgets.max_replans", 2)))
    if replan_count < max_replans and state.get("phase_outcome") != "replan_exhausted":
        return "replan"
    return "select_task"


def route_after_replan(state: Dict[str, Any]) -> str:
    if state.get("phase_outcome") == "replan_exhausted":
        return "handover"
    return "select_task"


def build_task_graph():
    graph = StateGraph(TaskState)
    graph.add_node("gen", gen_node)
    graph.add_node("gate", gate_node)
    graph.add_node("run", run_node)
    graph.add_node("evaluate", evaluate_node)

    graph.add_edge(START, "gen")
    graph.add_conditional_edges(
        "gen",
        route_after_gen,
        {"gen": "gen", "gate": "gate", "evaluate": "evaluate"},
    )
    graph.add_conditional_edges(
        "gate",
        route_after_gate,
        {"gen": "gen", "run": "run", "evaluate": "evaluate"},
    )
    graph.add_conditional_edges(
        "run",
        route_after_run,
        {"gen": "gen", "evaluate": "evaluate"},
    )
    graph.add_edge("evaluate", END)
    return graph.compile()


def build_phase_graph(task_graph):
    graph = StateGraph(PhaseState)
    graph.add_node("planner", planner_node)
    graph.add_node("select_task", select_task_node)
    graph.add_node("task", task_graph)
    graph.add_node("replan", replan_node)
    graph.add_node("handover", handover_node)

    graph.add_edge(START, "planner")
    graph.add_edge("planner", "select_task")
    graph.add_conditional_edges(
        "select_task",
        route_after_select,
        {"task": "task", "handover": "handover"},
    )
    graph.add_conditional_edges(
        "task",
        route_after_task,
        {"select_task": "select_task", "task": "task", "replan": "replan"},
    )
    graph.add_conditional_edges(
        "replan",
        route_after_replan,
        {"select_task": "select_task", "handover": "handover"},
    )
    graph.add_edge("handover", END)
    return graph.compile()


def create_agent_graph(with_checkpointer: bool = True, checkpointer=None):
    """Compile the engagement graph. Checkpointer is required for HITL/resume."""
    task_graph = build_task_graph()
    phase_graph = build_phase_graph(task_graph)

    graph = StateGraph(EngagementState)
    graph.add_node("scope", scope_node)
    graph.add_node("collector", phase_graph)
    graph.add_node("scanner", phase_graph)
    graph.add_node("exploiter", phase_graph)
    graph.add_node("to_scanner", to_scanner_node)
    graph.add_node("to_exploiter", to_exploiter_node)
    graph.add_node("backtrack", backtrack_node)
    graph.add_node("reporter", reporter_node)

    graph.add_edge(START, "scope")
    graph.add_edge("scope", "collector")
    graph.add_conditional_edges(
        "collector",
        route_after_collector,
        {"scanner": "to_scanner", "reporter": "reporter"},
    )
    graph.add_edge("to_scanner", "scanner")
    graph.add_conditional_edges(
        "scanner",
        route_after_scanner,
        {"exploiter": "to_exploiter", "reporter": "reporter"},
    )
    graph.add_edge("to_exploiter", "exploiter")
    graph.add_conditional_edges(
        "exploiter",
        route_after_exploiter,
        {"backtrack": "backtrack", "reporter": "reporter"},
    )
    graph.add_edge("backtrack", "scanner")
    graph.add_edge("reporter", END)

    if not with_checkpointer:
        return graph.compile()
    saver = checkpointer if checkpointer is not None else memory.get_checkpointer()
    return graph.compile(checkpointer=saver)
