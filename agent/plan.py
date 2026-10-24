"""Plan bookkeeping: normalisation, topological ordering, dependency-preserving
merge across replans, and task status helpers.

All pure functions - unit testable without an LLM.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

from agent.contracts import PlanSpec, TaskSpec
from agent.state import PenTask

TERMINAL = {"success", "failed", "blocked"}


def normalize_instruction(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def new_task(spec: TaskSpec, sequence: int, version: int = 1) -> PenTask:
    return {
        "id": f"v{version}-t{sequence}",
        "instruction": spec.instruction.strip(),
        "action": spec.action,
        "depends_on": [],
        "status": "pending",
        "attempts": 0,
        "commands": [],
        "result": "",
        "evidence": "",
    }


def _match_existing(spec: TaskSpec, old: List[PenTask]) -> Optional[PenTask]:
    """Match a replanned spec to an old task.

    Ids drift between replans, so we match by normalised instruction first and
    fall back to an id match. Successful tasks are always preserved verbatim.
    """
    wanted = normalize_instruction(spec.instruction)
    for task in old:
        if task.get("status") == "success" and normalize_instruction(task.get("instruction", "")) == wanted:
            return task
    for task in old:
        if task.get("id") == spec.id:
            return task
    for task in old:
        if normalize_instruction(task.get("instruction", "")) == wanted:
            return task
    return None


def merge_plan(
    old_plan: List[PenTask],
    spec: PlanSpec,
    version: int,
    max_tasks: int,
) -> List[PenTask]:
    """Merge an LLM-produced plan with the current plan.

    Guarantees:
    * every successful task survives, even if the model forgot it;
    * successful tasks keep their result/evidence/attempts;
    * dependency ids are remapped onto the new plan;
    * the plan never exceeds ``max_tasks`` entries.
    """
    old_plan = list(old_plan or [])
    specs = list(spec.tasks or [])[:max_tasks]
    if not specs:
        return old_plan

    spec_ids = {s.id for s in specs}
    matched: Dict[int, PenTask] = {}
    used: set = set()

    for index, task_spec in enumerate(specs):
        candidate = _match_existing(task_spec, old_plan)
        if candidate is not None and id(candidate) not in used:
            matched[index] = dict(candidate)
            used.add(id(candidate))

    # Successful tasks the model dropped must not disappear.
    matched_instructions = {
        normalize_instruction(t.get("instruction", "")) for t in matched.values()
    }
    orphans = [
        task
        for task in old_plan
        if task.get("status") == "success"
        and normalize_instruction(task.get("instruction", "")) not in matched_instructions
        and id(task) not in used
    ]

    result: List[PenTask] = []
    id_map: Dict[str, str] = {}

    for orphan in orphans:
        orphan = dict(orphan)
        orphan["id"] = f"v{version}-p{len(result)}"
        orphan["depends_on"] = []
        id_map.setdefault("__orphan__", orphan["id"])
        result.append(orphan)

    for index, task_spec in enumerate(specs):
        task = matched.get(index)
        if task is None:
            task = new_task(task_spec, index, version)
            task["status"] = "pending"
        else:
            task = dict(task)
            task["id"] = f"v{version}-t{index}"
            task["instruction"] = task_spec.instruction.strip() or task.get("instruction", "")
            task["action"] = task_spec.action
            if task.get("status") in ("running", None):
                task["status"] = "pending"
        id_map[task_spec.id] = task["id"]
        result.append(task)

    # Remap dependencies from spec ids to the new concrete ids.
    for index, task_spec in enumerate(specs):
        deps: List[str] = []
        for dep in task_spec.dependent_task_ids:
            if dep in id_map and id_map[dep] not in deps:
                deps.append(id_map[dep])
        result[len(orphans) + index]["depends_on"] = deps

    return result


def order_plan(plan: Iterable[PenTask]) -> List[PenTask]:
    """Kahn topological sort. Ties keep the model's original ordering."""
    tasks = [dict(t) for t in (plan or [])]
    if not tasks:
        return []

    by_id = {t["id"]: t for t in tasks}
    order = {t["id"]: i for i, t in enumerate(tasks)}
    indegree = {t["id"]: 0 for t in tasks}
    children: Dict[str, List[str]] = {t["id"]: [] for t in tasks}

    for task in tasks:
        for dep in task.get("depends_on", []):
            if dep in by_id and dep != task["id"]:
                indegree[task["id"]] += 1
                children[dep].append(task["id"])

    ready = sorted([tid for tid, deg in indegree.items() if deg == 0], key=order.get)
    sorted_ids: List[str] = []
    while ready:
        current = ready.pop(0)
        sorted_ids.append(current)
        for child in children[current]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
        ready.sort(key=order.get)

    if len(sorted_ids) != len(tasks):  # cycle safety net: fall back to given order
        return tasks
    return [by_id[tid] for tid in sorted_ids]


def select_next_task(plan: List[PenTask]) -> Optional[PenTask]:
    """First runnable task, or None when nothing more can run.

    The plan is mutated in place (blocked statuses) and must already be ordered;
    pass the output of :func:`order_plan`.
    """
    ordered = plan  # must already be topologically ordered by the caller
    ids = {t["id"] for t in ordered}
    done = {t["id"] for t in ordered if t.get("status") == "success"}
    dead = {t["id"] for t in ordered if t.get("status") in ("failed", "blocked")}

    changed = True
    while changed:
        changed = False
        for task in ordered:
            if task.get("status") in TERMINAL or task.get("status") == "running":
                continue
            deps = [d for d in task.get("depends_on", []) if d in ids]
            if any(d in dead for d in deps):
                task["status"] = "blocked"
                task["result"] = "Blocked: a prerequisite task failed"
                dead.add(task["id"])
                changed = True

    for task in ordered:
        if task.get("status") in TERMINAL or task.get("status") == "running":
            continue
        deps = [d for d in task.get("depends_on", []) if d in ids]
        if all(d in done for d in deps):
            return task
    return None


def update_task(
    plan: List[PenTask],
    task_id: str,
    **changes: Any,
) -> List[PenTask]:
    updated: List[PenTask] = []
    for task in plan or []:
        if task.get("id") == task_id:
            merged = dict(task)
            merged.update(changes)
            updated.append(merged)
        else:
            updated.append(dict(task))
    return updated


def get_task(plan: List[PenTask], task_id: str) -> Optional[PenTask]:
    for task in plan or []:
        if task.get("id") == task_id:
            return task
    return None


def phase_is_exhausted(plan: List[PenTask]) -> bool:
    return all(t.get("status") in TERMINAL for t in (plan or []))


def plan_metrics(plan: List[PenTask]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for task in plan or []:
        status = task.get("status", "pending")
        counts[status] = counts.get(status, 0) + 1
    return {
        "tasks": len(plan or []),
        "success": counts.get("success", 0),
        "failed": counts.get("failed", 0),
        "blocked": counts.get("blocked", 0),
        "pending": counts.get("pending", 0),
    }
