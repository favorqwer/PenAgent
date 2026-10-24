"""Persistence for the agent pipeline.

Three layers, deliberately separate:

1. LangGraph checkpointer  - execution truth (resume, time travel)
2. Projection tables       - plans/tasks/sessions in penagent.db for reports/benchmark
3. Cross-session store     - per-target knowledge reused on the next engagement
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.settings import cfg, resolve_path

_CHECKPOINTER = None
_STORE = None
_CONN: Dict[str, sqlite3.Connection] = {}


def _conn(path_key: str) -> sqlite3.Connection:
    if path_key not in _CONN:
        path = resolve_path(path_key)
        conn = sqlite3.connect(str(path), check_same_thread=False)
        _CONN[path_key] = conn
    return _CONN[path_key]


def get_checkpointer():
    global _CHECKPOINTER
    if _CHECKPOINTER is None:
        from langgraph.checkpoint.sqlite import SqliteSaver

        path = cfg("storage.checkpoint_path", "data/graph_checkpoints.db")
        _CHECKPOINTER = SqliteSaver(_conn(path))
    return _CHECKPOINTER


def get_store():
    global _STORE
    if _STORE is None:
        from langgraph.store.sqlite import SqliteStore

        path = cfg("storage.store_path", "data/graph_store.db")
        _STORE = SqliteStore(_conn(path))
    return _STORE


# --------------------------------------------------------------------------- #
# Cross-session target memory
# --------------------------------------------------------------------------- #

NAMESPACE = ("penagent", "targets")


def load_target_memory(target: str) -> Dict[str, Any]:
    if not target:
        return {}
    try:
        item = get_store().get(NAMESPACE, target)
    except Exception:
        return {}
    return dict(item.value) if item and getattr(item, "value", None) else {}


def save_target_memory(target: str, payload: Dict[str, Any]) -> None:
    if not target:
        return
    try:
        previous = load_target_memory(target)
        merged = _merge_memory(previous, payload)
        merged["updated_at"] = time.time()
        get_store().put(NAMESPACE, target, merged)
    except Exception:
        # Memory is an optimisation, never a hard dependency.
        return


def _merge_memory(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(old or {})
    for key, value in (new or {}).items():
        if isinstance(value, list):
            existing = list(out.get(key) or [])
            for item in value:
                if item not in existing:
                    existing.append(item)
            out[key] = existing
        elif isinstance(value, dict):
            merged = dict(out.get(key) or {})
            merged.update(value)
            out[key] = merged
        else:
            out[key] = value
    return out


def render_target_memory(memory: Dict[str, Any]) -> str:
    if not memory:
        return "No prior knowledge about this target."
    lines: List[str] = []
    ports = memory.get("open_ports") or []
    if ports:
        lines.append(f"Previous session knew these open ports: {sorted(ports)}")
    services = memory.get("services") or {}
    for port, info in list(services.items())[:10]:
        if isinstance(info, dict):
            lines.append(f"  {port}/tcp {info.get('service', '?')} {info.get('banner', '')}".rstrip())
    vulns = memory.get("vulnerabilities") or []
    for vuln in vulns[:6]:
        if isinstance(vuln, dict):
            label = vuln.get("cve") or vuln.get("name") or vuln.get("identifier")
            if label:
                lines.append(f"  known finding: {label}")
    tried = memory.get("tried_vectors") or []
    if tried:
        lines.append(f"  failed previously: {tried[-6:]}")
    if memory.get("is_compromised"):
        lines.append("  previous session reported the target as compromised")
    return "\n".join(lines) or "No prior knowledge about this target."


# --------------------------------------------------------------------------- #
# Projection into the legacy reporting tables
# --------------------------------------------------------------------------- #

def project_plan(plan_id: str, goal: str, phase: str) -> None:
    if not cfg("storage.projection", True):
        return
    try:
        from db.models.plan_model import PlanModel
        from utils.session import session_scope

        with session_scope() as session:
            row = session.query(PlanModel).filter(PlanModel.id == plan_id).first()
            if row is None:
                session.add(
                    PlanModel(
                        id=plan_id,
                        goal=f"[{phase}] {goal}"[:500],
                        current_task_sequence=0,
                        plan_chat_id="",
                        react_chat_id="",
                    )
                )
    except Exception:
        return


def upsert_task(plan_id: str, sequence: int, task: Dict[str, Any]) -> None:
    if not cfg("storage.projection", True):
        return
    try:
        from db.models.task_model import TaskModel
        from utils.session import session_scope

        with session_scope() as session:
            row = (
                session.query(TaskModel)
                .filter(TaskModel.plan_id == plan_id, TaskModel.sequence == sequence)
                .first()
            )
            if row is None:
                row = TaskModel(id=uuid.uuid4().hex, plan_id=plan_id, sequence=sequence)
                session.add(row)
            row.action = (task.get("action") or "")[:250]
            row.instruction = (task.get("instruction") or "")[:500]
            row.code = list(task.get("commands") or [])
            row.result = (task.get("result") or "")[:8000]
            row.is_finished = task.get("status") in ("success", "failed", "blocked")
            row.is_success = task.get("status") == "success"
            row.dependencies = list(task.get("depends_on") or [])
    except Exception:
        return


def sync_plan_tasks(plan_id: str, tasks: List[Dict[str, Any]]) -> None:
    """Replace the projected rows of one plan (delete + insert, no duplicates)."""
    if not cfg("storage.projection", True):
        return
    try:
        from db.models.task_model import TaskModel
        from utils.session import session_scope

        with session_scope() as session:
            session.query(TaskModel).filter(TaskModel.plan_id == plan_id).delete()
            for sequence, task in enumerate(tasks or []):
                session.add(
                    TaskModel(
                        id=uuid.uuid4().hex,
                        plan_id=plan_id,
                        sequence=sequence,
                        action=(task.get("action") or "")[:250],
                        instruction=(task.get("instruction") or "")[:500],
                        code=list(task.get("commands") or []),
                        result=(task.get("result") or "")[:8000],
                        dependencies=list(task.get("depends_on") or []),
                        is_finished=task.get("status") in ("success", "failed", "blocked"),
                        is_success=task.get("status") == "success",
                    )
                )
    except Exception:
        return


def project_session(
    session_id: str,
    name: str,
    init_description: str,
    current_role_name: str,
    current_planner_id: str,
    history_planner_ids: List[str],
) -> None:
    if not cfg("storage.projection", True):
        return
    try:
        from db.models.session_model import SessionModel
        from utils.session import session_scope

        with session_scope() as session:
            row = session.query(SessionModel).filter(SessionModel.id == session_id).first()
            if row is None:
                row = SessionModel(id=session_id)
                session.add(row)
            row.name = (name or "agent-run")[:50]
            row.init_description = (init_description or "")[:500]
            row.current_role_name = current_role_name
            row.current_planner_id = current_planner_id
            row.history_planner_ids = ",".join(history_planner_ids or [])
    except Exception:
        return


def save_report(thread_id: str, text: str) -> Optional[str]:
    try:
        directory = resolve_path(cfg("storage.report_dir", "data/reports"))
        directory.mkdir(parents=True, exist_ok=True)
        path = Path(directory) / f"{thread_id}.md"
        path.write_text(text or "", encoding="utf-8")
        return str(path)
    except Exception:
        return None


def reset_caches() -> None:
    """Tests only: forget open connections so a fresh temp path is used."""
    global _CHECKPOINTER, _STORE
    _CHECKPOINTER = None
    _STORE = None
    for conn in _CONN.values():
        try:
            conn.close()
        except Exception:
            pass
    _CONN.clear()
