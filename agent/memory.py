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
from utils.log_common import build_logger

logger = build_logger()

_CHECKPOINTER = None
_STORE = None
_CONN: Dict[Any, sqlite3.Connection] = {}


def _conn(path_key: str, *, autocommit: bool = False) -> sqlite3.Connection:
    """One long-lived connection per (path, isolation mode).

    ``SqliteStore`` issues explicit ``BEGIN``/``COMMIT`` and therefore needs
    autocommit mode (``isolation_level=None``), exactly like its own
    ``from_conn_string`` factory. ``SqliteSaver`` relies on implicit
    transactions, so it keeps the default mode. Sharing one connection between
    them makes every store write fail with "cannot start a transaction within a
    transaction".
    """
    key = (path_key, autocommit)
    if key not in _CONN:
        path = resolve_path(path_key)
        conn = sqlite3.connect(
            str(path),
            check_same_thread=False,
            isolation_level=None if autocommit else "",
        )
        _CONN[key] = conn
    return _CONN[key]


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
        _STORE = SqliteStore(_conn(path, autocommit=True))
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
    except Exception as exc:  # noqa: BLE001 - memory is an optimisation, never a dependency
        logger.warning(f"[memory] target lookup failed for {target}: {exc}")
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
    except Exception as exc:  # noqa: BLE001
        # Degraded, not fatal: the next session loses prior knowledge.
        logger.warning(f"[memory] could not persist target memory for {target}: {exc}")
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
