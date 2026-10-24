"""LangSmith tracing for the layered agent.

Ported from the v1 pipeline so observability survives the removal of `graph`.
Tracing is opt-in via ``basic_config.yaml -> langsmith.enabled``.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from config.config import Configs
from utils.log_common import build_logger

logger = build_logger()


def init_langsmith_tracing() -> bool:
    settings = getattr(Configs.basic_config, "langsmith", {}) or {}
    enabled = bool(settings.get("enabled"))
    api_key = str(settings.get("api_key") or "").strip()
    project = str(settings.get("project") or "PenAgent").strip()
    endpoint = str(settings.get("endpoint") or "").strip()

    if enabled and api_key:
        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        os.environ["LANGCHAIN_API_KEY"] = api_key
        os.environ["LANGCHAIN_PROJECT"] = project
        if endpoint:
            os.environ["LANGCHAIN_ENDPOINT"] = endpoint
        # langsmith 0.14 starts a compression sub-thread lazily; when it fires
        # during interpreter shutdown it raises "can't create new thread".
        # Disabling run compression avoids that race with no functional loss.
        os.environ["LANGSMITH_DISABLE_RUN_COMPRESSION"] = "true"
        logger.info(f"[LangSmith] tracing enabled, project='{project}' endpoint='{endpoint or 'default'}'")
        return True

    os.environ["LANGCHAIN_TRACING_V2"] = "false"
    return False


def build_run_config(
    thread_id: str,
    target: str,
    hitl: bool,
    dry_run: bool,
    phase: str = "engagement",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """RunnableConfig with a readable run name, tags and engagement metadata."""
    metadata: Dict[str, Any] = {
        "target": target,
        "thread_id": thread_id,
        "hitl": hitl,
        "dry_run": dry_run,
        "phase": phase,
        "framework": "penagent",
        "orchestrator": "langgraph-3-level",
    }
    if extra:
        metadata.update(extra)

    return {
        "configurable": {"thread_id": thread_id},
        "run_name": f"penagent/{phase}/{target}",
        "metadata": metadata,
        "tags": [
            "penagent",
            f"target:{target}",
            "dry-run" if dry_run else "live",
            "hitl" if hitl else "auto",
        ],
    }


def flush_tracing() -> None:
    """Flush queued traces before the interpreter exits (avoids shutdown races)."""
    try:
        from langsmith import Client

        Client().flush()
    except Exception:
        return
