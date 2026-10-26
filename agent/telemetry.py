"""Observability: token accounting, tracing and live progress events.

All three answer "what is the run doing right now" and none of them change it.
"""

import threading
from typing import Any, Dict, Iterable, Optional

from langchain_core.callbacks import BaseCallbackHandler

NODE_METADATA_KEY = "penagent_node"
# LangChain 1.x does not forward run metadata to ``on_llm_end`` (it only passes
# tags), so the node label travels as a tag and metadata is kept as a fallback.
NODE_TAG_PREFIX = "penagent_node:"
UNKNOWN_NODE = "unknown"

# Task-verdict counter: one evaluator call per finished task.
COUNTER_VERDICTS = "verdicts_evaluated"

_LOCK = threading.Lock()
_CALLS: Dict[str, int] = {}
_PROMPT_TOKENS: Dict[str, int] = {}
_COMPLETION_TOKENS: Dict[str, int] = {}
_COUNTERS: Dict[str, int] = {}


def reset() -> None:
    with _LOCK:
        _CALLS.clear()
        _PROMPT_TOKENS.clear()
        _COMPLETION_TOKENS.clear()
        _COUNTERS.clear()


def bump(name: str, amount: int = 1) -> None:
    with _LOCK:
        _COUNTERS[name] = _COUNTERS.get(name, 0) + int(amount)


def record(node: str, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
    node = node or UNKNOWN_NODE
    with _LOCK:
        _CALLS[node] = _CALLS.get(node, 0) + 1
        _PROMPT_TOKENS[node] = _PROMPT_TOKENS.get(node, 0) + int(prompt_tokens or 0)
        _COMPLETION_TOKENS[node] = _COMPLETION_TOKENS.get(node, 0) + int(completion_tokens or 0)


def _usage_from_response(response: Any) -> tuple:
    """Extract (prompt, completion) from either gateway-style or message-style payloads."""
    llm_output = getattr(response, "llm_output", None) or {}
    tokens = llm_output.get("token_usage") or llm_output.get("usage") or {}
    prompt = tokens.get("prompt_tokens") or tokens.get("input_tokens") or 0
    completion = tokens.get("completion_tokens") or tokens.get("output_tokens") or 0
    if prompt or completion:
        return int(prompt), int(completion)

    for generation in getattr(response, "generations", None) or []:
        for item in generation:
            message = getattr(item, "message", None)
            meta = getattr(message, "usage_metadata", None) or {}
            if meta:
                return int(meta.get("input_tokens") or 0), int(meta.get("output_tokens") or 0)
    return 0, 0


class UsageTracker(BaseCallbackHandler):
    """Records one line per LLM call, labelled with the node that made it."""

    @staticmethod
    def _node_from(kwargs: Any) -> str:
        for tag in kwargs.get("tags") or []:
            text = str(tag)
            if text.startswith(NODE_TAG_PREFIX):
                return text[len(NODE_TAG_PREFIX) :] or UNKNOWN_NODE
        metadata = kwargs.get("metadata") or {}
        return str(metadata.get(NODE_METADATA_KEY) or UNKNOWN_NODE)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        try:
            node = self._node_from(kwargs)
            prompt, completion = _usage_from_response(response)
            record(node, prompt, completion)
        except Exception:  # noqa: BLE001 - accounting must never break a run
            return


TRACKER = UsageTracker()


def snapshot() -> Dict[str, Any]:
    with _LOCK:
        nodes = sorted(set(_CALLS) | set(_PROMPT_TOKENS) | set(_COMPLETION_TOKENS))
        by_node = {
            node: {
                "calls": _CALLS.get(node, 0),
                "prompt_tokens": _PROMPT_TOKENS.get(node, 0),
                "completion_tokens": _COMPLETION_TOKENS.get(node, 0),
            }
            for node in nodes
        }
        totals = {
            "calls": sum(item["calls"] for item in by_node.values()),
            "prompt_tokens": sum(item["prompt_tokens"] for item in by_node.values()),
            "completion_tokens": sum(item["completion_tokens"] for item in by_node.values()),
        }
        totals["tokens"] = totals["prompt_tokens"] + totals["completion_tokens"]
        return {"by_node": by_node, "total": totals, "counters": dict(_COUNTERS)}


def render_lines(snapshot_data: Optional[Dict[str, Any]] = None) -> Iterable[str]:
    data = snapshot_data or snapshot()
    total = data["total"]
    counters = data.get("counters") or {}
    evaluated = counters.get(COUNTER_VERDICTS, 0)
    yield f"- LLM calls: {total['calls']} ({total['tokens']} tokens)"
    for node, item in (data.get("by_node") or {}).items():
        yield (
            f"  - {node}: {item['calls']} calls, "
            f"{item['prompt_tokens']} in / {item['completion_tokens']} out"
        )
    if evaluated:
        yield f"- Task verdicts: {evaluated}"


# --- LangSmith tracing ---------------------------------------------------

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


# --- live progress events ------------------------------------------------

from typing import Any, Dict


def emit(event: Dict[str, Any]) -> None:
    try:
        from langgraph.config import get_stream_writer

        get_stream_writer()(event)
    except Exception:
        return
