"""Runtime settings for the agent pipeline.

Isolated from the legacy configuration so the old `penagent` flow keeps working
exactly as before. Defaults live here; overrides live in
`config/yaml/agent_config.yaml`.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict

from config.config import Configs

try:  # ruamel is already a project dependency
    from ruamel.yaml import YAML

    def _read_yaml(path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        yaml = YAML(typ="safe")
        with path.open("r", encoding="utf-8") as fh:
            return yaml.load(fh) or {}

except Exception:  # pragma: no cover - fallback only
    def _read_yaml(path: Path) -> Dict[str, Any]:
        return {}


DEFAULT_CONFIG: Dict[str, Any] = {
    "budgets": {
        "deadline_minutes": 60,
        "max_commands": 250,
        "max_backtracks": 1,
        "max_task_attempts": 2,
        "max_replans": 2,
        "max_steps_per_task": 8,
        "llm_retries": 3,
        "max_stall_rounds": 2,
        # Split the command budget so late phases cannot be starved by recon.
        "phase_share": {"collector": 0.3, "scanner": 0.3, "exploiter": 0.4},
        "max_tasks_per_phase": {"collector": 3, "scanner": 4, "exploiter": 5},
    },
    "models": {
        "planner": "",
        "command": "",
        "evaluator": "",
        "summarizer": "",
        "reporter": "",
        # This gateway's default model thinks before every answer: 146-341
        # reasoning tokens for a one-line reply, billed and 2-3x slower.
        "reasoning_effort": "none",
        "reasoning_effort_by_node": {},
        # Honouring HTTP(S)_PROXY costs ~3s of env resolution at startup and does
        # not speed this gateway up; opt in only if your network needs it.
        "respect_env_proxy": False,
    },
    "temperatures": {
        "planner": 0.0,
        "command": 0.15,
        "evaluator": 0.0,
        "summarizer": 0.2,
        "reporter": 0.2,
    },
    "hitl": {
        "enabled": False,
        "require_approval_phases": ["exploiter"],
        "auto_approve_risk": ["read", "probe"],
        "max_denials": 2,
    },
    "context": {
        "max_tool_output": 6000,
        "max_task_messages": 18,
        "max_task_context_chars": 24000,
        "max_result_chars": 800,
        "max_evidence_chars": 4000,
        "max_planner_facts": 4000,
        "max_observation_chars": 1800,
    },
    "storage": {
        "checkpoint_path": "data/graph_checkpoints.db",
        "store_path": "data/graph_store.db",
        "report_dir": "data/reports",
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


_CONFIG_PATH = Configs.CONFIG_YAML_DIR / "agent_config.yaml"
_CACHE: Dict[str, Any] | None = None


def load() -> Dict[str, Any]:
    global _CACHE
    _CACHE = _deep_merge(DEFAULT_CONFIG, _read_yaml(_CONFIG_PATH))
    return _CACHE


def cfg(path: str, default: Any = None) -> Any:
    """Read a dotted config path, e.g. cfg('budgets.max_steps_per_task')."""
    if _CACHE is None:
        load()
    node: Any = _CACHE
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def set_value(path: str, value: Any) -> None:
    """Used by tests and the CLI to override a single setting in-process."""
    if _CACHE is None:
        load()
    parts = path.split(".")
    node = _CACHE
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Configs.PENTEST_ROOT / candidate
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate
