"""The final report: skeleton, cost appendix and archive.

Kept apart from the graph nodes so the write-up can be read, tested and changed
without touching orchestration. The reporter node decides *when* to write; this
module decides *what* is written.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from agent import telemetry
from agent.findings import render_facts
from agent.settings import cfg, resolve_path
from utils.log_common import build_logger

logger = build_logger()


def deterministic(state: Dict[str, Any]) -> str:
    """Report skeleton built only from recorded state - always available."""
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


def usage_section() -> str:
    lines: List[str] = list(telemetry.render_lines())
    if not lines:
        return ""
    return "\n\n## Run cost\n" + "\n".join(lines)


def save(thread_id: str, text: str) -> Optional[str]:
    try:
        directory = resolve_path(cfg("storage.report_dir", "data/reports"))
        directory.mkdir(parents=True, exist_ok=True)
        path = Path(directory) / f"{thread_id}.md"
        path.write_text(text or "", encoding="utf-8")
        return str(path)
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[report] could not write report for {thread_id}: {exc}")
        return None
