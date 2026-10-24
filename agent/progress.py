"""Live progress events pushed through LangGraph's custom stream channel.

Using the custom channel keeps the CLI/WebUI decoupled from state shape and
works identically at every subgraph depth.
"""

from __future__ import annotations

from typing import Any, Dict


def emit(event: Dict[str, Any]) -> None:
    try:
        from langgraph.config import get_stream_writer

        get_stream_writer()(event)
    except Exception:
        return
