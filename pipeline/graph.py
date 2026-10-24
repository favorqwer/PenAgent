"""
LangGraph assembly and compilation for PenAgent.
Builds the state graph, registers nodes, attaches conditional edges,
and equips the workflow with an SQLite checkpoint saver for resilience and time-travel.
"""

import sqlite3
from pathlib import Path
from typing import Optional

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph

from config.config import Configs
from pipeline.nodes import collector_node, exploiter_node, reporter_node, scanner_node
from pipeline.router import route_after_collector, route_after_exploiter, route_after_scanner
from pipeline.state import PentestState


def create_pentest_graph(
    db_path: Optional[str] = None,
    hitl_enabled: bool = False
):
    """
    Constructs and compiles the PenAgent LangGraph workflow.
    
    Args:
        db_path: Path to the SQLite database file for checkpoint persistence.
        hitl_enabled: If True, pauses execution before 'exploiter' node for human approval.
    
    Returns:
        CompiledStateGraph ready for streaming or invocation.
    """
    workflow = StateGraph(PentestState)

    # 1. Register specialized Agent Nodes
    workflow.add_node("collector", collector_node)
    workflow.add_node("scanner", scanner_node)
    workflow.add_node("exploiter", exploiter_node)
    workflow.add_node("reporter", reporter_node)

    # 2. Add Graph Entry Point
    workflow.add_edge(START, "collector")

    # 3. Add Conditional Edges for Dynamic Routing & Backtracking
    workflow.add_conditional_edges(
        "collector",
        route_after_collector,
        {
            "scanner": "scanner",
            "collector": "collector",
            "reporter": "reporter"
        }
    )

    workflow.add_conditional_edges(
        "scanner",
        route_after_scanner,
        {
            "exploiter": "exploiter",
            "scanner": "scanner",
            "collector": "collector",
            "reporter": "reporter"
        }
    )

    workflow.add_conditional_edges(
        "exploiter",
        route_after_exploiter,
        {
            "reporter": "reporter",
            "exploiter": "exploiter",
            "scanner": "scanner"
        }
    )

    # 4. Final Node Transitions to END
    workflow.add_edge("reporter", END)

    # 5. Checkpoint & Memory Configuration
    if db_path == ":memory:":
        conn = sqlite3.connect(":memory:", check_same_thread=False)
    else:
        if db_path is None:
            db_file = Path(Configs.db_config.sqlite_path).resolve()
        else:
            db_file = Path(db_path).resolve()

        db_file.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_file), check_same_thread=False)
    checkpointer = SqliteSaver(conn)

    # 6. Optional Human-In-The-Loop (HITL) Interruption
    interrupt_nodes = ["exploiter"] if hitl_enabled else []

    app = workflow.compile(
        checkpointer=checkpointer,
        interrupt_before=interrupt_nodes
    )

    return app
