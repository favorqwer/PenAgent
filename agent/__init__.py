"""Layered autonomous pentest agent.

Engagement graph -> phase subgraph -> task subgraph, built on LangGraph 1.x.
The legacy `penagent` role chain and its benchmark are untouched.
"""

__all__ = ["create_agent_graph", "run_agent"]


def create_agent_graph(*args, **kwargs):  # lazy import keeps `import agent` cheap
    from agent.graph import create_agent_graph as _create

    return _create(*args, **kwargs)


def run_agent(*args, **kwargs):
    from agent.runner import run_agent as _run

    return _run(*args, **kwargs)
