"""
LangSmith observability and tracing integration for PenAgent.
Automatically configures background OpenTelemetry/LangChain tracing
and injects domain-specific cybersecurity metadata and tags.
"""

import os
from typing import Any, Dict
from config.config import Configs
from utils.log_common import build_logger

logger = build_logger()


def init_langsmith_tracing() -> bool:
    """
    Initializes LangSmith tracing if enabled in config/yaml/basic_config.yaml.
    Sets necessary environment variables before graph execution.
    """
    langsmith_cfg = getattr(Configs.basic_config, "langsmith", {}) or {}
    enabled = langsmith_cfg.get("enabled", False)
    api_key = langsmith_cfg.get("api_key", "").strip()
    project = langsmith_cfg.get("project", "PenAgent").strip()
    endpoint = langsmith_cfg.get("endpoint", "https://api.smith.langchain.com").strip()

    if enabled and api_key:
        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        os.environ["LANGCHAIN_API_KEY"] = api_key
        os.environ["LANGCHAIN_PROJECT"] = project
        if endpoint:
            os.environ["LANGCHAIN_ENDPOINT"] = endpoint

        logger.info(f"[LangSmith] Tracing ACTIVATED. Project: '{project}' -> {endpoint}")
        return True
    else:
        # Graceful fallback: do not trace if disabled or key missing
        os.environ["LANGCHAIN_TRACING_V2"] = "false"
        return False


def get_pipeline_run_config(
    thread_id: str,
    target: str,
    hitl_enabled: bool = False
) -> Dict[str, Any]:
    """
    Constructs LangGraph runtime configuration equipped with 
    LangSmith tags and penetration testing engagement metadata.
    """
    init_langsmith_tracing()

    kali_ip = Configs.basic_config.kali.get("hostname", "100.74.213.15")

    return {
        "configurable": {
            "thread_id": thread_id
        },
        "metadata": {
            "target_host": target,
            "attack_machine": kali_ip,
            "hitl_enabled": hitl_enabled,
            "session_id": thread_id,
            "orchestrator": "LangGraph StateGraph",
            "framework": "PenAgent"
        },
        "tags": [
            "PenAgent",
            f"Target:{target}",
            "Autonomous-Pentest",
            f"HITL:{'Enabled' if hitl_enabled else 'Disabled'}"
        ]
    }
