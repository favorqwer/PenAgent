"""
Conditional edge routers for PenAgent LangGraph workflow.
Controls dynamic branching, self-correction loops, and phase backtracking.
"""

from typing import Literal
from loguru import logger
from pipeline.state import PentestState
from utils.log_common import build_logger

app_logger = build_logger()


def route_after_collector(state: PentestState) -> Literal["scanner", "collector", "reporter"]:
    """
    Decides next step after Reconnaissance (Collector) phase.
    """
    ports = state.get("open_ports", [])
    step = state.get("phase_step_count", 0)
    max_steps = state.get("max_phase_steps", 3)

    if ports:
        app_logger.info(f"[Router] Collector found open ports: {ports}. Advancing to 'scanner'.")
        return "scanner"

    if step < max_steps:
        app_logger.warning(f"[Router] No ports discovered yet (step {step}/{max_steps}). Retrying 'collector'.")
        return "collector"

    app_logger.warning("[Router] Max collector steps reached without open ports. Proceeding to 'reporter'.")
    return "reporter"


def route_after_scanner(state: PentestState) -> Literal["exploiter", "scanner", "collector", "reporter"]:
    """
    Decides next step after Vulnerability Scanning (Scanner) phase.
    """
    vulns = state.get("vulnerabilities", [])
    ports = state.get("open_ports", [])
    step = state.get("phase_step_count", 0)
    max_steps = state.get("max_phase_steps", 3)

    if vulns:
        app_logger.info(f"[Router] Scanner identified {len(vulns)} potential vulnerabilities. Advancing to 'exploiter'.")
        return "exploiter"

    # If open ports exist even if no explicit CVE found, try generic exploitation / PoC
    if ports:
        app_logger.info(f"[Router] Open ports present ({ports}). Advancing to 'exploiter' for active service probing.")
        return "exploiter"

    if step < max_steps:
        app_logger.info(f"[Router] Continuing vulnerability enumeration (step {step}/{max_steps}).")
        return "scanner"

    app_logger.warning("[Router] Vulnerability scan completed with no viable entry points. Proceeding to 'reporter'.")
    return "reporter"


def route_after_exploiter(state: PentestState) -> Literal["reporter", "exploiter", "scanner"]:
    """
    Decides next step after Exploitation (Exploiter) phase.
    Enables autonomous backtracking and retry loops.
    """
    is_compromised = state.get("is_compromised", False)
    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)

    if is_compromised:
        app_logger.success("[Router] Target successfully compromised! Advancing to 'reporter'.")
        return "reporter"

    if retry_count < max_retries:
        app_logger.info(f"[Router] Exploit attempt {retry_count}/{max_retries} unsuccessful. Retrying 'exploiter' with alternative payload.")
        return "exploiter"

    # Backtracking: Current exploit path failed. Return to scanner to find new attack surfaces.
    app_logger.warning(f"[Router] Max exploit retries ({max_retries}) reached. BACKTRACKING to 'scanner' to discover alternative attack vectors.")
    return "scanner"
