"""
State definition for PenAgent LangGraph workflow.
"""

from typing import Annotated, Dict, List, Optional, Any
from typing_extensions import TypedDict
import operator


class Finding(TypedDict, total=False):
    type: str              # "port", "service", "vulnerability", "credential", "flag"
    identifier: str        # e.g., "80/tcp", "CVE-2021-41773", "root:toor"
    description: str       # details of the finding
    confidence: str        # "confirmed", "probable", "tentative"
    metadata: Dict[str, Any]


class ActionLog(TypedDict, total=False):
    role: str              # "collector", "scanner", "exploiter"
    instruction: str       # High-level task
    command: str           # Raw shell command dispatched to Kali
    output: str            # Output captured from Kali shell
    status: str            # "success", "failed", "timeout"
    timestamp: float


def merge_dicts(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to merge two dictionaries immutably."""
    merged = dict(a)
    merged.update(b)
    return merged


class PentestState(TypedDict, total=False):
    """
    Unified global state dictionary for PenAgent multi-agent workflow.
    Managed and checkpointed automatically by LangGraph SqliteSaver.
    """
    # Core target configuration
    target: str                                     # Target IP or domain (e.g. 100.84.151.2)
    task_description: str                           # Initial penetration goal

    # Shared reconnaissance and vulnerability findings
    open_ports: Annotated[List[int], operator.add]  # List of discovered open ports
    services: Annotated[Dict[str, str], merge_dicts]# Port -> Service name/version mapping
    vulnerabilities: Annotated[List[Dict[str, Any]], operator.add] # Confirmed/suspected CVEs
    credentials: Annotated[List[str], operator.add] # Discovered credentials/tokens
    flags: Annotated[List[str], operator.add]       # Captured flags/proof of compromise

    # Workflow stage and control flow
    current_phase: str                              # "collector", "scanner", "exploiter", "reporter"
    phase_step_count: int                           # Current iteration count in this phase
    max_phase_steps: int                            # Maximum allowed iterations per phase
    retry_count: int                                # Exploitation attempt counter for current target
    max_retries: int                                # Max retry attempts before backtracking
    is_compromised: bool                            # Target fully compromised / root shell obtained

    # Auditing and memory
    action_history: Annotated[List[ActionLog], operator.add] # Log of all executed commands
    phase_summaries: Annotated[List[str], operator.add]      # Summaries produced during role handover
    current_plan: List[str]                         # Remaining tasks in current phase
    last_error: Optional[str]                       # Last error encountered for self-correction
