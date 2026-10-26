"""State schemas for the layered PenAgent graphs.

Three levels, three schemas:

* ``FactsState``      - shared, append-mostly knowledge (ports/services/vulns...)
* ``EngagementState`` - top-level orchestration (phase progression, budgets)
* ``PhaseState``      - one penetration phase (plan, replanning, task pointer)
* ``TaskState``       - one task's ReAct scratchpad (dies with the task subgraph)

Only keys present in a schema are passed into / bubbled out of a compiled
subgraph, so the scratchpad never leaks into the long-lived state.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Dict, List, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


class ServiceInfo(TypedDict, total=False):
    service: str
    banner: str
    raw: str


class PenTask(TypedDict, total=False):
    id: str
    instruction: str
    action: str
    depends_on: List[str]
    status: str  # pending | running | success | failed | blocked
    attempts: int
    commands: List[str]
    result: str
    evidence: str


class ActionLog(TypedDict, total=False):
    phase: str
    command: str
    output: str
    status: str
    duration: float
    log_path: str
    exit_code: int


def _vuln_key(v: Dict[str, Any]) -> str:
    for field in ("cve", "identifier", "name", "title"):
        value = v.get(field)
        if value:
            return f"{field}:{str(value).lower()}"
    return f"raw:{str(v).lower()[:120]}"


def merge_ports(a: List[int], b: List[int]) -> List[int]:
    out = list(dict.fromkeys(a or []))
    for port in b or []:
        if port not in out:
            out.append(port)
    return out


def merge_services(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Port-keyed deep merge. Never let an empty value erase a known banner."""
    out: Dict[str, Any] = dict(a or {})
    for port, value in (b or {}).items():
        if isinstance(value, str):
            value = {"service": value}
        prev = out.get(port) or {}
        if isinstance(prev, str):
            prev = {"service": prev}
        merged = dict(prev)
        for field, field_value in (value or {}).items():
            if field_value not in (None, "", [], {}):
                merged[field] = field_value
        out[port] = merged
    return out


def merge_vulns(a: List[Dict[str, Any]], b: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = list(a or [])
    seen = {_vuln_key(v) for v in out}
    for item in b or []:
        key = _vuln_key(item)
        if key not in seen:
            out.append(item)
            seen.add(key)
    return out


def merge_unique(a: List[str], b: List[str]) -> List[str]:
    out = list(dict.fromkeys(a or []))
    seen = set(out)
    for item in b or []:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out


def merge_events(a: List[Dict[str, Any]], b: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicating merge for event logs.

    Subgraph boundaries cause the same list to be merged twice (child returns the
    parent's copy plus its own). Content ids make that idempotent; events without
    an id fall back to structural equality, otherwise every re-merge would
    duplicate them.
    """
    out = list(a or [])
    seen = {item.get("id") for item in out if isinstance(item, dict) and item.get("id")}
    for item in b or []:
        key = item.get("id") if isinstance(item, dict) else None
        if key:
            if key in seen:
                continue
            seen.add(key)
        elif item in out:
            continue
        out.append(item)
    return out


class FactsState(TypedDict, total=False):
    """Knowledge every level is allowed to read and contribute to."""

    target: str
    open_ports: Annotated[List[int], merge_ports]
    services: Annotated[Dict[str, ServiceInfo], merge_services]
    vulnerabilities: Annotated[List[Dict[str, Any]], merge_vulns]
    credentials: Annotated[List[str], merge_unique]
    flags: Annotated[List[str], merge_unique]
    tried_vectors: Annotated[List[str], merge_unique]
    is_compromised: bool


class EngagementState(FactsState, total=False):
    goal: str
    success_criteria: str
    constraints: List[str]

    phase: str
    phase_index: int
    phase_outcome: str

    phase_summaries: Annotated[List[str], merge_unique]
    action_history: Annotated[List[ActionLog], merge_events]
    plan_ids: Annotated[List[str], merge_unique]
    phase_metrics: Annotated[List[Dict[str, Any]], merge_events]

    backtrack_count: int
    max_backtracks: int

    deadline_ts: float
    max_commands: int
    commands_used: int

    hitl_enabled: bool
    hitl_scope: str
    dry_run: bool
    thread_id: str
    final_report: str
    target_memory: str


class PhaseState(FactsState, total=False):
    goal: str
    success_criteria: str
    constraints: List[str]
    target_memory: str

    phase: str
    phase_index: int
    phase_outcome: str

    plan: List[PenTask]
    plan_id: str
    plan_version: int
    replan_count: int
    max_replans: int
    max_tasks: int

    phase_start_commands: int
    phase_allowance: int

    current_task: PenTask
    task_attempt: int
    task_verdict: Dict[str, Any]
    task_result: str
    max_steps: int

    phase_summaries: Annotated[List[str], merge_unique]
    action_history: Annotated[List[ActionLog], merge_events]
    plan_ids: Annotated[List[str], merge_unique]

    deadline_ts: float
    max_commands: int
    commands_used: int
    hitl_enabled: bool
    hitl_scope: str


class TaskState(FactsState, total=False):
    goal: str
    target_memory: str
    phase: str
    phase_index: int
    phase_outcome: str

    current_task: PenTask
    task_attempt: int
    task_verdict: Dict[str, Any]
    task_result: str
    plan: List[PenTask]
    plan_id: str
    plan_version: int
    replan_count: int
    max_replans: int
    max_tasks: int

    messages: Annotated[List[AnyMessage], add_messages]
    steps: int
    max_steps: int
    nudge_count: int
    task_done: bool
    task_success: bool
    hitl_denied: bool
    denials: int
    task_approved: bool
    approved_commands: List[str]
    last_output: str

    # Convergence guard: identical observations with no new facts.
    last_fingerprint: str
    stall_count: int

    phase_summaries: Annotated[List[str], merge_unique]
    action_history: Annotated[List[ActionLog], merge_events]
    plan_ids: Annotated[List[str], merge_unique]

    deadline_ts: float
    max_commands: int
    commands_used: int
    hitl_enabled: bool
    hitl_scope: str


# --- LLM contracts --------------------------------------------------------

from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field


class TaskSpec(BaseModel):
    id: str = Field(description="Short unique id inside the plan, e.g. t1, t2")
    dependent_task_ids: List[str] = Field(
        default_factory=list,
        description="Ids of tasks that must succeed before this one can run",
    )
    instruction: str = Field(
        description="Concrete action, must mention the target IP or port"
    )
    action: Literal["Shell", "Web", "Enumerate", "Exploit"] = Field(
        default="Shell", description="High level action type"
    )


class PlanSpec(BaseModel):
    tasks: List[TaskSpec] = Field(description="1-5 ordered tasks for this phase")


class ExtractedFacts(BaseModel):
    """Structured security facts confirmed during a task execution."""
    open_ports: List[int] = Field(
        default_factory=list, description="List of confirmed newly open ports, e.g. [80, 443]"
    )
    services: Dict[str, str] = Field(
        default_factory=dict, description="Port to service banner mapping, e.g. {'80': 'nginx 1.18'}"
    )
    vulnerabilities: List[Dict[str, Any]] = Field(
        default_factory=list, description="Discovered vulnerabilities, e.g. [{'cve': 'CVE-2021-44228', 'desc': 'Log4Shell'}]"
    )
    credentials: List[str] = Field(
        default_factory=list, description="Found credentials or tokens, e.g. ['admin:password123']"
    )
    flags: List[str] = Field(
        default_factory=list, description="Captured CTF flags, e.g. ['flag{...}']"
    )


class TaskVerdict(BaseModel):
    success: bool = Field(description="True only if the task objective was achieved")
    reason: str = Field(default="", description="Short justification")
    evidence: str = Field(
        default="", description="Exact quote from the output that proves the result"
    )
    confidence: Literal["low", "medium", "high"] = "medium"
    facts: ExtractedFacts = Field(
        default_factory=ExtractedFacts,
        description="Structured security facts confirmed during this task",
    )
