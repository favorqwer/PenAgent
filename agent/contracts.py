"""Structured contracts exchanged with the LLM.

Every LLM boundary in the agent is Pydantic-validated. No `<json>` tagging, no regex
extraction of model output.
"""

from __future__ import annotations

from typing import List, Literal

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


class TaskVerdict(BaseModel):
    success: bool = Field(description="True only if the task objective was achieved")
    reason: str = Field(default="", description="Short justification")
    evidence: str = Field(
        default="", description="Exact quote from the output that proves the result"
    )
    confidence: Literal["low", "medium", "high"] = "medium"


class ScopeSpec(BaseModel):
    target: str = Field(description="IPv4 address, hostname or URL base")
    goal: str = Field(description="What the engagement must achieve")
    success_criteria: str = Field(description="Observable definition of success")
    constraints: List[str] = Field(
        default_factory=list, description="Things the agent must never do"
    )
