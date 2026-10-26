"""Task subgraph nodes: the ReAct loop for a single task.

gen  -> (gate) -> run -> gen ... -> evaluate

* ``gen`` writes one assistant turn containing tool calls.
* ``gate`` is the human approval checkpoint (command level).
* ``run`` executes tool calls, appends observations, extracts facts.
* ``evaluate`` applies the three-layer verdict and updates the plan.
"""

from __future__ import annotations

import difflib
import hashlib
from pathlib import Path
import re
import time
import uuid
from typing import Any, Dict, List

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.types import interrupt

from agent import memory, policy, telemetry
from agent.schema import TaskVerdict
from agent.context import observation_digest, observations_digest, save_raw_log, trim_for_context
from agent.findings import clip, extract_findings, has_compromise_evidence, render_facts
from agent.llm import call_config, chat, get_llm, structured
from agent.phases import get_phase, phase_max_steps
from agent.plan import instruction_fingerprint
from agent.telemetry import emit
from agent.prompts import (
    COMMAND_SYSTEM,
    EVALUATOR_SYSTEM,
    EVALUATOR_USER,
    RETRY_NOTE,
)
from agent.settings import cfg
from agent.tools import ALL_TOOLS, artifact_command, run_tool, tool_names, tools_for_phase
from utils.log_common import build_logger

logger = build_logger()

NUDGE = (
    "You must respond with a tool call. Use execute_kali_command to run a command, "
    "record_finding for a discovery, or finish_task when the task is complete."
)


def _phase_conf(state: Dict[str, Any]):
    return get_phase(state.get("phase", "collector"))


def _max_steps(state: Dict[str, Any]) -> int:
    return int(state.get("max_steps") or phase_max_steps(state.get("phase", "collector")))


def build_kickoff(state: Dict[str, Any]) -> List:
    conf = _phase_conf(state)
    task = state.get("current_task") or {}
    attempt = int(state.get("task_attempt", 0))
    facts = render_facts(
        state,
        int(cfg("context.max_planner_facts", 4000)),
        ports=instruction_fingerprint(task.get("instruction", ""), task.get("action", ""))["ports"],
    )
    system = COMMAND_SYSTEM.format(
        target=state.get("target", ""),
        phase_name=conf.name,
        phase_key=conf.key,
        phase_goal=conf.goal,
        instruction=task.get("instruction", ""),
        tools=tool_names(list(conf.allowed_tools)),
        tools_hint=conf.tools_hint,
    )
    body = [
        f"TASK: {task.get('instruction', '')}",
        f"ACTION TYPE: {task.get('action', 'Shell')}",
        f"ATTEMPT: {attempt + 1}",
        "",
        "KNOWN FACTS",
        facts,
    ]
    if state.get("target_memory"):
        body += ["", "PRIOR SESSION KNOWLEDGE", state["target_memory"]]

    verdict = state.get("task_verdict") or {}
    if attempt > 0 and verdict:
        body.append(
            RETRY_NOTE.format(
                reason=verdict.get("reason", "previous attempt failed"),
                evidence=clip(verdict.get("evidence", ""), 600),
            )
        )
    return [SystemMessage(content=system), HumanMessage(content="\n".join(body))]


def gen_node(state: Dict[str, Any]) -> Dict[str, Any]:
    messages = list(state.get("messages") or [])
    if not messages:
        messages = build_kickoff(state)
        # Seed the transcript so the model sees the instruction on the first call.
        seeded = True
    else:
        seeded = False

    messages = trim_for_context(
        messages,
        int(cfg("context.max_task_context_chars", 24000)),
        int(cfg("context.max_task_messages", 18)),
    )

    conf = _phase_conf(state)
    llm = get_llm("command").bind_tools(tools_for_phase(list(conf.allowed_tools)))
    # No local try/except here on purpose: a swallowed exception looks like a
    # semantic failure to the graph, so the node-level retry policy never fires
    # and one transient gateway error burns a step of the task budget.
    ai = llm.invoke(messages, config=call_config("command"))

    tool_calls = list(getattr(ai, "tool_calls", None) or [])
    done = any(call.get("name") == "finish_task" for call in tool_calls)
    steps = int(state.get("steps", 0)) + 1

    emit(
        {
            "kind": "step",
            "phase": state.get("phase", ""),
            "task": (state.get("current_task") or {}).get("instruction", ""),
            "step": steps,
            "tools": [call.get("name") for call in tool_calls],
            "text": (ai.content if isinstance(ai.content, str) else ""),
        }
    )

    delta: Dict[str, Any] = {"steps": steps, "task_done": done}
    if seeded:
        delta["messages"] = messages + [ai]
    else:
        delta["messages"] = [ai]
    if not tool_calls and not done:
        nudges = int(state.get("nudge_count", 0)) + 1
        delta["nudge_count"] = nudges
        if steps >= _max_steps(state) or nudges >= 2:
            delta["task_done"] = True
        else:
            delta["messages"] = delta["messages"] + [HumanMessage(content=NUDGE)]
    return delta


def route_after_gen(state: Dict[str, Any]) -> str:
    if state.get("task_done"):
        return "evaluate"
    if int(state.get("steps", 0)) >= _max_steps(state):
        return "evaluate"
    last = (state.get("messages") or [None])[-1]
    if getattr(last, "tool_calls", None):
        return "gate"
    return "gen"


def _commands_from(ai_message) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    for call in getattr(ai_message, "tool_calls", None) or []:
        name = call.get("name")
        args = call.get("args") or {}
        if name == "execute_kali_command":
            items.append(
                {
                    "tool": name,
                    "command": str(args.get("command", "")),
                    "intent": str(args.get("intent", "")),
                }
            )
        elif name == "http_probe":
            items.append(
                {
                    "tool": name,
                    "command": f"{args.get('method', 'GET')} {args.get('url', '')}",
                    "intent": "HTTP probe",
                }
            )
    return items


def gate_node(state: Dict[str, Any]) -> Dict[str, Any]:
    if not state.get("hitl_enabled") or state.get("task_approved"):
        return {"hitl_denied": False}

    phase = state.get("phase", "")
    approval_phases = cfg("hitl.require_approval_phases", []) or []
    if phase not in approval_phases:
        return {"hitl_denied": False}

    ai_message = (state.get("messages") or [None])[-1]
    pending = _commands_from(ai_message)
    if not pending:
        return {"hitl_denied": False}

    auto_approve = cfg("hitl.auto_approve_risk", ["read", "probe"]) or []
    decisions = []
    for item in pending:
        risk, reason = policy.classify_command(item["command"])
        item["risk"] = risk
        item["risk_reason"] = reason
        decisions.append(policy.requires_approval(risk, auto_approve))

    if not any(decisions):
        return {"hitl_denied": False}

    payload = {
        "type": "command_approval",
        "phase": phase,
        "task": (state.get("current_task") or {}).get("instruction", ""),
        "commands": [
            {
                "command": item["command"],
                "intent": item["intent"],
                "risk": item["risk"],
                "risk_reason": item["risk_reason"],
                "needs_approval": decision,
            }
            for item, decision in zip(pending, decisions)
        ],
    }
    decision = interrupt(payload) or {}

    if decision.get("approved"):
        update: Dict[str, Any] = {"hitl_denied": False}
        if decision.get("scope") == "task" or state.get("hitl_scope") == "task":
            update["task_approved"] = True
        overrides = decision.get("commands")
        if overrides:
            update["approved_commands"] = [str(c) for c in overrides]
        return update

    denials = int(state.get("denials", 0)) + 1
    reason = decision.get("reason") or "operator denied the command"
    update = {
        "hitl_denied": True,
        "denials": denials,
        "messages": [
            HumanMessage(
                content=(
                    f"OPERATOR DENIED the command. Reason: {reason}. "
                    "Do not request that command again. Choose a safer alternative, "
                    "or call finish_task(success=false) if the task cannot proceed."
                )
            )
        ],
    }
    if denials >= int(cfg("hitl.max_denials", 2)):
        update["task_done"] = True
        update["task_success"] = False
        update["last_output"] = f"Operator denied {denials} times: {reason}"
    return update


def route_after_gate(state: Dict[str, Any]) -> str:
    if state.get("hitl_denied"):
        if state.get("task_done"):
            return "evaluate"
        return "gen"
    return "run"


def _finding_delta(kind: str, identifier: str, description: str) -> Dict[str, Any]:
    kind = (kind or "").lower()
    identifier = (identifier or "").strip()
    if not identifier:
        return {}
    if kind == "port" and identifier.split("/")[0].isdigit():
        return {"open_ports": [int(identifier.split("/")[0])]}
    if kind == "service":
        port = identifier.split("/")[0].split(":")[0]
        if port.isdigit():
            name = ((description or "unknown").split() or ["unknown"])[0][:40]
            return {"services": {port: {"service": name, "banner": description}}}
        return {}
    if kind == "vulnerability":
        return {
            "vulnerabilities": [
                {"name": identifier, "identifier": identifier, "evidence": description}
            ]
        }
    if kind == "credential":
        return {"credentials": [identifier + (f" ({description})" if description else "")]}
    if kind == "flag":
        return {"flags": [identifier]}
    return {}


def _merge_facts(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    ports = list(base.get("open_ports") or [])
    for port in extra.get("open_ports") or []:
        if port not in ports:
            ports.append(port)
    if ports:
        out["open_ports"] = ports

    services = dict(base.get("services") or {})
    for port, info in (extra.get("services") or {}).items():
        merged = dict(services.get(port) or {})
        merged.update({k: v for k, v in info.items() if v})
        services[port] = merged
    if services:
        out["services"] = services

    for key in ("vulnerabilities", "credentials", "flags"):
        values = list(base.get(key) or [])
        for item in extra.get(key) or []:
            if item not in values:
                values.append(item)
        if values:
            out[key] = values
    return out


def unknown_tool_message(name: str, allowed) -> str:
    """Correct a hallucinated tool name instead of pretending it was a command."""
    options = [item for item in allowed if item != name]
    close = difflib.get_close_matches(name, options, n=1, cutoff=0.5)
    hint = f" Did you mean '{close[0]}'?" if close else ""
    return (
        f"Unknown tool '{name}'.{hint} Nothing was executed and nothing was charged to the budget. "
        f"Tools available right now: {', '.join(options) or 'none'}."
    )


def run_node(state: Dict[str, Any]) -> Dict[str, Any]:
    ai_message = (state.get("messages") or [None])[-1]
    calls = list(getattr(ai_message, "tool_calls", None) or [])
    overrides = list(state.get("approved_commands") or [])
    allowed = list(_phase_conf(state).allowed_tools)

    tool_messages: List[ToolMessage] = []
    logs: List[Dict[str, Any]] = []
    facts_update: Dict[str, Any] = {}
    output_acc = ""
    turn_output = ""
    commands_used = int(state.get("commands_used", 0))
    task_done = False
    task_success = bool(state.get("task_success"))

    override_index = 0
    stop_reason = ""
    for call in calls:
        name = call.get("name")
        args = dict(call.get("args") or {})
        call_id = call.get("id") or ""

        if name == "finish_task":
            task_done = True
            task_success = bool(args.get("success"))
            evidence = str(args.get("evidence") or args.get("summary") or "")
            output_acc += "\n[finish_task] " + evidence
            tool_messages.append(ToolMessage(content="acknowledged", tool_call_id=call_id))
            continue

        if name == "record_finding":
            facts_update = _merge_facts(
                facts_update,
                _finding_delta(
                    args.get("kind", ""),
                    args.get("identifier", ""),
                    args.get("description", ""),
                ),
            )
            tool_messages.append(
                ToolMessage(
                    content=f"recorded {args.get('kind')}: {args.get('identifier')}",
                    tool_call_id=call_id,
                )
            )
            continue

        if name not in ALL_TOOLS or name not in allowed:
            tool_messages.append(
                ToolMessage(
                    content=unknown_tool_message(name, allowed),
                    tool_call_id=call_id,
                    status="error",
                )
            )
            emit({"kind": "tool_error", "phase": state.get("phase", ""), "tool": name})
            continue

        if name == "execute_kali_command":
            command = str(args.get("command", ""))
            if override_index < len(overrides):
                command = overrides[override_index]
                override_index += 1
            args["command"] = command
        elif name == "read_artifact":
            command = artifact_command(
                str(args.get("path", "")).strip(),
                int(args.get("lines", 60)),
                int(args.get("offset", 0)),
            )
        else:
            # http_probe is the only remaining tool that reaches the executor.
            command = f"HTTP {args.get('method', 'GET')} {args.get('url', '')}"

        total_cap = int(state.get("max_commands") or cfg("budgets.max_commands", 250))
        allowance = int(state.get("phase_allowance") or 0)
        phase_start = int(state.get("phase_start_commands") or 0)
        if commands_used >= total_cap:
            stop_reason = "command budget"
        elif allowance and commands_used - phase_start >= allowance:
            stop_reason = "phase command budget"
        if stop_reason:
            # Hard cap: the command is never sent, so max_commands cannot be
            # exceeded by a task that keeps asking for more.
            tool_messages.append(
                ToolMessage(
                    content=f"Not executed: {stop_reason} exhausted.",
                    tool_call_id=call_id,
                    status="error",
                )
            )
            output_acc += f"\n[budget] {stop_reason} exhausted; task stopped before running: {command}"
            task_done = True
            task_success = False
            emit(
                {
                    "kind": "budget",
                    "phase": state.get("phase", ""),
                    "reason": stop_reason,
                    "commands_used": commands_used,
                }
            )
            break

        outcome = run_tool(name, args)
        commands_used += 1
        output_acc += "\n" + outcome.text
        turn_output += "\n" + (outcome.payload or outcome.text)
        log_file = save_raw_log(state.get("phase", ""), command, outcome.text)
        digest_content = observation_digest(
            outcome.text,
            int(cfg("context.max_observation_chars", 1800)),
        )
        if log_file and len(outcome.text) > 400:
            digest_content += f"\n[Full raw output saved to {log_file}]"

        tool_messages.append(
            ToolMessage(
                content=digest_content,
                tool_call_id=call_id,
                status=outcome.status,
            )
        )
        logs.append(
            {
                "id": f"{state.get('phase', '')}-{uuid.uuid4().hex[:10]}",
                "phase": state.get("phase", ""),
                "command": command,
                "output": clip(outcome.text, 500),
                "status": outcome.status,
                "exit_code": outcome.exit_code,
                "duration": outcome.duration,
                "log_path": log_file,
            }
        )
        emit(
            {
                "kind": "command",
                "phase": state.get("phase", ""),
                "command": command,
                "output": clip(outcome.text, 800),
                "status": outcome.status,
                "exit_code": outcome.exit_code,
            }
        )
        facts_update = _merge_facts(
            facts_update,
            extract_findings(outcome.text, command=command, phase=state.get("phase", "")),
        )

    # Convergence: identical observations with no new facts means the loop is idling.
    stall = int(state.get("stall_count", 0))
    fingerprint = hashlib.sha1(clip(turn_output.strip(), 2000).encode("utf-8", errors="replace")).hexdigest()
    if not turn_output.strip():
        pass
    elif facts_update:
        stall = 0
    elif fingerprint == (state.get("last_fingerprint") or ""):
        stall += 1
    else:
        stall = 0
    if stall >= int(cfg("budgets.max_stall_rounds", 2)) and not task_done:
        task_done = True
        task_success = False
        output_acc += "\n[stalled] identical observations and no new facts; ending the task early"
        emit({"kind": "stall", "phase": state.get("phase", ""), "rounds": stall})

    update: Dict[str, Any] = {
        "messages": tool_messages,
        "action_history": logs,
        "commands_used": commands_used,
        "last_output": output_acc.strip(),
        "approved_commands": [],
        "task_done": task_done,
        "task_success": task_success,
        "stall_count": stall,
        "last_fingerprint": fingerprint if turn_output.strip() else (state.get("last_fingerprint") or ""),
    }
    if stop_reason:
        update["phase_outcome"] = "budget"
    if facts_update:
        update.update(facts_update)
    return update


def route_after_run(state: Dict[str, Any]) -> str:
    if state.get("task_done"):
        return "evaluate"
    return "gen"


def _verdict(state: Dict[str, Any], digest: str) -> TaskVerdict:
    task = state.get("current_task") or {}
    # Errors propagate so the node-level retry policy can retry the call. A
    # "verdict: failed" returned from a transport error would mark a healthy
    # task as failed.
    return structured(
        TaskVerdict,
        [
            SystemMessage(content=EVALUATOR_SYSTEM),
            HumanMessage(
                content=EVALUATOR_USER.format(
                    instruction=task.get("instruction", ""),
                    phase=state.get("phase", ""),
                    phase_goal=_phase_conf(state).goal,
                    digest=digest,
                )
            ),
        ],
        node="evaluator",
    )


def _compress(text: str, limit: int) -> str:
    text = (text or "").strip()
    return clip(text, limit)


def evaluate_node(state: Dict[str, Any]) -> Dict[str, Any]:
    task = dict(state.get("current_task") or {})
    task_id = task.get("id", "")
    plan = list(state.get("plan") or [])
    attempt = int(state.get("task_attempt", 0))
    max_attempts = int(cfg("budgets.max_task_attempts", 2))

    model_claim = bool(state.get("task_success"))
    messages = state.get("messages") or []
    observations = observations_digest(messages, 8000)
    last_output = state.get("last_output", "")
    last_command = ""
    for message in reversed(messages):
        for call in getattr(message, "tool_calls", None) or []:
            if call.get("name") == "execute_kali_command":
                last_command = str((call.get("args") or {}).get("command", ""))
                break
        if last_command:
            break

    # One judge: the evaluator model. It sees the facts (tool output + commands),
    # never the assistant's own claims, so a hallucinated "uid=0" cannot pass.
    # No deterministic pre-filter decides the outcome; a scan that completed with
    # a negative result is judged the same way as any other observation.
    telemetry.bump(telemetry.COUNTER_VERDICTS)
    verdict = _verdict(state, observations)
    success = bool(verdict.success)

    new_attempt = attempt if success else attempt + 1
    if success:
        status = "success"
    elif new_attempt >= max_attempts:
        status = "failed"
    else:
        status = "pending"

    evidence = clip(verdict.evidence or last_output, int(cfg("context.max_evidence_chars", 4000)))
    if success:
        reason_text = verdict.reason or "objective achieved"
    else:
        reason_text = verdict.reason or "objective not achieved"
    result = _compress(reason_text, int(cfg("context.max_result_chars", 800)))

    emit(
        {
            "kind": "verdict",
            "phase": state.get("phase", ""),
            "task": task.get("instruction", ""),
            "success": success,
            "reason": reason_text,
            "evidence": clip(evidence or last_output, 400),
            "confidence": verdict.confidence,
        }
    )

    updated_plan: List[Dict[str, Any]] = []
    for item in plan:
        if item.get("id") != task_id:
            updated_plan.append(item)
            continue
        updated = dict(item)
        updated["status"] = status
        updated["attempts"] = new_attempt
        updated["result"] = result
        updated["evidence"] = evidence
        if last_command:
            commands = list(updated.get("commands") or [])
            if last_command not in commands:
                commands.append(last_command)
            updated["commands"] = commands
        updated_plan.append(updated)

    compromised = (
        bool(state.get("is_compromised"))
        or has_compromise_evidence(last_output)
        or has_compromise_evidence(observations)
    )

    update: Dict[str, Any] = {
        "plan": updated_plan,
        "task_attempt": new_attempt,
        "task_verdict": {
            "success": success,
            "reason": reason_text,
            "evidence": evidence,
            "confidence": verdict.confidence,
            "model_claim": model_claim,
        },
        "task_result": result,
        "task_success": success,
        "task_done": True,
        "is_compromised": compromised,
    }
    if status == "failed":
        # Only the exhausted failure is remembered; the planner reads this list
        # as "already attempted, do not repeat".
        detail = f" (last command: {last_command[:160]})" if last_command else ""
        update["tried_vectors"] = [f"[failed] {task.get('instruction', '')}{detail} -> {reason_text[:200]}"]

    extracted_facts = getattr(verdict, "facts", None)
    if extracted_facts:
        if extracted_facts.open_ports:
            update["open_ports"] = extracted_facts.open_ports
        if extracted_facts.services:
            update["services"] = extracted_facts.services
        if extracted_facts.vulnerabilities:
            update["vulnerabilities"] = extracted_facts.vulnerabilities
        if extracted_facts.credentials:
            update["credentials"] = extracted_facts.credentials
        if extracted_facts.flags:
            update["flags"] = extracted_facts.flags
        update["task_verdict"]["facts"] = extracted_facts.model_dump()

    return update
