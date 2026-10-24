"""Task subgraph nodes: the ReAct loop for a single task.

gen  -> (gate) -> run -> gen ... -> evaluate

* ``gen`` writes one assistant turn containing tool calls.
* ``gate`` is the human approval checkpoint (command level).
* ``run`` executes tool calls, appends observations, extracts facts.
* ``evaluate`` applies the three-layer verdict and updates the plan.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.types import interrupt

from agent import memory, policy
from agent.contracts import TaskVerdict
from agent.findings import (
    clip,
    evidence_verdict,
    extract_findings,
    has_compromise_evidence,
    observations_digest,
    render_facts,
    transcript_digest,
)
from agent.llm import chat, get_llm, structured
from agent.phases import get_phase, phase_max_steps
from agent.progress import emit
from agent.prompts import (
    COMMAND_SYSTEM,
    EVALUATOR_SYSTEM,
    EVALUATOR_USER,
    RETRY_NOTE,
    SUMMARIZER_SYSTEM,
)
from agent.settings import cfg
from agent.tools import ALL_TOOLS, tool_names, tools_for_phase

NUDGE = (
    "You must respond with a tool call. Use execute_kali_command to run a command, "
    "record_finding for a discovery, or finish_task when the task is complete."
)

TEXT_COMMAND_PREFIXES = (
    "nmap ", "nikto ", "curl ", "gobuster ", "dirb ", "searchsploit ", "whatweb ",
    "wget ", "sqlmap ", "hydra ", "nc ", "ncat ", "msfconsole ", "python3 ",
    "python ", "enum4linux ", "smbclient ", "smbmap ", "dig ", "whois ",
)


def extract_text_command(content: Any) -> str:
    """Fallback for models that answer with a command in prose instead of a tool call."""
    if not isinstance(content, str) or not content.strip():
        return ""
    text = content.replace("```", "")
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        line = line.lstrip("$").strip()
        if line[:2].rstrip(".").isdigit():
            line = line.split(".", 1)[1].strip() if "." in line else line
        line = line.lstrip("-*").strip()
        lowered = line.lower()
        if any(lowered.startswith(prefix) for prefix in TEXT_COMMAND_PREFIXES) and len(line) <= 500:
            return line
    return ""


def _phase_conf(state: Dict[str, Any]):
    return get_phase(state.get("phase", "collector"))


def _max_steps(state: Dict[str, Any]) -> int:
    return int(state.get("max_steps") or phase_max_steps(state.get("phase", "collector")))


def build_kickoff(state: Dict[str, Any]) -> List:
    conf = _phase_conf(state)
    task = state.get("current_task") or {}
    attempt = int(state.get("task_attempt", 0))
    facts = render_facts(state, int(cfg("context.max_planner_facts", 12000)))
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

    conf = _phase_conf(state)
    llm = get_llm("command").bind_tools(tools_for_phase(list(conf.allowed_tools)))
    try:
        ai = llm.invoke(messages)
    except Exception as exc:  # noqa: BLE001 - never kill the graph on one bad turn
        ai = AIMessage(content=f"LLM call failed: {exc}")

    tool_calls = list(getattr(ai, "tool_calls", None) or [])
    done = any(call.get("name") == "finish_task" for call in tool_calls)
    steps = int(state.get("steps", 0)) + 1

    if not tool_calls and not done and "execute_kali_command" in conf.allowed_tools:
        command = extract_text_command(ai.content)
        if command:
            ai = AIMessage(
                content=ai.content if isinstance(ai.content, str) else "",
                tool_calls=[
                    {
                        "name": "execute_kali_command",
                        "args": {"command": command, "intent": "fallback: command written in text", "timeout": None},
                        "id": f"fallback_{uuid.uuid4().hex[:10]}",
                    }
                ],
            )
            tool_calls = list(ai.tool_calls)
            emit({"kind": "fallback", "phase": state.get("phase", ""), "command": command})
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


def run_node(state: Dict[str, Any]) -> Dict[str, Any]:
    ai_message = (state.get("messages") or [None])[-1]
    calls = list(getattr(ai_message, "tool_calls", None) or [])
    overrides = list(state.get("approved_commands") or [])

    tool_messages: List[ToolMessage] = []
    logs: List[Dict[str, Any]] = []
    facts_update: Dict[str, Any] = {}
    output_acc = ""
    commands_used = int(state.get("commands_used", 0))
    task_done = False
    task_success = bool(state.get("task_success"))

    override_index = 0
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

        if name == "execute_kali_command":
            command = str(args.get("command", ""))
            if override_index < len(overrides):
                command = overrides[override_index]
                override_index += 1
            timeout = args.get("timeout")
            result = ALL_TOOLS["execute_kali_command"].invoke(
                {"command": command, "intent": args.get("intent", ""), "timeout": timeout}
            )
        elif name == "http_probe":
            command = f"HTTP {args.get('method', 'GET')} {args.get('url', '')}"
            result = ALL_TOOLS["http_probe"].invoke(args)
        else:
            result = f"Unknown tool: {name}"

        commands_used += 1
        output_acc += "\n" + result
        tool_messages.append(
            ToolMessage(content=clip(result, int(cfg("context.max_tool_output", 6000))), tool_call_id=call_id)
        )
        logs.append(
            {
                "id": f"{state.get('phase', '')}-{uuid.uuid4().hex[:10]}",
                "phase": state.get("phase", ""),
                "command": command,
                "output": clip(result, 2000),
                "status": "failed" if "error executing" in result.lower() else "success",
            }
        )
        emit(
            {
                "kind": "command",
                "phase": state.get("phase", ""),
                "command": command,
                "output": clip(result, 800),
                "status": logs[-1]["status"],
            }
        )
        extracted = extract_findings(result, command=command, phase=state.get("phase", ""))
        facts_update = _merge_facts(facts_update, extracted)

    update: Dict[str, Any] = {
        "messages": tool_messages,
        "action_history": logs,
        "commands_used": commands_used,
        "last_output": output_acc.strip(),
        "approved_commands": [],
        "task_done": task_done,
        "task_success": task_success,
    }
    if facts_update:
        update.update(facts_update)
    return update


def route_after_run(state: Dict[str, Any]) -> str:
    if state.get("task_done"):
        return "evaluate"
    return "gen"


def _verdict(state: Dict[str, Any], digest: str) -> TaskVerdict:
    task = state.get("current_task") or {}
    try:
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
    except Exception as exc:  # noqa: BLE001
        return TaskVerdict(success=False, reason=f"evaluator unavailable: {exc}", evidence="")


def _compress(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    if len(text) > 8000:
        try:
            summary = chat(
                [
                    SystemMessage(content=SUMMARIZER_SYSTEM),
                    HumanMessage(content="Condense the decisive part of this output:\n" + clip(text, 20000)),
                ],
                node="summarizer",
            )
            if summary:
                return summary
        except Exception:  # noqa: BLE001
            pass
    return clip(text, limit)


def evaluate_node(state: Dict[str, Any]) -> Dict[str, Any]:
    task = dict(state.get("current_task") or {})
    task_id = task.get("id", "")
    plan = list(state.get("plan") or [])
    attempt = int(state.get("task_attempt", 0))
    max_attempts = int(cfg("budgets.max_task_attempts", 2))

    model_claim = bool(state.get("task_success"))
    messages = state.get("messages") or []
    digest = transcript_digest(messages, 8000)
    observations = observations_digest(messages, 8000)
    verdict = _verdict(state, digest)
    last_output = state.get("last_output", "")
    last_command = ""
    for message in reversed(state.get("messages") or []):
        for call in getattr(message, "tool_calls", None) or []:
            if call.get("name") == "execute_kali_command":
                last_command = str((call.get("args") or {}).get("command", ""))
                break
        if last_command:
            break

    objective = evidence_verdict(
        state.get("phase", ""), task.get("action", ""), last_output, last_command, digest=observations
    )

    if objective["kind"] in ("compromise", "execution", "ports", "vuln-signal", "empty-scan"):
        success = True
    elif objective["kind"] in ("error", "no-compromise"):
        success = False
    else:
        success = bool(model_claim and verdict.success and last_output.strip())

    emit(
        {
            "kind": "verdict",
            "phase": state.get("phase", ""),
            "task": task.get("instruction", ""),
            "success": success,
            "reason": verdict.reason,
            "evidence": clip(verdict.evidence or last_output, 400),
            "objective": objective,
        }
    )

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
        reason_text = f"{objective['detail']}: {verdict.reason}" if verdict.reason else objective["detail"]
    result = _compress(reason_text, int(cfg("context.max_result_chars", 800)))

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

    sequence = next((i for i, item in enumerate(plan) if item.get("id") == task_id), 0)
    if state.get("plan_id"):
        memory.upsert_task(state["plan_id"], sequence, next((t for t in updated_plan if t.get("id") == task_id), {}))

    compromised = (
        bool(state.get("is_compromised"))
        or has_compromise_evidence(last_output)
        or has_compromise_evidence(observations)
    )
    tried = list(state.get("tried_vectors") or [])
    if not success and status == "failed":
        tried.append(f"{task.get('instruction', '')[:160]} -> {verdict.reason[:160]}")

    update: Dict[str, Any] = {
        "plan": updated_plan,
        "task_attempt": new_attempt,
        "task_verdict": {
            "success": success,
            "reason": reason_text,
            "evidence": evidence,
            "confidence": verdict.confidence,
            "objective": objective,
            "model_claim": model_claim,
        },
        "task_result": result,
        "task_success": success,
        "task_done": True,
        "is_compromised": compromised,
    }
    if tried:
        update["tried_vectors"] = tried
    return update
