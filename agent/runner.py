"""Interactive runner for the agent graph."""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from langgraph.types import Command
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from config.config import Configs

from agent import shell
from agent.findings import clip
from agent.graphs import create_agent_graph
from agent.policy import describe_risk
from agent.settings import cfg
from agent.tracing import build_run_config, flush_tracing, init_langsmith_tracing


RISK_STYLE = {
    "read": "green",
    "probe": "cyan",
    "intrusive": "yellow",
    "destructive": "bold red",
    "unknown": "magenta",
}


class AgentUI:
    def __init__(self, console: Optional[Console] = None, quiet: bool = False):
        self.console = console or Console()
        self.quiet = quiet
        self._last_plan = ""

    def event(self, payload: Dict[str, Any]) -> None:
        if self.quiet:
            return
        kind = payload.get("kind")
        if kind == "scope":
            prior = " (prior knowledge loaded)" if payload.get("prior") else ""
            self.console.print(
                Panel(
                    f"[bold]Target[/bold]: {payload.get('target')}\n"
                    f"[bold]Goal[/bold]: {payload.get('goal')}{prior}",
                    title="Engagement scope",
                    border_style="bright_blue",
                )
            )
        elif kind == "plan":
            self._render_plan(payload)
        elif kind == "replan":
            self.console.print(
                Panel(
                    self._plan_table(payload.get("tasks") or []),
                    title=f"Replanning {payload.get('phase')} (v{payload.get('version')})",
                    border_style="yellow",
                )
            )
        elif kind == "task":
            task = payload.get("task") or {}
            self.console.rule(f"[bold]{payload.get('phase')}[/bold] · {task.get('id')} {task.get('instruction', '')[:90]}")
        elif kind == "step":
            tools = ", ".join(payload.get("tools") or []) or "no tool call"
            self.console.print(f"  [dim]step {payload.get('step')} -> {tools}[/dim]")
        elif kind == "command":
            status = payload.get("status")
            colour = "green" if status == "success" else "red"
            self.console.print(f"  [{colour}]$ {escape(str(payload.get('command')))}[/{colour}]")
            output = (payload.get("output") or "").strip()
            if output:
                self.console.print(f"  [dim]{escape(clip(output, 600))}[/dim]")
        elif kind == "verdict":
            ok = payload.get("success")
            style = "bold green" if ok else "bold red"
            objective = (payload.get("objective") or {}).get("detail", "")
            self.console.print(
                f"  [{style}]{'PASS' if ok else 'FAIL'}[/{style}] {escape(str(payload.get('reason', '')))}"
                f" [dim]({escape(str(objective))})[/dim]"
            )
        elif kind == "handover":
            self.console.print(
                Panel(
                    escape(clip(payload.get("summary", ""), 2000)),
                    title=f"Handover: {payload.get('phase')} ({payload.get('outcome')})",
                    border_style="green",
                )
            )
        elif kind == "report":
            self.console.print(
                Panel(
                    f"compromised: {payload.get('compromised')}\nreport: {payload.get('path')}",
                    title="Report",
                    border_style="bright_green",
                )
            )

    def _plan_table(self, tasks) -> Table:
        table = Table(show_lines=False, expand=True)
        table.add_column("#", width=3)
        table.add_column("id", width=10)
        table.add_column("status", width=9)
        table.add_column("instruction", overflow="fold")
        table.add_column("depends", width=14)
        for index, task in enumerate(tasks, 1):
            table.add_row(
                str(index),
                escape(str(task.get("id", ""))),
                escape(str(task.get("status", ""))),
                escape(str(task.get("instruction", ""))),
                escape(",".join(task.get("depends_on") or []) or "-"),
            )
        return table

    def _render_plan(self, payload: Dict[str, Any]) -> None:
        self.console.print(
            Panel(
                self._plan_table(payload.get("tasks") or []),
                title=f"Plan: {payload.get('phase')} (v{payload.get('version')})",
                border_style="blue",
            )
        )


def _split_chunk(chunk):
    """Normalise stream chunks for both subgraphs=True and single-namespace runs."""
    if isinstance(chunk, tuple) and len(chunk) == 3:
        namespace, mode, payload = chunk
        return tuple(namespace or ()), mode, payload
    if isinstance(chunk, tuple) and len(chunk) == 2:
        mode, payload = chunk
        return (), mode, payload
    return (), "updates", chunk


def _interrupt_payload(chunk: Any) -> Optional[Dict[str, Any]]:
    interrupts = chunk.get("__interrupt__") if isinstance(chunk, dict) else None
    if not interrupts:
        return None
    first = interrupts[0]
    value = getattr(first, "value", None)
    return value if isinstance(value, dict) else {"type": "unknown", "raw": str(value)}


def ask_decision(console: Console, payload: Dict[str, Any]) -> Dict[str, Any]:
    console.print(
        Panel(
            f"Phase: [bold]{payload.get('phase')}[/bold]\nTask: {payload.get('task', '')}",
            title="[bold red]Command approval required[/bold red]",
            border_style="red",
        )
    )
    for item in payload.get("commands") or []:
        style = RISK_STYLE.get(item.get("risk", ""), "white")
        console.print(f"  [{style}]$ {escape(str(item.get('command')))}[/{style}]")
        console.print(
            f"    [dim]intent: {escape(str(item.get('intent', '')))} | risk: {escape(str(item.get('risk')))} "
            f"({describe_risk(item.get('risk', ''))}) | {escape(str(item.get('risk_reason', '')))}[/dim]"
        )

    choice = Prompt.ask(
        "Approve? [bold]y[/bold]=yes  [bold]n[/bold]=no  [bold]e[/bold]=edit  [bold]a[/bold]=approve rest of task",
        default="n",
        choices=["y", "n", "e", "a"],
    ).lower()

    if choice == "y":
        return {"approved": True}
    if choice == "a":
        return {"approved": True, "scope": "task"}
    if choice == "e":
        commands = []
        for item in payload.get("commands") or []:
            edited = Prompt.ask("command", default=item.get("command", ""))
            commands.append(edited)
        return {"approved": True, "commands": commands}

    reason = Prompt.ask("Reason for denial", default="operator denied")
    return {"approved": False, "reason": reason}


def _build_initial_state(
    target: str,
    goal: str,
    thread_id: str,
    hitl: bool,
    hitl_scope: str,
    dry_run: bool,
    max_commands: Optional[int],
    deadline_minutes: Optional[float],
) -> Dict[str, Any]:
    return {
        "target": target,
        "goal": goal,
        "constraints": [],
        "phase": "collector",
        "phase_index": 0,
        "phase_summaries": [],
        "action_history": [],
        "plan_ids": [],
        "phase_metrics": [],
        "backtrack_count": 0,
        "open_ports": [],
        "services": {},
        "vulnerabilities": [],
        "credentials": [],
        "flags": [],
        "tried_vectors": [],
        "is_compromised": False,
        "commands_used": 0,
        "hitl_enabled": bool(hitl),
        "hitl_scope": hitl_scope or "command",
        "dry_run": bool(dry_run),
        "thread_id": thread_id,
        "target_memory": "",
        "final_report": "",
        "max_commands": int(max_commands) if max_commands else int(cfg("budgets.max_commands", 250)),
    }


def apply_kali(host: Optional[str]) -> str:
    """Override the Kali host for this process (CLI --kali).

    Accounts/port keep coming from basic_config.yaml; only the host changes.
    Any already-open SSH channel is closed so the next command reconnects.
    """
    host = (host or "").strip()
    if host:
        Configs.basic_config.kali["hostname"] = host
        try:
            shell.close()
        except Exception:
            pass
    return str(Configs.basic_config.kali.get("hostname", "") or "")


def run_agent(
    target: str,
    goal: str = "Autonomous penetration test: obtain and prove the highest practical level of access.",
    thread_id: Optional[str] = None,
    hitl: bool = False,
    hitl_scope: str = "command",
    dry_run: bool = False,
    resume: bool = False,
    max_commands: Optional[int] = None,
    deadline_minutes: Optional[float] = None,
    kali: Optional[str] = None,
    console: Optional[Console] = None,
    quiet: bool = False,
) -> Dict[str, Any]:
    console = console or Console()
    ui = AgentUI(console, quiet=quiet)
    kali_host = apply_kali(kali)

    if deadline_minutes is not None:
        from agent import settings

        settings.set_value("budgets.deadline_minutes", float(deadline_minutes))

    brain = None
    if dry_run:
        from agent.fake import install_dry_run

        brain = install_dry_run(target)
        console.print("[yellow]DRY RUN: scripted model + scripted shell, no API calls, no SSH.[/yellow]")

    thread_id = thread_id or f"agent-{target}-{uuid.uuid4().hex[:8]}"
    console.print(f"[dim]lab: kali={kali_host} target={target} thread={thread_id}[/dim]")

    tracing_on = init_langsmith_tracing()
    if not quiet:
        console.print(
            f"[dim]planning model: {cfg('models.planner') or 'default'} | "
            f"LangSmith: {'ON' if tracing_on else 'OFF'} | "
            f"command timeout: {shell.default_timeout()}s[/dim]"
        )

    app = create_agent_graph()
    config = build_run_config(thread_id, target, hitl, dry_run)

    pending: Any
    if resume:
        snapshot = app.get_state(config)
        if not snapshot.values:
            raise SystemExit(f"No checkpoint found for thread '{thread_id}'.")
        stored_target = (snapshot.values or {}).get("target")
        if stored_target and stored_target != target:
            raise SystemExit(
                f"Thread '{thread_id}' belongs to target {stored_target}, not {target}. "
                "Use a different --thread-id."
            )
        interrupts = tuple(getattr(snapshot, "interrupts", ()) or ())
        if not interrupts:
            for task in getattr(snapshot, "tasks", ()) or ():
                interrupts += tuple(getattr(task, "interrupts", ()) or ())
        if interrupts:
            payload = getattr(interrupts[0], "value", {}) or {}
            pending = Command(resume=ask_decision(console, payload))
        else:
            pending = None
        console.print(f"[bold]Resuming thread[/bold] {thread_id}")
    else:
        pending = _build_initial_state(target, goal, thread_id, hitl, hitl_scope, dry_run, max_commands, deadline_minutes)

    try:
        while True:
            interrupted: Optional[Dict[str, Any]] = None
            for chunk in app.stream(
                pending,
                config=config,
                stream_mode=["updates", "custom"],
                durability="sync",
                subgraphs=True,
            ):
                namespace, mode, payload = _split_chunk(chunk)
                if mode == "custom":
                    ui.event(payload if isinstance(payload, dict) else {})
                    continue
                interrupt_value = _interrupt_payload(payload if isinstance(payload, dict) else {})
                if interrupt_value is not None:
                    interrupted = interrupt_value
                    continue
                if not quiet and not namespace and isinstance(payload, dict):
                    for node, update in payload.items():
                        if not isinstance(update, dict):
                            continue
                        outcome = update.get("phase_outcome")
                        if outcome and node not in ("handover",):
                            console.print(f"  [dim]{node}: {outcome}[/dim]")

            if interrupted is None:
                break
            pending = Command(resume=ask_decision(console, interrupted))
    finally:
        if dry_run:
            from agent.fake import uninstall

            uninstall()
        flush_tracing()
        shell.close()

    snapshot = app.get_state(config)
    values = dict(snapshot.values or {})
    report = values.get("final_report") or ""
    if report and not quiet:
        console.print(Panel(Markdown(report), title="Final report", border_style="bright_green"))
    console.print(
        f"[bold]thread[/bold]={thread_id}  compromised={values.get('is_compromised')}  "
        f"commands={values.get('commands_used', 0)}"
    )
    values["thread_id"] = thread_id
    return values
