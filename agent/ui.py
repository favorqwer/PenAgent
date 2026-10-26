"""Terminal presentation: live progress, approval prompts, usage and history tables.

Renderer only - it never touches the graph, the model or the shell.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from agent import telemetry
from agent.findings import clip
from agent.policy import describe_risk


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


def print_usage(console: Console, quiet: bool) -> None:
    """Per-node call and token totals (silent when nothing was spent)."""
    snap = telemetry.snapshot()
    total = snap["total"]
    if quiet or not total["calls"]:
        return
    table = Table(show_header=True, box=None, expand=False, pad_edge=False)
    table.add_column("node", style="bold")
    table.add_column("calls", justify="right")
    table.add_column("in", justify="right")
    table.add_column("out", justify="right")
    for node, item in snap["by_node"].items():
        table.add_row(
            str(node),
            str(item["calls"]),
            str(item["prompt_tokens"]),
            str(item["completion_tokens"]),
        )
    table.add_section()
    table.add_row(
        "total", str(total["calls"]), str(total["prompt_tokens"]), str(total["completion_tokens"])
    )
    evaluated = (snap.get("counters") or {}).get(telemetry.COUNTER_VERDICTS, 0)
    console.print(
        Panel(
            table,
            title=f"LLM usage · task verdicts: {evaluated}",
            border_style="cyan",
        )
    )


def render_history(
    rows: List[Dict[str, Any]], thread_id: str, console: Console
) -> List[Dict[str, Any]]:
    """Print the checkpoint timeline of a thread (newest first)."""
    if not rows:
        console.print(f"[yellow]No checkpoints found for thread '{thread_id}'.[/yellow]")
        return rows

    # Narrow terminals drop the bookkeeping columns instead of squeezing every
    # column into two characters.
    compact = console.width < 100
    table = Table(title=f"Thread {thread_id}", show_lines=False, padding=(0, 1))
    table.add_column("when", width=11, no_wrap=True)
    if not compact:
        table.add_column("ckpt", width=8, no_wrap=True)
        table.add_column("step", width=4, justify="right")
    table.add_column("phase", width=10, no_wrap=True)
    table.add_column("cmds", width=4, justify="right")
    table.add_column("next", overflow="fold")
    table.add_column("flags", width=17, no_wrap=True)
    for row in rows:
        flags = []
        if row["compromised"]:
            flags.append("compromised")
        if row["pending_approval"]:
            flags.append("awaiting approval")
        cells = [row["created_at"][5:16]]
        if not compact:
            cells += [row["checkpoint_short"], str(row["step"])]
        cells += [row["phase"], str(row["commands"]), row["next"], ", ".join(flags) or "-"]
        table.add_row(*cells)
    console.print(table)
    if compact:
        console.print("[dim]checkpoint ids and step numbers appear on terminals >= 100 columns[/dim]")
    console.print(f"[dim]{len(rows)} checkpoint(s), newest first[/dim]")
    return rows


def print_report(console: Console, report: str) -> None:
    console.print(Panel(Markdown(report), title="Final report", border_style="bright_green"))


def print_aborted(console: Console, failure: str, target: str, thread_id: str) -> None:
    body = (
        f"{failure}\n\n"
        "Every executed command is already checkpointed. Continue with:\n"
        f"  python cli.py agent -t {target} --thread-id {thread_id} --resume\n"
        "Inspect the steps with:\n"
        f"  python cli.py agent --history --thread-id {thread_id}"
    )
    console.print(Panel(body, title="Run aborted", border_style="red"))
