"""
Runner and execution orchestrator for PenAgent LangGraph workflow.
Provides interactive CLI execution, streaming visualizer, and Human-In-The-Loop approvals.
"""

import time
import uuid
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pipeline.graph import create_pentest_graph
from pipeline.state import PentestState
from pipeline.tracing import get_pipeline_run_config, init_langsmith_tracing


def run_pentest_pipeline(
    target: str,
    task_desc: str = "Autonomous Penetration Testing",
    thread_id: Optional[str] = None,
    hitl_enabled: bool = False,
    max_phase_steps: int = 3,
    max_retries: int = 3
):
    """
    Executes the LangGraph penetration testing workflow with streaming visual feedback.
    """
    console = Console()
    app = create_pentest_graph(hitl_enabled=hitl_enabled)

    if not thread_id:
        thread_id = f"penagent-session-{uuid.uuid4().hex[:8]}"

    # Automatically initialize LangSmith tracing and build metadata config
    is_tracing = init_langsmith_tracing()
    config = get_pipeline_run_config(thread_id=thread_id, target=target, hitl_enabled=hitl_enabled)

    console.print(Panel(
        f"[bold green]Target Host:[/bold green] [bold cyan]{target}[/bold cyan]\n"
        f"[bold green]Task Goal:[/bold green] {task_desc}\n"
        f"[bold green]Session Thread ID:[/bold green] [yellow]{thread_id}[/yellow]\n"
        f"[bold green]HITL (Human-in-the-Loop):[/bold green] {'[red]ENABLED (Review before Exploiter)[/red]' if hitl_enabled else '[dim]Disabled (Full Auto)[/dim]'}\n"
        f"[bold green]LangSmith Tracing:[/bold green] {'[bold green]CONNECTED (https://smith.langchain.com)[/bold green]' if is_tracing else '[dim]Disabled[/dim]'}",
        title="🛡️ PenAgent LangGraph Orchestrator",
        border_style="bright_blue"
    ))

    # Initial input state
    initial_state = {
        "target": target,
        "task_description": task_desc,
        "open_ports": [],
        "services": {},
        "vulnerabilities": [],
        "credentials": [],
        "flags": [],
        "current_phase": "collector",
        "phase_step_count": 0,
        "max_phase_steps": max_phase_steps,
        "retry_count": 0,
        "max_retries": max_retries,
        "is_compromised": False,
        "action_history": [],
        "phase_summaries": []
    }

    current_input = initial_state

    while True:
        try:
            # Stream events through the graph
            for event in app.stream(current_input, config=config):
                for node_name, state_delta in event.items():
                    _render_node_event(console, node_name, state_delta)

            # Check if workflow is interrupted by HITL
            snapshot = app.get_state(config)
            if snapshot.next and "exploiter" in snapshot.next:
                console.print(Panel(
                    "[bold red]⚠️ HUMAN-IN-THE-LOOP INTERRUPT REQUIRED[/bold red]\n"
                    "The agent is ready to transition to the [bold red]Exploiter[/bold red] phase.\n"
                    "Active attack payloads and proof-of-concept exploits may be sent to the target.",
                    title="Security Safeguard",
                    border_style="red"
                ))

                choice = console.input("[bold yellow]Authorize exploitation phase to proceed? [y/N]: [/bold yellow]").strip().lower()
                if choice in ['y', 'yes']:
                    console.print("[green]✓ Exploitation authorized by operator. Resuming graph...[/green]")
                    current_input = None  # None input signals LangGraph to continue from checkpoint
                    continue
                else:
                    console.print("[yellow]✕ Exploitation rejected by operator. Aborting execution safely.[/yellow]")
                    break

            # If snapshot.next is empty, the graph has terminated (reached END)
            if not snapshot.next:
                console.print("\n[bold green]🎉 Penetration testing workflow completed successfully![/bold green]")
                _render_final_summary(console, snapshot.values)
                break

        except KeyboardInterrupt:
            console.print(f"\n[bold yellow]Execution paused by user. Resume anytime with Thread ID: {thread_id}[/bold yellow]")
            break
        except Exception as e:
            console.print(f"\n[bold red]Workflow execution error: {e}[/bold red]")
            import traceback
            console.print(traceback.format_exc(), style="dim")
            break


def _render_node_event(console: Console, node_name: str, state_delta: dict):
    """Renders formatted panel for a completed node event."""
    colors = {
        "collector": "cyan",
        "scanner": "yellow",
        "exploiter": "red",
        "reporter": "green"
    }
    color = colors.get(node_name, "white")
    title = f"Phase Completed: {node_name.upper()}"

    content_lines = []

    # Display actions executed
    if "action_history" in state_delta and state_delta["action_history"]:
        for action in state_delta["action_history"]:
            content_lines.append(f"[bold dim]$ {action.get('command')}[/bold dim]")
            out = action.get('output', '')
            preview = out[:300] + ("..." if len(out) > 300 else "")
            content_lines.append(f"[dim]{preview}[/dim]\n")

    # Display findings
    if "open_ports" in state_delta and state_delta["open_ports"]:
        content_lines.append(f"[bold cyan]Discovered Ports:[/bold cyan] {state_delta['open_ports']}")
    if "services" in state_delta and state_delta["services"]:
        content_lines.append(f"[bold cyan]Identified Services:[/bold cyan] {state_delta['services']}")
    if "vulnerabilities" in state_delta and state_delta["vulnerabilities"]:
        content_lines.append(f"[bold red]Discovered Vulnerabilities:[/bold red] {len(state_delta['vulnerabilities'])} findings")
    if "is_compromised" in state_delta:
        status_text = "[bold red]YES (Target Compromised)[/bold red]" if state_delta["is_compromised"] else "[yellow]No[/yellow]"
        content_lines.append(f"[bold]Compromise Status:[/bold] {status_text}")

    body = "\n".join(content_lines) if content_lines else "[dim]Phase executed successfully.[/dim]"
    console.print(Panel(body, title=title, border_style=color))


def _render_final_summary(console: Console, final_state: dict):
    """Renders the executive summary table and report."""
    table = Table(title="PenAgent Final Engagement Overview", border_style="green")
    table.add_column("Attribute", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Target Host", str(final_state.get("target", "N/A")))
    table.add_row("Open Ports", str(final_state.get("open_ports", [])))
    table.add_row("Services Mapped", str(len(final_state.get("services", {}))))
    table.add_row("Vulnerabilities", str(len(final_state.get("vulnerabilities", []))))
    table.add_row("Flags / Proofs", str(final_state.get("flags", [])))
    table.add_row("Compromise Achieved", "YES" if final_state.get("is_compromised") else "NO")

    console.print(table)

    summaries = final_state.get("phase_summaries", [])
    if summaries and isinstance(summaries[-1], str) and summaries[-1].startswith("# PenAgent"):
        console.print(Panel(summaries[-1], title="Full Assessment Report", border_style="bright_green"))
