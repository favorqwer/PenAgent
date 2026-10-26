"""Interactive runner for the agent graph."""

from __future__ import annotations

import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from langgraph.types import Command
from rich.console import Console

from config.config import Configs

from agent import telemetry, ui
from agent.graph import create_agent_graph
from agent.llm import reset_llm_clients, warm_up
from agent.settings import cfg
from agent.tools import close_shell, default_timeout
from agent.telemetry import build_run_config, flush_tracing, init_langsmith_tracing


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


def _local_time(stamp: Any) -> str:
    """Render a checkpoint timestamp in the operator's timezone.

    LangGraph stores ``created_at`` as timezone-aware UTC; slicing the string
    silently presented UTC as local time (8 hours off in this lab).
    """
    text = str(stamp or "")
    try:
        return datetime.fromisoformat(text).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return text[:19].replace("T", " ")


def history_rows(thread_id: str, limit: int = 40) -> List[Dict[str, Any]]:
    """Checkpoint timeline for one thread, newest first."""
    app = create_agent_graph()
    config = {"configurable": {"thread_id": thread_id}}
    rows: List[Dict[str, Any]] = []
    for snapshot in app.get_state_history(config):
        values = snapshot.values or {}
        configurable = (snapshot.config or {}).get("configurable") or {}
        rows.append(
            {
                "created_at": _local_time(snapshot.created_at),
                "checkpoint_id": str(configurable.get("checkpoint_id", "")),
                "checkpoint_short": str(configurable.get("checkpoint_id", ""))[-6:],
                "step": (snapshot.metadata or {}).get("step"),
                "next": ",".join(snapshot.next or ()) or "end",
                "phase": values.get("phase", ""),
                "commands": int(values.get("commands_used") or 0),
                "compromised": bool(values.get("is_compromised")),
                "pending_approval": bool(getattr(snapshot, "interrupts", ())),
            }
        )
        if len(rows) >= limit:
            break
    return rows


def show_history(
    thread_id: str, console: Optional[Console] = None, limit: int = 40
) -> List[Dict[str, Any]]:
    """Print the checkpoint timeline of a thread (newest first)."""
    console = console or Console()
    return ui.render_history(history_rows(thread_id, limit), thread_id, console)


def find_checkpoint(app, config: Dict[str, Any], needle: str):
    """Resolve a checkpoint id (full, prefix or suffix) to a snapshot.

    Checkpoint ids inside one thread share their leading characters, so the
    history view prints and matches the trailing part instead.
    """
    needle = (needle or "").strip()
    if not needle:
        return None
    for snapshot in app.get_state_history(config):
        checkpoint_id = str(((snapshot.config or {}).get("configurable") or {}).get("checkpoint_id", ""))
        if checkpoint_id == needle or checkpoint_id.endswith(needle) or checkpoint_id.startswith(needle):
            return snapshot
    return None


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

    The host is stored on ShellManager as well as in Configs: the settings
    objects are re-read from YAML on every cache miss, so mutating Configs alone
    reverts as soon as anything touches another config object (e.g. llm_config).
    """
    from actions.shell_manager import ShellManager

    host = (host or "").strip()
    if host:
        Configs.basic_config.kali["hostname"] = host
        ShellManager.set_host_override(host)
        try:
            close_shell()
        except Exception:
            pass
    return ShellManager.effective_host()


def run_agent(
    target: str,
    goal: str = "Autonomous penetration test: obtain and prove the highest practical level of access.",
    thread_id: Optional[str] = None,
    hitl: bool = False,
    hitl_scope: str = "command",
    dry_run: bool = False,
    resume: bool = False,
    from_checkpoint: Optional[str] = None,
    max_commands: Optional[int] = None,
    deadline_minutes: Optional[float] = None,
    kali: Optional[str] = None,
    console: Optional[Console] = None,
    quiet: bool = False,
) -> Dict[str, Any]:
    console = console or Console()
    progress_ui = ui.AgentUI(console, quiet=quiet)
    kali_host = apply_kali(kali)

    if deadline_minutes is not None:
        from agent import settings

        settings.set_value("budgets.deadline_minutes", float(deadline_minutes))

    brain = None
    if dry_run:
        from agent.dry_run import install_dry_run

        brain = install_dry_run(target)
        console.print("[yellow]DRY RUN: scripted model + scripted shell, no API calls, no SSH.[/yellow]")

    telemetry.reset()
    reset_llm_clients()
    if not dry_run:
        # Hide the ~9.7s cold start: the handshake happens while the graph and
        # the memory lookup get ready.
        threading.Thread(target=warm_up, name="llm-warmup", daemon=True).start()

    thread_id = thread_id or f"agent-{target}-{uuid.uuid4().hex[:8]}"
    console.print(f"[dim]lab: kali={kali_host} target={target} thread={thread_id}[/dim]")

    tracing_on = init_langsmith_tracing()
    if not quiet:
        console.print(
            f"[dim]planning model: {cfg('models.planner') or 'default'} | "
            f"LangSmith: {'ON' if tracing_on else 'OFF'} | "
            f"command timeout: {default_timeout()}s[/dim]"
        )

    app = create_agent_graph()
    config = build_run_config(thread_id, target, hitl, dry_run)
    pending: Any
    run_config: Dict[str, Any] = config
    if from_checkpoint:
        snapshot = find_checkpoint(app, config, from_checkpoint)
        if snapshot is None:
            raise SystemExit(
                f"No checkpoint matching '{from_checkpoint}' in thread '{thread_id}'. "
                "Run with --history to list the available ids."
            )
        stored_target = (snapshot.values or {}).get("target")
        if stored_target and stored_target != target:
            raise SystemExit(
                f"Checkpoint '{from_checkpoint}' belongs to target {stored_target}, not {target}."
            )
        pending = None
        run_config = dict(config)
        run_config["configurable"] = dict(snapshot.config.get("configurable") or {})
        next_nodes = ", ".join(snapshot.next or ()) or "nothing (end of run)"
        console.print(
            f"[bold]Forking[/bold] thread {thread_id} from checkpoint {from_checkpoint} "
            f"(phase={snapshot.values.get('phase', '?')}, commands={snapshot.values.get('commands_used', 0)}, "
            f"next={next_nodes})"
        )
        if not snapshot.next:
            console.print("[yellow]That checkpoint has nothing left to run; pick an earlier one.[/yellow]")
            return dict(snapshot.values or {})
    elif resume:
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
            pending = Command(resume=ui.ask_decision(console, payload))
        else:
            pending = None
        console.print(f"[bold]Resuming thread[/bold] {thread_id}")
    else:
        pending = _build_initial_state(target, goal, thread_id, hitl, hitl_scope, dry_run, max_commands, deadline_minutes)

    failed: Optional[str] = None
    try:
        while True:
            interrupted: Optional[Dict[str, Any]] = None
            for chunk in app.stream(
                pending,
                config=run_config,
                stream_mode=["updates", "custom"],
                durability="sync",
                subgraphs=True,
            ):
                namespace, mode, payload = _split_chunk(chunk)
                if mode == "custom":
                    progress_ui.event(payload if isinstance(payload, dict) else {})
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
            pending = Command(resume=ui.ask_decision(console, interrupted))
    except Exception as exc:  # noqa: BLE001 - report, never hide
        failed = f"{type(exc).__name__}: {exc}"
        ui.print_aborted(console, failed, target, thread_id)
    finally:
        if dry_run:
            from agent.dry_run import uninstall

            uninstall()
        flush_tracing()
        close_shell()

    snapshot = app.get_state(config)
    values = dict(snapshot.values or {})
    if failed:
        values["aborted"] = failed
    report = values.get("final_report") or ""
    if report and not quiet:
        ui.print_report(console, report)
    console.print(
        f"[bold]thread[/bold]={thread_id}  compromised={values.get('is_compromised')}  "
        f"commands={values.get('commands_used', 0)}"
    )
    ui.print_usage(console, quiet)
    values["thread_id"] = thread_id
    return values
