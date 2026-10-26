import importlib

import click

from config.config import Configs
from utils.session import create_tables

from utils.log_common import build_logger

logger = build_logger()


# The web server and the benchmark harness live in their own stacks (FastAPI,
# RAG vector store, ollama). Importing them at start-up made `cli.py agent`
# depend on every one of those packages, so they are resolved on first use.
LAZY_COMMANDS = {
    "start": ("startup", "main", "Start the web server (FastAPI + WebUI)"),
    "penagent": ("pentest", "main", "Run the legacy role chain (collector / scanner / exploiter)"),
    "vulnbot": ("pentest", "main", "Alias of penagent"),
    "pentestgpt": ("benchmark.pentestgpt", "main", "Benchmark against PentestGPT"),
    "base": ("benchmark.base", "main", "Benchmark the single-agent baseline"),
}


class LazyCommand(click.Command):
    """Placeholder that resolves the real command only when it is executed.

    ``cli.py --help`` asks every subcommand for its one-line description, so
    returning the real command from ``get_command`` would import every stack
    again. Only ``make_context`` (invocation, and the command's own --help)
    needs the real object.
    """

    def __init__(self, name, target, help=None):
        super().__init__(name=name, help=help)
        self.target = target

    def _resolve(self):
        module_name, attribute = self.target[:2]
        return getattr(importlib.import_module(module_name), attribute)

    def make_context(self, info_name, args, parent=None, **extra):
        return self._resolve().make_context(info_name, args, parent=parent, **extra)


class LazyGroup(click.Group):
    """click group whose subcommands are imported only when they are used."""

    def __init__(self, *args, lazy=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._lazy = dict(lazy or {})

    def list_commands(self, ctx):
        return sorted(set(super().list_commands(ctx)) | set(self._lazy))

    def get_command(self, ctx, name):
        command = super().get_command(ctx, name)
        if command is not None:
            return command
        target = self._lazy.get(name)
        if not target:
            return None
        command = LazyCommand(name, target[:2], help=target[2] if len(target) > 2 else None)
        self.add_command(command, name)
        return command


@click.group(
    cls=LazyGroup,
    lazy=LAZY_COMMANDS,
    help="PenAgent: Autonomous Penetration Testing Framework",
)
def main():
    ...


@main.command("init", help="Initialize project directories and database")
def init():
    Configs.set_auto_reload(False)
    logger.success(f"Start initializing the project data directory：{Configs.PENTEST_ROOT}")
    Configs.basic_config.make_dirs()
    logger.success("Creating all data directories: Success.")

    create_tables()
    logger.success("Initializing database: Success.")

    Configs.create_all_templates()
    Configs.set_auto_reload(True)

    logger.success("Generating default configuration file: Success.")


@main.command("agent", help="Run the layered agent (plan -> ReAct -> verify) with checkpointing")
@click.option(
    "-t",
    "--target",
    "target",
    default=None,
    help="Target host IP or domain (required unless --history is used)",
)
@click.option(
    "-d",
    "--desc",
    "desc",
    default="Autonomous penetration test: obtain and prove the highest practical level of access.",
    help="Engagement goal",
)
# Lab profiles (keep in sync with agents.md):
#   lab1: kali 100.74.213.15 -> target 100.84.151.2
#   lab2: kali 100.116.135.31 -> target 100.86.108.4
@click.option(
    "--kali",
    "kali",
    default=None,
    help="Kali host override. lab1=100.74.213.15, lab2=100.116.135.31",
)
@click.option("--thread-id", "thread_id", default=None, help="Stable thread id for resume / time travel")
@click.option("--resume", "resume", is_flag=True, default=False, help="Resume an existing thread")
@click.option(
    "--from-checkpoint",
    "from_checkpoint",
    default=None,
    help="Fork the thread from a past checkpoint id (see --history); prefix is enough",
)
@click.option("--hitl", "hitl", is_flag=True, default=False, help="Require approval for intrusive commands")
@click.option(
    "--hitl-scope",
    "hitl_scope",
    type=click.Choice(["command", "task"]),
    default="command",
    help="Approval granularity",
)
@click.option("--dry-run", "dry_run", is_flag=True, default=False, help="Scripted model + shell, no API/SSH calls")
@click.option("--max-commands", "max_commands", type=int, default=None, help="Global command budget")
@click.option("--deadline", "deadline", type=float, default=None, help="Wall-clock budget in minutes")
@click.option("--command-timeout", "command_timeout", type=int, default=120, help="Global per-command timeout cap (seconds)")
@click.option("--quiet", "quiet", is_flag=True, default=False, help="Only print the final report")
@click.option(
    "--history",
    "history",
    is_flag=True,
    default=False,
    help="Print the checkpoint timeline of --thread-id and exit",
)
def agent_cmd(
    target, desc, thread_id, resume, from_checkpoint, hitl, hitl_scope, dry_run,
    max_commands, deadline, command_timeout, kali, quiet, history
):
    from actions.shell_manager import ShellManager
    from agent.runner import run_agent, show_history

    if history:
        if not thread_id:
            raise click.UsageError("--history requires --thread-id")
        show_history(thread_id)
        return

    if not target:
        raise click.UsageError("-t/--target is required (or use --history --thread-id ID)")

    if resume and not thread_id:
        raise click.UsageError("--resume requires --thread-id")

    if from_checkpoint and not thread_id:
        raise click.UsageError("--from-checkpoint requires --thread-id")

    ShellManager.command_timeout = int(command_timeout)

    try:
        run_agent(
            target=target,
            goal=desc,
            thread_id=thread_id,
            hitl=hitl,
            hitl_scope=hitl_scope,
            dry_run=dry_run,
            resume=resume,
            from_checkpoint=from_checkpoint,
            max_commands=max_commands,
            deadline_minutes=deadline,
            kali=kali,
            quiet=quiet,
        )
    finally:
        ShellManager.get_instance().close()


# Benchmark & Evaluation Subgroup
@main.group(
    name="benchmark",
    cls=LazyGroup,
    lazy={
        "pentestgpt": ("benchmark.pentestgpt", "main", "Benchmark against PentestGPT"),
        "baseline": ("benchmark.base", "main", "Run the single-agent baseline"),
    },
    help="Benchmark evaluation against baseline models (PentestGPT / Single-Agent Baseline)",
)
def benchmark():
    pass


if __name__ == "__main__":
    main()
