import click

from config.config import Configs
from utils.session import create_tables
from startup import main as startup_main
from pentest import main as pentest_main
from benchmark.pentestgpt import main as pentestgpt_main
from benchmark.base import main as base_main

from utils.log_common import build_logger

logger = build_logger()


@click.group(help="PenAgent: Autonomous Penetration Testing Framework")
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


# Core Commands
main.add_command(startup_main, "start")
main.add_command(pentest_main, "penagent")
main.add_command(pentest_main, "vulnbot")


@main.command("agent", help="Run the layered agent (plan -> ReAct -> verify) with checkpointing")
@click.option("-t", "--target", "target", required=True, help="Target host IP or domain")
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
def agent_cmd(
    target, desc, thread_id, resume, hitl, hitl_scope, dry_run,
    max_commands, deadline, command_timeout, kali, quiet
):
    from actions.shell_manager import ShellManager
    from agent.runner import run_agent

    if resume and not thread_id:
        raise click.UsageError("--resume requires --thread-id")

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
            max_commands=max_commands,
            deadline_minutes=deadline,
            kali=kali,
            quiet=quiet,
        )
    finally:
        ShellManager.get_instance().close()


# Benchmark & Evaluation Subgroup
@main.group(name="benchmark", help="Benchmark evaluation against baseline models (PentestGPT / Single-Agent Baseline)")
def benchmark():
    pass

benchmark.add_command(pentestgpt_main, "pentestgpt")
benchmark.add_command(base_main, "baseline")

# Backwards compatible shortcuts
main.add_command(pentestgpt_main, "pentestgpt")
main.add_command(base_main, "base")


if __name__ == "__main__":
    main()
