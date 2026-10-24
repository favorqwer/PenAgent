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


@main.command("graph", help="Run autonomous penetration testing via LangGraph state graph")
@click.option("-t", "--target", "target", default="100.84.151.2", help="Target host IP or domain (default: 100.84.151.2)")
@click.option("-d", "--desc", "desc", default="Autonomous penetration testing and privilege escalation", help="Task objective description")
@click.option("-s", "--session-id", "session_id", default=None, help="Resume an existing session thread ID")
@click.option("--hitl", "hitl", is_flag=True, default=False, help="Enable Human-in-the-Loop approval before exploitation")
@click.option("--timeout", "timeout", default=120, help="Per-command execution timeout in seconds")
def graph_cmd(target, desc, session_id, hitl, timeout):
    from actions.shell_manager import ShellManager
    from pipeline.runner import run_pentest_pipeline
    ShellManager.command_timeout = timeout
    try:
        run_pentest_pipeline(target=target, task_desc=desc, thread_id=session_id, hitl_enabled=hitl)
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
