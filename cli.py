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
