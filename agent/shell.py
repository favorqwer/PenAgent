"""Thin shell access layer.

Indirection exists so tests and `--dry-run` can swap in a scripted shell
without touching ShellManager or opening an SSH connection.
"""

from __future__ import annotations

from typing import Optional

from actions.shell_manager import ShellManager

_OVERRIDE = None


def set_shell_override(shell) -> None:
    global _OVERRIDE
    _OVERRIDE = shell


def reset_shell_override() -> None:
    global _OVERRIDE
    _OVERRIDE = None


def get_shell():
    if _OVERRIDE is not None:
        return _OVERRIDE
    return ShellManager.get_instance().get_shell()


def default_timeout() -> int:
    """Operator-configured per-command cap (CLI --command-timeout)."""
    from actions.shell_manager import ShellManager

    return int(getattr(ShellManager, "command_timeout", 120) or 120)


def execute(command: str, timeout: Optional[float] = None) -> str:
    shell = get_shell()
    try:
        return shell.execute_cmd(command, timeout=timeout)
    except TypeError:
        # Any third-party shell stub that does not accept a timeout.
        return shell.execute_cmd(command)


def close() -> None:
    if _OVERRIDE is None:
        ShellManager.get_instance().close()
