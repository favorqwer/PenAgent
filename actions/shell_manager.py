import paramiko

from typing import Optional

from actions.remote_shell import RemoteShell
from config.config import Configs


class ShellManager:
    _instance = None
    _ssh_client = None
    _shell = None
    # Timeout (in seconds) applied to each command execution. Can be overridden
    # before the first connection (e.g. from the CLI) via `ShellManager.command_timeout = ...`.
    command_timeout = 120
    # CLI `--kali` override. Kept outside Configs on purpose: the settings objects
    # are reloaded from YAML whenever the shared one-slot settings cache misses
    # (touching llm_config is enough), which silently reverts in-memory mutations
    # and sends the run to the host in the YAML file instead.
    host_override: Optional[str] = None

    @classmethod
    def set_host_override(cls, host: Optional[str]) -> None:
        cls.host_override = (host or "").strip() or None

    @classmethod
    def effective_host(cls) -> str:
        return cls.host_override or Configs.basic_config.kali["hostname"]

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def is_alive(self) -> bool:
        """Checks if underlying SSH transport is active."""
        if self._ssh_client is None:
            return False
        transport = self._ssh_client.get_transport()
        return transport is not None and transport.is_active()

    def get_shell(self) -> RemoteShell:
        """Returns the RemoteShell instance, auto-reconnecting if disconnected."""
        if self._shell is None or not self.is_alive():
            self._connect()
        return self._shell

    def _connect(self):
        self.close()
        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh_client.connect(
            hostname=self.effective_host(),
            username=Configs.basic_config.kali['username'],
            password=Configs.basic_config.kali['password'],
            port=Configs.basic_config.kali['port'],
            timeout=10,
        )
        self._shell = RemoteShell(self._ssh_client, command_timeout=self.command_timeout)

    def close(self):
        if self._shell:
            try:
                self._shell.close()
            except:
                pass
            self._shell = None

        if self._ssh_client:
            try:
                self._ssh_client.close()
            except:
                pass
            self._ssh_client = None
