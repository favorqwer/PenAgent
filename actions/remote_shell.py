import re
import time
from typing import Optional
import paramiko

from config.config import Configs


class RemoteShell:
    """Production-grade RemoteShell with a Hybrid Execution Engine:
    1. Direct non-interactive execution (exec_command) for standard tools (nmap, gobuster, etc.):
       - Isolated stdout and stderr
       - True exit code capture ($?)
       - Zero terminal echo and ANSI escape sequences
       - Non-blocking sudo password injection
    2. Sentinel delimiter protocol for persistent interactive PTY sessions (msfconsole, etc.):
       - Exact command completion detection using a unique delimiter
       - No fragile prompt guessing
    3. Output sanitization and safe truncation to protect LLM context windows.
    """

    FORBIDDEN_COMMANDS = {'apt', 'apt-get'}
    MAX_OUTPUT_LENGTH = 16000  # Truncate threshold to protect LLM context

    def __init__(self, ssh_client: paramiko.SSHClient, timeout: float = 120.0, command_timeout: float = 120.0):
        self.ssh_client = ssh_client
        self.timeout = timeout
        self.command_timeout = command_timeout
        self._interactive_channel: Optional[paramiko.Channel] = None
        self._sudo_password = Configs.basic_config.kali.get("password", "")

    @property
    def shell(self) -> paramiko.Channel:
        """Compatibility property for code accessing shell.shell directly."""
        return self._get_interactive_channel()

    def _get_interactive_channel(self) -> paramiko.Channel:
        """Lazily creates and initializes an interactive PTY channel if needed."""
        if self._interactive_channel is None or self._interactive_channel.closed:
            self._interactive_channel = self.ssh_client.invoke_shell()
            self._interactive_channel.settimeout(self.command_timeout)
            time.sleep(0.5)
            # Drain initial motd / banner
            if self._interactive_channel.recv_ready():
                self._interactive_channel.recv(8192)
        return self._interactive_channel

    @staticmethod
    def strip_ansi(text: str) -> str:
        """Removes terminal escape codes, ANSI colors, and bracketed paste sequences."""
        pattern = r'\x1b(\[[0-9;?]*[a-zA-Z]|\([a-zA-Z]|[=>])|\x00|\r'
        return re.sub(pattern, '', text)

    def _truncate_output(self, text: str) -> str:
        """Truncates excessively large outputs to keep LLM context safe and cost-effective."""
        if len(text) <= self.MAX_OUTPUT_LENGTH:
            return text
        half = self.MAX_OUTPUT_LENGTH // 2
        head = text[:half]
        tail = text[-half:]
        return f"{head}\n\n... [Output truncated: total {len(text)} bytes] ...\n\n{tail}"

    def _check_forbidden_commands(self, cmd: str) -> Optional[str]:
        cmd_parts = cmd.split()
        if any(c in self.FORBIDDEN_COMMANDS for c in cmd_parts):
            return "Command not allowed: network tunneling tools are restricted"
        return None

    def execute_cmd(self, cmd: str) -> str:
        """Main entry point. Intelligently routes between clean exec_command and interactive PTY."""
        cmd = cmd.strip()
        if not cmd:
            return ""

        if err := self._check_forbidden_commands(cmd):
            return err

        # Determine if command strictly requires persistent PTY (e.g., msfconsole)
        interactive_tools = ('msfconsole', 'ftp', 'smbclient')
        is_interactive = any(tool in cmd for tool in interactive_tools)

        if is_interactive:
            raw_result = self._execute_pty(cmd)
        else:
            raw_result = self._execute_exec(cmd)

        # Tool-specific post-processing if needed
        if "dirb" in cmd and "gobuster" not in cmd:
            return clean_dirb_output(raw_result)
        elif "msfconsole" in cmd:
            return clean_msfconsole_output(raw_result)

        return raw_result

    def _execute_exec(self, cmd: str) -> str:
        """Executes one-shot command using SSH exec_command (fast, clean, isolated streams, exact exit code)."""
        actual_cmd = cmd
        # Automatically inject sudo password non-interactively if sudo is used
        if actual_cmd.startswith("sudo ") or " sudo " in actual_cmd:
            if self._sudo_password:
                # Use sudo -S -p '' to consume password silently from stdin pipe
                if actual_cmd.startswith("sudo "):
                    actual_cmd = f"echo '{self._sudo_password}' | sudo -S -p '' {actual_cmd[5:]}"
                else:
                    actual_cmd = actual_cmd.replace(" sudo ", f" echo '{self._sudo_password}' | sudo -S -p '' ")

        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(
                actual_cmd,
                timeout=self.command_timeout,
                get_pty=False
            )
            raw_out = stdout.read().decode('utf-8', errors='replace')
            raw_err = stderr.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()

            clean_out = self.strip_ansi(raw_out).strip()
            clean_err = self.strip_ansi(raw_err).strip()

            result_parts = []
            if clean_out:
                result_parts.append(clean_out)
            if clean_err:
                # If command succeeded with minor warnings on stderr, or failed with stderr
                if exit_code != 0:
                    result_parts.append(f"[STDERR]: {clean_err}")
                elif not clean_out:
                    result_parts.append(clean_err)

            if exit_code != 0:
                result_parts.append(f"[Exit Status: {exit_code}]")

            final_result = "\n".join(result_parts) if result_parts else "Command executed successfully with no output."
            return self._truncate_output(final_result)

        except Exception as e:
            return f"Command execution failed: {str(e)}"

    def _execute_pty(self, cmd: str) -> str:
        """Executes interactive command using PTY with Sentinel Delimiter protocol."""
        channel = self._get_interactive_channel()
        sentinel = f"__PENAGENT_STATUS_{int(time.time() * 1000)}__"
        wrapped_cmd = f"{cmd}\necho \"{sentinel}:$?:__END__\"\n"

        channel.send(wrapped_cmd)

        start_time = time.time()
        buf = ""
        pattern = re.compile(rf"{sentinel}:(-?\d+):__END__")

        while True:
            if channel.recv_ready():
                chunk = channel.recv(8192).decode('utf-8', errors='replace')
                buf += chunk

                match = pattern.search(buf)
                if match:
                    exit_code = match.group(1)
                    raw_output = buf[: match.start()]
                    lines = raw_output.splitlines()
                    # Remove the echoed command line if present
                    if lines and cmd in lines[0]:
                        lines = lines[1:]
                    clean_output = self.strip_ansi("\n".join(lines)).strip()
                    if exit_code != "0":
                        clean_output += f"\n[Exit Status: {exit_code}]"
                    return self._truncate_output(clean_output)

            if time.time() - start_time > self.command_timeout:
                channel.send('\x03')  # Send Ctrl+C on timeout
                time.sleep(0.5)
                clean_output = self.strip_ansi(buf).strip()
                return f"{clean_output}\n[Command timed out after {self.command_timeout}s]"

            time.sleep(0.05)

    def close(self):
        """Closes interactive channel."""
        if self._interactive_channel:
            try:
                self._interactive_channel.close()
            except:
                pass
            self._interactive_channel = None


def clean_dirb_output(output: str) -> str:
    """Clean the output from the 'dirb' command."""
    output = re.sub(r'\x1b\[[0-9;]*[mGKH]', '', output)
    summary_pattern = r"(URL_BASE:.*\n|WORDLIST_FILES:.*\n|GENERATED WORDS:.*\n|---- Scanning URL:.*\n)"
    summary = "\n".join(re.findall(summary_pattern, output))
    url_pattern = r"http[^\s]+ \(CODE:[0-9]+\|SIZE:[0-9]+\)"
    urls = "\n".join(re.findall(url_pattern, output))
    stats_pattern = r"DOWNLOADED: \d+ - FOUND: \d+"
    stats = "\n".join(re.findall(stats_pattern, output))
    return f"{summary}\n{urls}\n{stats}".strip()


def clean_msfconsole_output(output: str) -> str:
    """Clean the output from the 'msfconsole' command."""
    output = re.sub(r'\x1b\[[0-9;]*[mGKH]', '', output)
    cleaned = [
        line for line in output.splitlines()
        if not any(x in line.lower() for x in ["loading", "warning:", "starting", "====="])
    ]
    return "\n".join(cleaned).strip()
