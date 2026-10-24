"""
Standard Tool definitions and LLM factory for PenAgent LangGraph workflow.
Replaces brittle regex parsing with Pydantic-validated Native Tool Calling.
"""

import time
import uuid
from typing import Optional
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from actions.shell_manager import ShellManager
from config.config import Configs
from utils.log_common import build_logger

logger = build_logger()


class KaliShellInput(BaseModel):
    """Input parameters for executing commands on the Kali Linux attack machine."""
    command: str = Field(
        ...,
        description="The exact Linux shell command to execute on Kali (e.g. 'nmap -sV 100.84.151.2', 'nikto -h 100.84.151.2')"
    )
    intent: Optional[str] = Field(
        default="Penetration testing probe",
        description="Short technical purpose explaining what this command accomplishes"
    )
    timeout: Optional[int] = Field(
        default=60,
        ge=5,
        le=300,
        description="Command timeout limit in seconds (5-300)"
    )


@tool("execute_kali_command", args_schema=KaliShellInput)
def execute_kali_command(command: str, intent: str = "Penetration probe", timeout: int = 60) -> str:
    """
    Executes a shell command on the remote Kali Linux attack machine via SSH.
    Supports network scanners, web enumerators, and exploitation tools.
    """
    logger.info(f"[Tool: execute_kali_command] Command: '{command}' (Intent: {intent})")
    shell = ShellManager.get_instance().get_shell()
    t0 = time.time()
    try:
        output = shell.execute_cmd(command)
        duration = round(time.time() - t0, 2)
        logger.info(f"[Tool: execute_kali_command] Finished in {duration}s")
        return output.strip()
    except Exception as e:
        logger.error(f"[Tool: execute_kali_command] Failed: {e}")
        return f"Error executing command '{command}': {str(e)}"


def get_llm(temperature: float = 0.1) -> ChatOpenAI:
    """
    Constructs a LangChain ChatOpenAI instance configured with PenAgent's model settings.
    Automatically injects required gateway routing headers (e.g. x-opencode-session).
    """
    headers = {}
    base_url_str = str(Configs.llm_config.base_url).lower()
    if "opencode" in base_url_str:
        headers["x-opencode-session"] = str(uuid.uuid4())

    llm = ChatOpenAI(
        model=Configs.llm_config.llm_model_name,
        api_key=Configs.llm_config.api_key,
        base_url=Configs.llm_config.base_url,
        default_headers=headers or None,
        temperature=temperature,
        timeout=Configs.llm_config.timeout
    )
    return llm
