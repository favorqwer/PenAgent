"""Zero-LLM / zero-SSH tests for the layered agent pipeline.

Covers: state reducers, plan merging/topology, command risk policy, evidence
extraction, a full scripted engagement, command-level HITL interrupt/resume,
and the exploitation -> scanning backtrack path.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langgraph.types import Command

from agent import memory, settings
from agent.schema import PlanSpec, TaskSpec
from agent.dry_run import FakeShell, RULES, install_dry_run, uninstall
from agent.context import observations_digest
from agent.findings import extract_findings, has_compromise_evidence, render_facts
from agent.graph import create_agent_graph
from agent.plan import merge_plan, order_plan, select_next_task
from agent.policy import classify_command
from agent.schema import merge_events, merge_ports, merge_services, merge_vulns


def _initial(thread_id: str, hitl: bool = False) -> dict:
    return {
        "target": "100.84.151.2",
        "goal": "prove command execution",
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
        "hitl_enabled": hitl,
        "hitl_scope": "command",
        "dry_run": True,
        "thread_id": thread_id,
        "target_memory": "",
        "final_report": "",
        "max_commands": 250,
    }


def _drain(app, pending, config):
    """Run until an interrupt or completion; return (interrupt_payload, snapshots)."""
    for chunk in app.stream(
        pending, config=config, stream_mode=["updates", "custom"], subgraphs=True, durability="sync"
    ):
        if len(chunk) == 3:
            _, mode, payload = chunk
        else:
            mode, payload = chunk
        if mode == "updates" and isinstance(payload, dict) and "__interrupt__" in payload:
            return payload["__interrupt__"][0].value
    return None


class TestStateAndPlan(unittest.TestCase):
    def test_reducers(self):
        self.assertEqual(merge_ports([22, 80], [80, 8080]), [22, 80, 8080])
        merged = merge_services({"80": {"service": "http", "banner": "Apache 2.4.49"}}, {"80": {"service": "", "raw": "x"}})
        self.assertEqual(merged["80"]["banner"], "Apache 2.4.49")
        self.assertEqual(merged["80"]["raw"], "x")

        vulns = merge_vulns([{"cve": "CVE-2021-41773"}], [{"cve": "cve-2021-41773"}, {"name": "dir listing"}])
        self.assertEqual(len(vulns), 2)

        events = merge_events([{"id": "a", "command": "x"}], [{"id": "a", "command": "x"}, {"id": "b", "command": "y"}])
        self.assertEqual([e["id"] for e in events], ["a", "b"])

    def test_plan_merge_keeps_successful_tasks(self):
        old = [
            {"id": "v1-t0", "instruction": "scan ports", "status": "success", "result": "22/80", "depends_on": []},
            {"id": "v1-t1", "instruction": "bust dirs", "status": "success", "result": "/admin", "depends_on": ["v1-t0"]},
            {"id": "v1-t2", "instruction": "exploit apache", "status": "failed", "result": "no luck", "depends_on": []},
        ]
        spec = PlanSpec(
            tasks=[
                TaskSpec(id="a", instruction="scan ports", action="Shell"),
                TaskSpec(id="b", instruction="exploit tomcat", action="Exploit", dependent_task_ids=["a"]),
            ]
        )
        merged = merge_plan(old, spec, version=2, max_tasks=5)
        instructions = [t["instruction"] for t in merged]
        self.assertIn("bust dirs", instructions, "successful task dropped by the model must survive")
        self.assertIn("exploit tomcat", instructions)
        tomcat = next(t for t in merged if t["instruction"] == "exploit tomcat")
        self.assertEqual(tomcat["depends_on"], [next(t["id"] for t in merged if t["instruction"] == "scan ports")])

    def test_selection_respects_dependencies_and_failures(self):
        plan = [
            {"id": "a", "instruction": "a", "status": "success", "depends_on": []},
            {"id": "b", "instruction": "b", "status": "pending", "depends_on": ["a"]},
            {"id": "c", "instruction": "c", "status": "failed", "depends_on": []},
            {"id": "d", "instruction": "d", "status": "pending", "depends_on": ["c"]},
        ]
        ordered = order_plan(plan)
        first = select_next_task(ordered)
        self.assertEqual(first["id"], "b")
        self.assertEqual(next(t for t in ordered if t["id"] == "d")["status"], "blocked")


class TestPolicyAndEvidence(unittest.TestCase):
    def test_risk_classification(self):
        self.assertEqual(classify_command("nmap -sV 10.0.0.1")[0], "read")
        self.assertEqual(classify_command("gobuster dir -u http://x -w list")[0], "probe")
        self.assertEqual(classify_command("curl -sS -X PUT http://x -u a:b")[0], "intrusive")
        self.assertEqual(classify_command("msfconsole -x 'use exploit/x'")[0], "intrusive")
        self.assertEqual(classify_command("rm -rf /")[0], "destructive")
        self.assertEqual(classify_command("somecoollateral --flag")[0], "unknown")

    def test_extraction_and_evidence(self):
        nmap = "22/tcp   open  ssh     OpenSSH 8.2p1\n80/tcp   open  http    Apache httpd 2.4.49\n"
        found = extract_findings(nmap, "nmap -sV x", "collector")
        self.assertEqual(found["open_ports"], [22, 80])
        self.assertIn("Apache", found["services"]["80"]["banner"])

        self.assertTrue(has_compromise_evidence("uid=0(root) gid=0(root)"))
        self.assertFalse(has_compromise_evidence("root:x:0:0:root:/root:/bin/bash"))

    def test_model_claims_are_not_evidence(self):
        from langchain_core.messages import AIMessage, ToolMessage

        fabricated = [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "finish_task",
                        "args": {"success": True, "summary": "root shell", "evidence": "uid=0(root)"},
                        "id": "c1",
                    }
                ],
            ),
            ToolMessage(content="[dry-run] no canned output for the command", tool_call_id="c1"),
        ]
        digest = observations_digest(fabricated)
        self.assertNotIn("uid=0", digest)
        self.assertFalse(has_compromise_evidence(digest))

        real = [ToolMessage(content="uid=0(root) gid=0(root)", tool_call_id="c2")]
        self.assertTrue(has_compromise_evidence(observations_digest(real)))

    def test_render_facts_can_hide_tried_vectors(self):
        state = {"open_ports": [80], "tried_vectors": ["apache failed"]}
        self.assertIn("apache failed", render_facts(state))
        self.assertNotIn("apache failed", render_facts(state, include_tried=False))


class TestKaliOverride(unittest.TestCase):
    def test_apply_kali_only_changes_host(self):
        from config.config import Configs
        from agent.runner import apply_kali

        original = Configs.basic_config.kali.get("hostname")
        try:
            self.assertEqual(apply_kali("10.9.9.9"), "10.9.9.9")
            self.assertEqual(Configs.basic_config.kali["hostname"], "10.9.9.9")
            # empty / None keep the current host
            self.assertEqual(apply_kali(""), "10.9.9.9")
            self.assertEqual(apply_kali(None), "10.9.9.9")
            # port/user/password are untouched
            self.assertEqual(Configs.basic_config.kali.get("port"), 22)
            self.assertEqual(Configs.basic_config.kali.get("username"), "kali")
        finally:
            from actions.shell_manager import ShellManager

            ShellManager.set_host_override(None)
            Configs.basic_config.kali["hostname"] = original

    def test_override_survives_a_config_cache_miss(self):
        """--kali must not be reverted when another config object is touched.

        The settings objects are re-read from YAML on every shared-cache miss, and
        the cache holds one entry, so reading llm_config evicts basic_config and
        silently restores the hostname from the file. That is how a lab2 run
        ended up connecting to the lab1 Kali box.
        """
        from config.config import Configs
        from agent.runner import apply_kali
        from actions.shell_manager import ShellManager

        original = Configs.basic_config.kali.get("hostname")
        try:
            apply_kali("10.9.9.9")
            _ = Configs.llm_config.llm_model_name
            self.assertEqual(ShellManager.effective_host(), "10.9.9.9")
        finally:
            ShellManager.set_host_override(None)
            Configs.basic_config.kali["hostname"] = original


class TestRealSSH(unittest.TestCase):
    """Smoke test against the real Kali box; skipped automatically when offline."""

    def test_kali_ssh_execution(self):
        from actions.shell_manager import ShellManager
        from agent.tools import execute_kali_command

        try:
            output = execute_kali_command.invoke(
                {"command": "whoami; hostname -I", "intent": "smoke test", "timeout": 15}
            )
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"Kali unreachable: {type(exc).__name__}: {exc}")
        finally:
            ShellManager.get_instance().close()

        if "kali" not in output.lower():
            self.skipTest(f"unexpected output from Kali: {output[:160]}")
        self.assertIn("kali", output.lower())


class GraphHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="penagent-agent-")
        settings.set_value("storage.checkpoint_path", str(Path(self.tmp) / "cp.db"))
        settings.set_value("storage.store_path", str(Path(self.tmp) / "store.db"))
        settings.set_value("storage.report_dir", str(Path(self.tmp) / "reports"))
        settings.set_value("storage.projection", False)
        settings.set_value("hitl.require_approval_phases", ["exploiter"])
        memory.reset_caches()
        self.app = create_agent_graph()

    def tearDown(self):
        uninstall()
        memory.reset_caches()


class TestFullGraph(GraphHarness):
    def test_scripted_engagement_reaches_compromise(self):
        install_dry_run("100.84.151.2")
        thread = "t-success"
        config = {"configurable": {"thread_id": thread}}
        payload = _drain(self.app, _initial(thread), config)
        self.assertIsNone(payload, "no approval expected without --hitl")

        state = self.app.get_state(config).values
        self.assertTrue(state.get("is_compromised"))
        self.assertEqual(state.get("phase"), "done")
        self.assertEqual(len(state.get("phase_summaries") or []), 3)
        self.assertGreaterEqual(state.get("commands_used", 0), 6)
        # Counting must not double at subgraph boundaries: the task subgraph
        # returns an absolute total, the parent channel overwrites (no reducer).
        from agent import tools as shell_module

        self.assertEqual(
            state.get("commands_used"),
            len(shell_module.get_shell().calls),
            "commands_used must match the number of executed commands exactly",
        )
        self.assertIn(22, state.get("open_ports") or [])
        self.assertIn("/admin:200", [v.get("identifier") for v in state.get("vulnerabilities") or []])
        self.assertTrue(state.get("tried_vectors"), "failed Apache attempt should be recorded")

        report_path = Path(self.tmp) / "reports" / f"{thread}.md"
        self.assertTrue(report_path.exists())
        report = report_path.read_text(encoding="utf-8")
        self.assertIn("compromise confirmed", report.lower())
        summaries = state.get("phase_summaries") or []
        self.assertEqual(sum("Reconnaissance" in s for s in summaries), 1, "summaries must not duplicate")

    def test_hitl_interrupt_and_resume(self):
        install_dry_run("100.84.151.2")
        thread = "t-hitl"
        config = {"configurable": {"thread_id": thread}}

        payload = _drain(self.app, _initial(thread, hitl=True), config)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["type"], "command_approval")
        self.assertEqual(payload["phase"], "exploiter")
        self.assertTrue(any(item["risk"] == "intrusive" for item in payload["commands"]))

        second = _drain(self.app, Command(resume={"approved": True, "scope": "task"}), config)
        self.assertIsNone(second)
        state = self.app.get_state(config).values
        self.assertTrue(state.get("is_compromised"))

    def test_backtrack_when_exploitation_keeps_failing(self):
        brain = install_dry_run("100.84.151.2")
        # Remove the Tomcat rules so both exploit tasks fail.
        from agent import tools as shell_module

        shell_module.set_shell_override(
            FakeShell([(needle, out) for needle, out in RULES if "manager/text/deploy" not in needle and "exec?cmd=id" not in needle])
        )

        thread = "t-backtrack"
        config = {"configurable": {"thread_id": thread}}
        _drain(self.app, _initial(thread), config)

        state = self.app.get_state(config).values
        self.assertFalse(state.get("is_compromised"))
        self.assertEqual(state.get("backtrack_count"), 1)
        self.assertTrue(any("Backtrack" in s for s in (state.get("phase_summaries") or [])))
        self.assertTrue(any("Fail" in s or "Exploitation" in s for s in (state.get("phase_summaries") or [])))
        self.assertGreater(brain.command_calls, 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
