"""
Comprehensive Zero-LLM Unit & Integration Test Suite for PenAgent.
Verifies all core pipeline mechanisms, real Kali SSH execution,
Pydantic schemas, state reducers, dynamic routing/backtracking,
SQLite checkpointing, and reporting without calling LLM APIs (0 token cost).
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
import sqlite3
from pydantic import ValidationError

from pipeline.tools import execute_kali_command, KaliShellInput
from pipeline.state import PentestState, merge_dicts
from pipeline.router import route_after_collector, route_after_scanner, route_after_exploiter
from pipeline.graph import create_pentest_graph
from pipeline.nodes import reporter_node
from actions.shell_manager import ShellManager


class TestPenAgentZeroLLM(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n=======================================================")
        print("  PenAgent Comprehensive Test Suite (Zero-LLM Mode)    ")
        print("=======================================================\n")

    @classmethod
    def tearDownClass(cls):
        ShellManager.get_instance().close()

    # ---------------------------------------------------------
    # Test 1: Real Kali SSH Execution & Tool Wrapper
    # ---------------------------------------------------------
    def test_01_real_kali_ssh_execution(self):
        print("[Test 1] Testing real Kali Linux SSH execution via execute_kali_command tool...")
        res = execute_kali_command.invoke({
            "command": "whoami; hostname -I",
            "intent": "Verify Kali connection and user identity",
            "timeout": 30
        })
        print(f"  -> Kali Output: {repr(res)}")
        self.assertIn("kali", res.lower(), "Expected output to contain 'kali' user")
        self.assertIn("100.74.213.15", res, "Expected output to show Kali Tailscale IP 100.74.213.15")
        print("  -> [PASS] Kali SSH channel connected and executed command successfully.\n")

    # ---------------------------------------------------------
    # Test 2: Pydantic Schema Validation & Parameter Guardrails
    # ---------------------------------------------------------
    def test_02_pydantic_schema_validation(self):
        print("[Test 2] Testing Pydantic schema validation for KaliShellInput...")
        # Valid input
        valid = KaliShellInput(command="nmap 100.84.151.2", intent="Port scan", timeout=60)
        self.assertEqual(valid.command, "nmap 100.84.151.2")
        self.assertEqual(valid.timeout, 60)

        # Invalid: timeout below minimum (ge=5)
        with self.assertRaises(ValidationError):
            KaliShellInput(command="nmap", timeout=2)

        # Invalid: timeout above maximum (le=300)
        with self.assertRaises(ValidationError):
            KaliShellInput(command="nmap", timeout=500)

        # Invalid: missing required command field
        with self.assertRaises(ValidationError):
            KaliShellInput()  # type: ignore

        print("  -> [PASS] Input schema correctly enforces parameter types and boundaries (5-300s).\n")

    # ---------------------------------------------------------
    # Test 3: PentestState Reducers & Incremental Aggregation
    # ---------------------------------------------------------
    def test_03_state_reducers(self):
        print("[Test 3] Testing PentestState reducers and dictionary merging...")
        d1 = {"80": "Apache 2.4", "22": "OpenSSH 8.2"}
        d2 = {"3306": "MySQL 8.0", "80": "Apache 2.4.49"}
        merged = merge_dicts(d1, d2)
        
        self.assertEqual(len(merged), 3, "Expected 3 unique ports")
        self.assertEqual(merged["80"], "Apache 2.4.49", "Expected latest service banner to update port 80")
        self.assertEqual(merged["22"], "OpenSSH 8.2")
        self.assertEqual(merged["3306"], "MySQL 8.0")
        print("  -> [PASS] State reducers correctly aggregate ports and update service fingerprints.\n")

    # ---------------------------------------------------------
    # Test 4: Dynamic Conditional Routing & Backtracking Logic
    # ---------------------------------------------------------
    def test_04_dynamic_routing_and_backtracking(self):
        print("[Test 4] Testing dynamic routing conditions and backtracking algorithm...")
        
        # 4a: Collector routing
        self.assertEqual(
            route_after_collector({"open_ports": [], "phase_step_count": 1, "max_phase_steps": 3}),
            "collector",
            "Empty ports should trigger collector retry"
        )
        self.assertEqual(
            route_after_collector({"open_ports": [80], "phase_step_count": 1, "max_phase_steps": 3}),
            "scanner",
            "Discovered ports should advance to scanner"
        )
        self.assertEqual(
            route_after_collector({"open_ports": [], "phase_step_count": 3, "max_phase_steps": 3}),
            "reporter",
            "Max steps reached without ports should exit to reporter"
        )

        # 4b: Scanner routing
        self.assertEqual(
            route_after_scanner({"vulnerabilities": [{"cve": "CVE-2021-41773"}]}),
            "exploiter",
            "Found vulnerabilities should advance to exploiter"
        )
        self.assertEqual(
            route_after_scanner({"vulnerabilities": [], "open_ports": [80]}),
            "exploiter",
            "Open ports should advance to exploiter even without explicit CVE"
        )

        # 4c: Exploiter routing & Backtracking!
        self.assertEqual(
            route_after_exploiter({"is_compromised": True, "retry_count": 1, "max_retries": 3}),
            "reporter",
            "Target compromised should immediately advance to reporter"
        )
        self.assertEqual(
            route_after_exploiter({"is_compromised": False, "retry_count": 1, "max_retries": 3}),
            "exploiter",
            "Failed exploit attempt with retries left should retry exploiter"
        )
        # THE CORE BACKTRACKING TEST:
        self.assertEqual(
            route_after_exploiter({"is_compromised": False, "retry_count": 3, "max_retries": 3}),
            "scanner",
            "Failed exploit reaching max retries MUST BACKTRACK to scanner!"
        )

        print("  -> [PASS] Dynamic routing correctly handles forward progression, retries, and backtracking.\n")

    # ---------------------------------------------------------
    # Test 5: SQLite Checkpoint Persistence & Session Isolation
    # ---------------------------------------------------------
    def test_05_sqlite_checkpointer_isolation(self):
        print("[Test 5] Testing SQLite checkpoint persistence and multi-thread isolation...")
        app = create_pentest_graph(":memory:")

        config_a = {"configurable": {"thread_id": "session-target-a"}}
        config_b = {"configurable": {"thread_id": "session-target-b"}}

        # Write state to Session A
        app.update_state(config_a, {
            "target": "100.84.151.2",
            "open_ports": [22, 80],
            "is_compromised": False
        })

        # Write state to Session B
        app.update_state(config_b, {
            "target": "192.168.1.100",
            "open_ports": [443],
            "is_compromised": True
        })

        # Read back Session A
        snap_a = app.get_state(config_a)
        self.assertEqual(snap_a.values["target"], "100.84.151.2")
        self.assertEqual(snap_a.values["open_ports"], [22, 80])
        self.assertFalse(snap_a.values["is_compromised"])

        # Read back Session B
        snap_b = app.get_state(config_b)
        self.assertEqual(snap_b.values["target"], "192.168.1.100")
        self.assertEqual(snap_b.values["open_ports"], [443])
        self.assertTrue(snap_b.values["is_compromised"])

        print("  -> [PASS] SQLite checkpointer maintains perfect state persistence and thread isolation.\n")

    # ---------------------------------------------------------
    # Test 6: Reporter Node Report Generation (Local Synthesis)
    # ---------------------------------------------------------
    def test_06_reporter_node_synthesis(self):
        print("[Test 6] Testing ReporterNode local markdown report synthesis...")
        mock_final_state = {
            "target": "100.84.151.2",
            "open_ports": [22, 80],
            "services": {"22": "OpenSSH 8.2p1", "80": "Apache httpd 2.4.49"},
            "vulnerabilities": [{"cve": "CVE-2021-41773", "target": "100.84.151.2"}],
            "flags": ["root privilege confirmed", "flag{penagent_owned}"],
            "is_compromised": True,
            "phase_summaries": [
                "[Collector] Open ports 22, 80 found.",
                "[Scanner] Identified CVE-2021-41773 Apache path traversal.",
                "[Exploiter] Executed RCE PoC, captured root flag."
            ],
            "action_history": [
                {"command": "nmap", "output": "ports open"},
                {"command": "curl poc", "output": "root:x:0:0"}
            ]
        }

        result = reporter_node(mock_final_state)
        self.assertEqual(result["current_phase"], "complete")
        self.assertIn("phase_summaries", result)
        report_text = result["phase_summaries"][0]

        self.assertIn("# PenAgent Autonomous Penetration Testing Report", report_text)
        self.assertIn("COMPROMISED (Success)", report_text)
        self.assertIn("CVE-2021-41773", report_text)
        self.assertIn("flag{penagent_owned}", report_text)
        self.assertIn("Apache httpd 2.4.49", report_text)

        print("  -> [PASS] ReporterNode generates structured, compliant Markdown engagement report.\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
