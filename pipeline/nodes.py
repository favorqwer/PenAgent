"""
Node implementations for PenAgent LangGraph workflow.
Powered by Native Tool Calling (JSON Schema) instead of brittle regex parsing:
1. CollectorNode: Reconnaissance & Asset Discovery
2. ScannerNode: Vulnerability Assessment & Service Enumeration
3. ExploiterNode: Exploitation, Proof-of-Concept & Verification
4. ReporterNode: Automated Synthesis of Penetration Testing Findings
"""

import re
import time
from typing import Any, Dict, List, Tuple
from loguru import logger

from pipeline.state import ActionLog, PentestState
from pipeline.tools import execute_kali_command, get_llm
from utils.log_common import build_logger

app_logger = build_logger()


def invoke_agent_with_tool(prompt: str, role: str) -> Tuple[str, List[ActionLog]]:
    """
    Invokes LLM with native tool calling bound to execute_kali_command.
    Executes all requested tool calls directly via Pydantic validation.
    """
    llm = get_llm(temperature=0.1)
    llm_with_tools = llm.bind_tools([execute_kali_command])

    app_logger.info(f"[{role.upper()}] Prompting LLM with native Tool Calling...")
    ai_response = llm_with_tools.invoke(prompt)

    composite_output = []
    action_logs = []

    if ai_response.tool_calls:
        for tool_call in ai_response.tool_calls:
            args = tool_call["args"]
            cmd = args.get("command", "")
            intent = args.get("intent", f"{role} action")
            app_logger.info(f"[{role.upper()}] Native Tool Call -> '{cmd}' ({intent})")

            t0 = time.time()
            output = execute_kali_command.invoke(args)
            duration = round(time.time() - t0, 2)

            composite_output.append(f"$ {cmd}\n{output}")
            action_logs.append({
                "role": role,
                "instruction": intent,
                "command": cmd,
                "output": output,
                "status": "success" if not output.startswith("Error executing") else "failed",
                "timestamp": duration
            })
    else:
        # Fallback if model decided to respond with text instructions
        content = ai_response.content if isinstance(ai_response.content, str) else str(ai_response.content)
        app_logger.warning(f"[{role.upper()}] Model responded with text instead of direct tool call: {content[:100]}...")
        # Check if text contains an obvious single command
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        for line in lines:
            if line.startswith(("nmap ", "nikto ", "curl ", "gobuster ", "dirb ", "searchsploit ")):
                output = execute_kali_command.invoke({"command": line, "intent": "Fallback execution"})
                composite_output.append(f"$ {line}\n{output}")
                action_logs.append({
                    "role": role,
                    "instruction": "Fallback text command execution",
                    "command": line,
                    "output": output,
                    "status": "success",
                    "timestamp": 1.0
                })
                break

    return "\n\n".join(composite_output), action_logs


# ==========================================
# 1. Collector Node (Reconnaissance)
# ==========================================

def collector_node(state: PentestState) -> Dict[str, Any]:
    """
    Performs network reconnaissance on the target.
    Scans for open ports and fingerprints running services via execute_kali_command.
    """
    target = state.get("target", "127.0.0.1")
    task_desc = state.get("task_description", "")
    existing_ports = state.get("open_ports", [])
    step = state.get("phase_step_count", 0) + 1

    prompt = f"""You are the Reconnaissance Agent (Collector) in an autonomous penetration testing team.
Your objective is to discover all open network ports, active services, and operating system fingerprints on the target.

Target Machine IP: {target}
Testing Goal: {task_desc}
Already known open ports: {existing_ports if existing_ports else "None discovered yet"}

Call the 'execute_kali_command' tool to run appropriate network scanning commands.
Recommended tools: nmap (e.g. 'nmap -sV -T4 --open -p 1-1000 {target}' or fast ports first).
"""

    output, logs = invoke_agent_with_tool(prompt, role="collector")

    # Regex parse discovered ports and service versions from Nmap output
    new_ports = []
    new_services = {}
    port_matches = re.findall(r'(\d+)/(?:tcp|udp)\s+open\s+([^\r\n]+)', output)
    for port_str, service_str in port_matches:
        port = int(port_str)
        if port not in existing_ports and port not in new_ports:
            new_ports.append(port)
        new_services[str(port)] = service_str.strip()

    summary = f"[Collector] Completed scan on {target}. Discovered open ports: {list(new_services.keys())}."
    app_logger.info(summary)

    return {
        "open_ports": new_ports,
        "services": new_services,
        "action_history": logs,
        "phase_step_count": step,
        "current_phase": "collector",
        "phase_summaries": [summary]
    }


# ==========================================
# 2. Scanner Node (Vulnerability Assessment)
# ==========================================

def scanner_node(state: PentestState) -> Dict[str, Any]:
    """
    Analyzes discovered services and investigates vulnerabilities, misconfigurations, and CVEs.
    """
    target = state.get("target", "127.0.0.1")
    ports = state.get("open_ports", [])
    services = state.get("services", {})
    step = state.get("phase_step_count", 0) + 1

    services_desc = "\n".join([f"- Port {p}: {s}" for p, s in services.items()]) if services else "No services reported"

    prompt = f"""You are the Vulnerability Scanner Agent in an autonomous penetration testing team.
Your objective is to identify potential vulnerabilities, security flaws, weak configurations, or known CVEs in the target services.

Target Machine IP: {target}
Active Open Ports & Services:
{services_desc}

Call the 'execute_kali_command' tool to run targeted vulnerability scanning or enumeration tools.
Recommended tools: searchsploit, nikto, curl, dirb, hydra, or nmap scripts.
"""

    output, logs = invoke_agent_with_tool(prompt, role="scanner")

    # Extract detected CVEs or vulnerabilities
    cve_matches = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', output, re.IGNORECASE)))
    new_vulns = []
    for cve in cve_matches:
        new_vulns.append({
            "cve": cve.upper(),
            "target": target,
            "evidence": "Identified in scanner output"
        })

    # Check for sensitive directory exposure or web server banners
    if "200 OK" in output or "Directory indexing found" in output:
        new_vulns.append({
            "name": "Information Disclosure / Directory Listing",
            "target": target,
            "evidence": "Web directory or sensitive path discovered"
        })

    summary = f"[Scanner] Enumerated {len(ports)} ports. Found {len(new_vulns)} potential vulnerabilities/findings."
    app_logger.info(summary)

    return {
        "vulnerabilities": new_vulns,
        "action_history": logs,
        "phase_step_count": step,
        "current_phase": "scanner",
        "phase_summaries": [summary]
    }


# ==========================================
# 3. Exploiter Node (Exploitation & Verification)
# ==========================================

def exploiter_node(state: PentestState) -> Dict[str, Any]:
    """
    Attempts to exploit identified vulnerabilities to obtain unauthorized access or proof of compromise.
    """
    target = state.get("target", "127.0.0.1")
    vulns = state.get("vulnerabilities", [])
    services = state.get("services", {})
    retry_count = state.get("retry_count", 0) + 1

    vuln_desc = "\n".join([str(v) for v in vulns]) if vulns else "No specific CVE confirmed; attempt service enumeration/bruteforce/PoC"
    services_desc = "\n".join([f"- Port {p}: {s}" for p, s in services.items()])

    prompt = f"""You are the Exploitation Agent (Exploiter) in an autonomous penetration testing team.
Your objective is to execute an exploit payload or Proof-of-Concept against the target to gain access, verify vulnerabilities, or escalate privileges.

Target Machine IP: {target}
Identified Vulnerabilities:
{vuln_desc}
Available Services:
{services_desc}
Current Attempt Count: {retry_count}

Call the 'execute_kali_command' tool to execute an exploit or verification command (e.g., curl PoC, msfconsole script, python exploit, or reverse shell).
Always include a verification command like 'whoami' or 'id' if command execution is expected.
"""

    output, logs = invoke_agent_with_tool(prompt, role="exploiter")

    # Determine if exploit succeeded (Proof of Concept verification)
    compromised = False
    flags = []

    # Check for root/user command execution evidence
    if re.search(r'uid=\d+\([^\)]+\)\s+gid=\d+', output):
        compromised = True
        flags.append(f"Remote Code Execution confirmed: {re.search(r'uid=\d+\([^\)]+\)', output).group(0)}")
    elif "root@" in output or "whoami\nroot" in output or "uid=0(root)" in output:
        compromised = True
        flags.append("Root privilege achieved!")
    elif re.search(r'flag\{[^\}]+\}', output, re.IGNORECASE):
        found_flag = re.search(r'flag\{[^\}]+\}', output, re.IGNORECASE).group(0)
        compromised = True
        flags.append(f"Flag captured: {found_flag}")

    summary = f"[Exploiter] Attempt #{retry_count}. Compromised: {compromised}."
    app_logger.info(summary)

    return {
        "retry_count": retry_count,
        "is_compromised": compromised,
        "flags": flags,
        "action_history": logs,
        "current_phase": "exploiter",
        "phase_summaries": [summary]
    }


# ==========================================
# 4. Reporter Node (Final Assessment Report)
# ==========================================

def reporter_node(state: PentestState) -> Dict[str, Any]:
    """
    Synthesizes the entire engagement into a structured penetration testing report.
    """
    target = state.get("target", "127.0.0.1")
    ports = state.get("open_ports", [])
    services = state.get("services", {})
    vulns = state.get("vulnerabilities", [])
    flags = state.get("flags", [])
    compromised = state.get("is_compromised", False)
    summaries = state.get("phase_summaries", [])
    total_actions = len(state.get("action_history", []))

    report = f"""# PenAgent Autonomous Penetration Testing Report

## Executive Summary
- **Target IP**: `{target}`
- **Engagement Result**: {"COMPROMISED (Success)" if compromised else "ASSESSMENT COMPLETE (Uncompromised)"}
- **Discovered Open Ports**: `{len(ports)}` ports ({ports})
- **Identified Potential Vulnerabilities**: `{len(vulns)}` findings
- **Total Commands Executed**: `{total_actions}` actions

## Attack Surface & Services
"""
    for p, s in services.items():
        report += f"- **Port {p}**: `{s}`\n"

    report += "\n## Vulnerabilities & Findings\n"
    if vulns:
        for v in vulns:
            report += f"- {v}\n"
    else:
        report += "- No high-severity critical CVEs confirmed during automated scanning.\n"

    report += "\n## Proof of Compromise / Flags\n"
    if flags:
        for f in flags:
            report += f"- **{f}**\n"
    else:
        report += "- Target remained resilient to automated exploit attempts.\n"

    report += "\n## Timeline of Agent Actions\n"
    for s in summaries:
        report += f"- {s}\n"

    app_logger.success(f"[Reporter] Penetration test report compiled for target {target}.")

    return {
        "current_phase": "complete",
        "phase_summaries": [report]
    }
