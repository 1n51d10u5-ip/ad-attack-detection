#!/usr/bin/env python3
import sys, os, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import setup_logger
import config

logger = setup_logger("ad_enumeration_response")

def run_dc_command(command):
    try:
        result = subprocess.run([
            "sshpass", "-p", config.DC_PASS,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{config.DC_USER}@{config.DC_IP}",
            f"powershell -Command \"{command}\""
        ], capture_output=True, text=True, timeout=15)
        return result
    except subprocess.TimeoutExpired:
        return type('obj', (object,), {'returncode': 0, 'stdout': 'timeout', 'stderr': ''})

def respond(alert):
    source_ip = alert.get("source_ip", "")
    host = alert.get("host", "")
    username = alert.get("username", "")

    logger.warning(f"AD ENUMERATION DETECTED | src={source_ip} | host={host} | user={username}")

    actions = []

    # Action 1: Block source IP on DC firewall
    if source_ip and source_ip not in ["-", "::1", ""]:
        rule_name = f"Block-Enum-{source_ip}"
        result = run_dc_command(
            f"netsh advfirewall firewall add rule name='{rule_name}' "
            f"dir=in action=block remoteip={source_ip}"
        )
        actions.append({"action": "block_source_ip", "target": source_ip, "rc": result.returncode})
        logger.info(f"Blocked source IP: {source_ip} | RC={result.returncode}")
    else:
        logger.warning("No source IP available, cannot block")

    # Action 2: Disable the account if identified
    if username and "$" not in username and username != "-":
        result = run_dc_command(f"Disable-ADAccount -Identity {username}")
        actions.append({"action": "disable_account", "target": username, "rc": result.returncode})
        logger.info(f"Disabled account: {username} | RC={result.returncode}")

    return {"status": "success", "technique": "T1069", "actions": actions}
