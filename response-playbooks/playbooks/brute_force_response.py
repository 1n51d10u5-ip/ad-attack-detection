#!/usr/bin/env python3
import sys, os, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import setup_logger
import config

logger = setup_logger("brute_force_response")

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
    username = alert.get("username", "")
    host = alert.get("host", "")
    source_ip = alert.get("source_ip", "")

    logger.warning(f"BRUTE FORCE DETECTED | user={username} | host={host} | src={source_ip}")

    actions = []

    if username and "$" not in username and username != "-":
        result = run_dc_command(f"Disable-ADAccount -Identity {username}")
        actions.append({"action": "disable_account", "target": username, "rc": result.returncode})
        logger.info(f"Disabled account: {username} | RC={result.returncode}")

    return {"status": "success", "technique": "T1110", "actions": actions}
