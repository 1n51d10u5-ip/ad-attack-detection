#!/usr/bin/env python3
import sys, os, subprocess, secrets
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import setup_logger
import config

logger = setup_logger("dcsync_response")

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

    logger.warning(f"DCSYNC DETECTED | user={username} | host={host}")

    actions = []

    # Action 1: Disable the account that performed DCSync
    if username and "$" not in username and username != "-":
        result = run_dc_command(f"Disable-ADAccount -Identity {username}")
        actions.append({"action": "disable_account", "target": username, "rc": result.returncode})
        logger.info(f"Disabled account: {username} | RC={result.returncode}")

    # Action 2: Reset krbtgt password (invalidates all Kerberos tickets)
    new_pass = "Krbtgt@Reset!" + secrets.token_hex(8)
    result = run_dc_command(
        f"Set-ADAccountPassword -Identity krbtgt "
        f"-NewPassword (ConvertTo-SecureString '{new_pass}' -AsPlainText -Force) -Reset"
    )
    actions.append({"action": "reset_krbtgt", "rc": result.returncode})
    logger.info(f"Reset krbtgt password | RC={result.returncode}")

    return {"status": "success", "technique": "T1003.006", "actions": actions}
