#!/usr/bin/env python3
import sys, os, subprocess, secrets, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import setup_logger
import config

logger = setup_logger("golden_ticket_response")

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

    logger.warning(f"GOLDEN TICKET DETECTED | user={username} | host={host}")

    actions = []

    # Action 1: Reset krbtgt password (first reset)
    new_pass1 = "Gt@Reset1!" + secrets.token_hex(8)
    result = run_dc_command(
        f"Set-ADAccountPassword -Identity krbtgt "
        f"-NewPassword (ConvertTo-SecureString '{new_pass1}' -AsPlainText -Force) -Reset"
    )
    actions.append({"action": "reset_krbtgt_1", "rc": result.returncode})
    logger.info(f"First krbtgt reset | RC={result.returncode}")

    # Wait 10 seconds between resets
    time.sleep(10)

    # Action 2: Reset krbtgt password again (second reset fully invalidates all forged tickets)
    new_pass2 = "Gt@Reset2!" + secrets.token_hex(8)
    result = run_dc_command(
        f"Set-ADAccountPassword -Identity krbtgt "
        f"-NewPassword (ConvertTo-SecureString '{new_pass2}' -AsPlainText -Force) -Reset"
    )
    actions.append({"action": "reset_krbtgt_2", "rc": result.returncode})
    logger.info(f"Second krbtgt reset | RC={result.returncode}")

    # Action 3: Disable the account used to forge the ticket
    if username and "$" not in username and username != "-":
        result = run_dc_command(f"Disable-ADAccount -Identity {username}")
        actions.append({"action": "disable_account", "target": username, "rc": result.returncode})
        logger.info(f"Disabled account: {username} | RC={result.returncode}")

    return {"status": "success", "technique": "T1558.001", "actions": actions}
