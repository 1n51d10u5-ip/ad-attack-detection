#!/usr/bin/env python3
import sys, os, subprocess, secrets
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import setup_logger
import config

logger = setup_logger("asrep_roasting_response")

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

    logger.warning(f"AS-REP ROASTING DETECTED | user={username} | host={host}")

    actions = []

    if username and "$" not in username and username != "-":
        # Action 1: Re-enable Kerberos pre-authentication
        result = run_dc_command(
            f"Set-ADAccountControl -Identity {username} -DoesNotRequirePreAuth $false"
        )
        actions.append({"action": "enable_preauth", "target": username, "rc": result.returncode})
        logger.info(f"Re-enabled pre-auth for: {username} | RC={result.returncode}")

        # Action 2: Reset password
        new_pass = "Asrep@Reset!" + secrets.token_hex(8)
        result = run_dc_command(
            f"Set-ADAccountPassword -Identity {username} "
            f"-NewPassword (ConvertTo-SecureString '{new_pass}' -AsPlainText -Force) -Reset"
        )
        actions.append({"action": "reset_password", "target": username, "rc": result.returncode})
        logger.info(f"Reset password for: {username} | RC={result.returncode}")

    return {"status": "success", "technique": "T1558.004", "actions": actions}
