#!/usr/bin/env python3
import sys, os, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from common.logger import setup_logger
import config

logger = setup_logger("dcsync_response")

# LAB NOTE: The Administrator account is excluded from automated disablement
# because it serves as the SSH service account for orchestrator-to-DC communication.
# In a production environment, privileged accounts (Domain Admins, Administrator)
# would be flagged for immediate SOC escalation rather than automated disablement
# to avoid disrupting critical infrastructure access.
EXCLUDED_ACCOUNTS = {"Administrator", "krbtgt", "-", ""}

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

    if username in EXCLUDED_ACCOUNTS or "$" in username:
        logger.warning(
            f"ESCALATION REQUIRED: DCSync detected by privileged/excluded account '{username}'. "
            f"Automated disablement skipped — manual SOC investigation required."
        )
        actions.append({"action": "escalation_required", "target": username, "rc": -1})
    else:
        # Action 1: Disable the account that performed DCSync
        result = run_dc_command(f"Disable-ADAccount -Identity {username}")
        actions.append({"action": "disable_account", "target": username, "rc": result.returncode})
        logger.info(f"Disabled account: {username} | RC={result.returncode}")

        # Action 2: Force password reset on compromised account
        result = run_dc_command(f"Set-ADUser -Identity {username} -ChangePasswordAtLogon $true")
        actions.append({"action": "force_password_reset", "target": username, "rc": result.returncode})
        logger.info(f"Forced password reset: {username} | RC={result.returncode}")

    # Action 3: Log critical alert for manual krbtgt reset
    logger.warning("MANUAL ACTION REQUIRED: Reset krbtgt password to invalidate all Kerberos tickets")
    actions.append({"action": "manual_krbtgt_reset_required", "target": "krbtgt", "rc": -1})

    return {"status": "success", "technique": "T1003.006", "actions": actions}
