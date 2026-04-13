#!/usr/bin/env python3
import sys, os, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import setup_logger
import config

logger = setup_logger("gpo_abuse_response")

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

def extract_gpo_name(alert):
    raw = alert.get("raw", {})
    winlog = raw.get("winlog", {}).get("event_data", {})
    attr_name = winlog.get("AttributeLDAPDisplayName", "")
    attr_value = winlog.get("AttributeValue", "")

    # Only extract when the modified attribute is the displayName
    if attr_name == "displayName" and attr_value and attr_value != "-":
        return attr_value
    return None

def respond(alert):
    host = alert.get("host", "")
    username = alert.get("username", "")
    gpo_name = extract_gpo_name(alert)

    logger.warning(f"GPO ABUSE DETECTED | gpo={gpo_name} | host={host} | user={username}")

    actions = []

    if gpo_name:
        result = run_dc_command(f"Remove-GPO -Name '{gpo_name}' -Confirm:$false")
        actions.append({"action": "remove_gpo", "target": gpo_name, "rc": result.returncode})
        logger.info(f"Removed GPO: {gpo_name} | RC={result.returncode}")

        result2 = run_dc_command("Invoke-GPUpdate -Force")
        actions.append({"action": "gp_update", "rc": result2.returncode})
        logger.info(f"Forced GP update | RC={result2.returncode}")
    else:
        logger.warning("Could not extract GPO display name — skipping removal")

    return {"status": "success", "technique": "T1484.001", "actions": actions}
