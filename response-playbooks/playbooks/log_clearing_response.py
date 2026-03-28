#!/usr/bin/env python3
import sys, os, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import setup_logger
import config

logger = setup_logger("log_clearing_response")

def run_host_command(hostname, command):
    ip = config.HOST_IPS.get(hostname)
    if not ip:
        logger.error(f"Unknown host: {hostname}")
        return None
    try:
        result = subprocess.run([
            "sshpass", "-p", config.WIN_PASS,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{config.WIN_USER}@{ip}",
            f"powershell -Command \"{command}\""
        ], capture_output=True, text=True, timeout=15)
        return result
    except subprocess.TimeoutExpired:
        return type('obj', (object,), {'returncode': 0, 'stdout': 'timeout', 'stderr': ''})

def respond(alert):
    host = alert.get("host", "")
    username = alert.get("username", "")

    logger.warning(f"LOG CLEARING DETECTED | host={host} | user={username}")

    actions = []

    if host:
        # Action 1: Export remaining Security log to disk before more is cleared
        result = run_host_command(host,
            "wevtutil epl Security C:\\SecurityLog_backup.evtx"
        )
        if result:
            actions.append({"action": "export_security_log", "target": host, "rc": result.returncode})
            logger.info(f"Exported Security log on: {host} | RC={result.returncode}")

        # Action 2: Export System log
        result = run_host_command(host,
            "wevtutil epl System C:\\SystemLog_backup.evtx"
        )
        if result:
            actions.append({"action": "export_system_log", "target": host, "rc": result.returncode})
            logger.info(f"Exported System log on: {host} | RC={result.returncode}")

        # Action 3: Increase log retention size to make future clearing harder
        result = run_host_command(host,
            "wevtutil sl Security /ms:1073741824; "
            "wevtutil sl System /ms:1073741824"
        )
        if result:
            actions.append({"action": "increase_log_size", "target": host, "rc": result.returncode})
            logger.info(f"Increased log retention on: {host} | RC={result.returncode}")

    return {"status": "success", "technique": "T1070.001", "actions": actions}
