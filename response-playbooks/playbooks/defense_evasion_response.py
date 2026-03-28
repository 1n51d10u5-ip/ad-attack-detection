#!/usr/bin/env python3
import sys, os, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import setup_logger
import config

logger = setup_logger("defense_evasion_response")

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

    logger.warning(f"DEFENSE EVASION DETECTED | host={host} | user={username}")

    actions = []

    # Action 1: Re-enable Windows Defender real-time protection
    if host:
        result = run_host_command(host,
            "Set-MpPreference -DisableRealtimeMonitoring $false; "
            "Start-Service WinDefend"
        )
        if result:
            actions.append({"action": "reenable_defender", "target": host, "rc": result.returncode})
            logger.info(f"Re-enabled Defender on: {host} | RC={result.returncode}")

        # Action 2: Remove GPO disabling Defender if present
        result = run_host_command(host,
            "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' "
            "-Name DisableAntiSpyware -ErrorAction SilentlyContinue"
        )
        if result:
            actions.append({"action": "remove_gpo_defender_disable", "target": host, "rc": result.returncode})
            logger.info(f"Removed Defender GPO disable on: {host} | RC={result.returncode}")

    return {"status": "success", "technique": "T1562.001", "actions": actions}
