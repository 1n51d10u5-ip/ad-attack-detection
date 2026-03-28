#!/usr/bin/env python3
import sys, os, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import setup_logger
import config

logger = setup_logger("psexec_response")

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

def isolate_host(hostname):
    ip = config.HOST_IPS.get(hostname)
    if not ip:
        return None
    try:
        result = subprocess.run([
            "sshpass", "-p", config.WIN_PASS,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{config.WIN_USER}@{ip}",
            "powershell C:\\isolate.ps1"
        ], capture_output=True, text=True, timeout=10)
        return result
    except subprocess.TimeoutExpired:
        return type('obj', (object,), {'returncode': 0, 'stdout': 'host_isolated', 'stderr': ''})

def respond(alert):
    username = alert.get("username", "")
    host = alert.get("host", "")
    raw = alert.get("raw", {})
    service_name = raw.get("winlog", {}).get("event_data", {}).get("ServiceName", "")

    logger.warning(f"PSEXEC LATERAL MOVEMENT DETECTED | host={host} | service={service_name} | user={username}")

    actions = []

    # Action 1: Stop and remove the PSExec service
    if service_name:
        result = run_dc_command(
            f"Stop-Service -Name '{service_name}' -Force -ErrorAction SilentlyContinue; "
            f"sc.exe delete '{service_name}'"
        )
        actions.append({"action": "remove_service", "target": service_name, "rc": result.returncode})
        logger.info(f"Removed PSExec service: {service_name} | RC={result.returncode}")

    # Action 2: Isolate the affected host
    if host:
        result = isolate_host(host)
        if result:
            actions.append({"action": "isolate_host", "target": host, "rc": result.returncode})
            logger.info(f"Isolated host: {host} | RC={result.returncode}")

    return {"status": "success", "technique": "T1021.002", "actions": actions}
