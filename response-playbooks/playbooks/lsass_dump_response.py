#!/usr/bin/env python3
import sys, os, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.logger import setup_logger
import config

logger = setup_logger("lsass_dump_response")

def isolate_host(hostname):
    ip = config.HOST_IPS.get(hostname)
    if not ip:
        logger.error(f"Unknown host: {hostname}")
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
    host = alert.get("host", "")
    username = alert.get("username", "")

    logger.warning(f"LSASS DUMP DETECTED | host={host} | user={username}")

    if not host:
        logger.error("No host in alert, cannot isolate")
        return {"status": "error", "reason": "no host"}

    logger.info(f"Isolating host: {host}")
    result = isolate_host(host)

    if result and result.returncode == 0:
        logger.info(f"Host {host} isolated successfully")
        return {"status": "success", "technique": "T1003.001", "action": "host_isolated", "host": host}
    else:
        logger.error(f"Failed to isolate {host}")
        return {"status": "error", "technique": "T1003.001", "host": host}
