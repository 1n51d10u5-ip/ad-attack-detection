#!/bin/bash
# Attack Simulation: AD Enumeration (Lightweight)
# MITRE ATT&CK: T1069.002

DC_IP="192.168.50.86"
DOMAIN="lab.local"
USERNAME="jsmith"
PASSWORD="Password123!"

echo "[*] Running AD user enumeration against $DOMAIN"

impacket-GetADUsers "${DOMAIN}/${USERNAME}:${PASSWORD}" \
-dc-ip $DC_IP \
-all

echo "[*] Enumeration complete - check Kibana for LDAP queries / 4624 events"
