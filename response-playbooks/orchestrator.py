#!/usr/bin/env python3
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify
from common.elastic_client import get_recent_alerts
from common.alert_parser import parse_alert
from common.logger import setup_logger
import config

from playbooks.kerberoasting_response import respond as kerberoasting_respond
from playbooks.dcsync_response import respond as dcsync_respond
from playbooks.lsass_dump_response import respond as lsass_respond
from playbooks.brute_force_response import respond as bruteforce_respond
from playbooks.pass_the_hash_response import respond as pth_respond
from playbooks.pass_the_ticket_response import respond as ptt_respond
from playbooks.golden_ticket_response import respond as golden_ticket_respond
from playbooks.psexec_response import respond as psexec_respond
from playbooks.asrep_roasting_response import respond as asrep_respond
from playbooks.defense_evasion_response import respond as defense_evasion_respond
from playbooks.log_clearing_response import respond as log_clearing_respond
from playbooks.gpo_abuse_response import respond as gpo_respond

logger = setup_logger("orchestrator")

TECHNIQUE_HANDLERS = {
    "T1558.003": kerberoasting_respond,
    "T1003.006": dcsync_respond,
    "T1003.001": lsass_respond,
    "T1110":     bruteforce_respond,
    "T1550.002": pth_respond,
    "T1550.003": ptt_respond,
    "T1558.001": golden_ticket_respond,
    "T1021.002": psexec_respond,
    "T1558.004": asrep_respond,
    "T1562.001": defense_evasion_respond,
    "T1070.001": log_clearing_respond,
    "T1484.001": gpo_respond,
}

ISOLATION_TECHNIQUES = {"T1003.001", "T1021.002"}

app = Flask(__name__)

def process_alert(alert, responded_hosts=None):
    parsed = parse_alert(alert)
    technique_id = parsed.get("technique_id", "UNKNOWN")
    host = parsed.get("host", "")

    logger.info(f"Processing alert | technique={technique_id} | host={host} | user={parsed['username']}")

    if technique_id == "UNKNOWN":
        return {"status": "skipped", "reason": "unknown technique"}

    handler = TECHNIQUE_HANDLERS.get(technique_id)
    if not handler:
        return {"status": "skipped", "reason": "no handler"}

    # Per-host cooldown for isolation-type responses
    if responded_hosts is not None and technique_id in ISOLATION_TECHNIQUES:
        if host in responded_hosts:
            logger.info(f"Host {host} already responded to, skipping")
            return {"status": "skipped", "reason": "already_responded"}
        responded_hosts.add(host)

    if config.DRY_RUN:
        logger.info(f"DRY RUN - would execute {technique_id} response for {parsed['username']}")
        return {"status": "dry_run", "technique": technique_id}

    result = handler(parsed)
    logger.info(f"Response complete | technique={technique_id} | result={result}")
    return result

@app.route('/alert', methods=['POST'])
def webhook_handler():
    alerts = request.json
    if isinstance(alerts, list):
        results = [process_alert(a) for a in alerts]
    else:
        results = [process_alert(alerts)]
    return jsonify({"processed": len(results), "results": results})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

def polling_mode():
    logger.info("Starting orchestrator in polling mode...")
    seen_ids = set()
    responded_hosts = set()

    while True:
        try:
            for technique_id in TECHNIQUE_HANDLERS.keys():
                alerts = get_recent_alerts(technique_id=technique_id, minutes=2)
                for alert in alerts:
                    alert_id = alert.get("_id")
                    if not alert_id:
                        continue
                    if alert_id in seen_ids:
                        continue
                    seen_ids.add(alert_id)
                    process_alert(alert, responded_hosts)
        except Exception as e:
            logger.error(f"Polling error: {e}")

        time.sleep(config.POLL_INTERVAL)

if __name__ == "__main__":
    if "--webhook" in sys.argv:
        logger.info("Starting orchestrator in webhook mode on port 5000...")
        app.run(host="0.0.0.0", port=5000)
    else:
        polling_mode()
