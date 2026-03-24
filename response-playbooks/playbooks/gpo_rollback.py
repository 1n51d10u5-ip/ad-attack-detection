#!/usr/bin/env python3
from elasticsearch import Elasticsearch
import subprocess
import datetime
import json

ES_HOST = "http://localhost:9200"
ES_USER = "elastic"
ES_PASS = "lolomomo"

DC_IP = "192.168.56.10"
WIN_USER = "Administrator"
WIN_PASS = "whiksey_ratpor666#"

def get_gpo_abuse_events():
    es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS))
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"event.code": "5136"}},
                    {"wildcard": {"winlog.event_data.ObjectDN": "*policies*"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "size": 10
    }
    
    result = es.search(index="winlogbeat-*", body=query)
    return result["hits"]["hits"]

def extract_gpo_name(alert):
    source = alert.get("_source", {})
    message = source.get("message", "")
    for line in message.split("\n"):
        if "Value:" in line:
            value = line.split("Value:")[-1].strip()
            if value and value != "-":
                return value
    return None

def rollback_gpo(gpo_name):
    try:
        result = subprocess.run([
            "sshpass", "-p", WIN_PASS,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{WIN_USER}@{DC_IP}",
            f"powershell -Command \"Remove-GPO -Name '{gpo_name}' -Confirm:$false\""
        ], capture_output=True, text=True, timeout=15)
        return result
    except subprocess.TimeoutExpired:
        return type('obj', (object,), {'returncode': 0, 'stdout': 'timeout', 'stderr': ''})

def log_action(gpo_name, result):
    timestamp = datetime.datetime.now().isoformat()
    log = {
        "timestamp": timestamp,
        "playbook": "gpo_rollback",
        "action": "remove_gpo",
        "gpo_name": gpo_name,
        "result": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }
    with open("/home/ishan/playbooks/playbook.log", "a") as f:
        f.write(json.dumps(log) + "\n")
    print(f"[{timestamp}] GPO '{gpo_name}' removed. RC={result.returncode}")

if __name__ == "__main__":
    print("Running GPO rollback playbook...")
    alerts = get_gpo_abuse_events()
    if not alerts:
        print("No GPO abuse events found.")
    
    seen_gpos = set()
    for alert in alerts:
        gpo_name = extract_gpo_name(alert)
        if gpo_name and gpo_name not in seen_gpos:
            seen_gpos.add(gpo_name)
            print(f"Removing GPO: {gpo_name}")
            result = rollback_gpo(gpo_name)
            log_action(gpo_name, result)



