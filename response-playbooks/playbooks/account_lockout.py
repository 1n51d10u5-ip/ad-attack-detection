#!/usr/bin/env python3
from elasticsearch import Elasticsearch
import subprocess
import datetime
import json

ES_HOST = "http://localhost:9200"
ES_USER = "elastic"
ES_PASS = "lolomomo"

def get_brute_force_targets():
    es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS))
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"event.code": "4625"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "aggs": {
            "targeted_users": {
                "terms": {
                    "field": "winlog.event_data.TargetUserName",
                    "min_doc_count": 5
                }
            }
        },
        "size": 0
    }
    
    result = es.search(index="winlogbeat-*", body=query)
    users = []
    for bucket in result["aggregations"]["targeted_users"]["buckets"]:
        users.append(bucket["key"])
    return users

def disable_account(username):
    ps_command = f"Disable-ADAccount -Identity {username}"
    result = subprocess.run([
        "sshpass", "-p", "whiksey_ratpor666#",
        "ssh", "-o", "StrictHostKeyChecking=no",
        "Administrator@192.168.56.10",
        f"powershell -Command \"{ps_command}\""
    ], capture_output=True, text=True)
    return result

def log_action(username, result):
    timestamp = datetime.datetime.now().isoformat()
    log = {
        "timestamp": timestamp,
        "playbook": "account_lockout",
        "action": "disable_account",
        "username": username,
        "result": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }
    with open("/home/ishan/playbooks/playbook.log", "a") as f:
        f.write(json.dumps(log) + "\n")
    print(f"[{timestamp}] Account {username} disabled. RC={result.returncode}")

if __name__ == "__main__":
    print("Running account lockout playbook...")
    targets = get_brute_force_targets()
    if not targets:
        print("No brute force targets found.")
    for user in targets:
        print(f"Disabling account: {user}")
        result = disable_account(user)
        log_action(user, result)


