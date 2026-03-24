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

def get_recent_alerts():
    es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS))
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"terms": {"event.code": ["4625", "4769", "4662", "10", "7045"]}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "aggs": {
            "usernames": {
                "terms": {
                    "field": "winlog.event_data.TargetUserName",
                    "min_doc_count": 1
                }
            }
        },
        "size": 0
    }
    
    result = es.search(index="winlogbeat-*", body=query)
    users = []
    for bucket in result["aggregations"]["usernames"]["buckets"]:
        username = bucket["key"]
        if username and username != "-" and "$" not in username:
            users.append(username)
    return users

def enrich_user(username):
    try:
        result = subprocess.run([
            "sshpass", "-p", WIN_PASS,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{WIN_USER}@{DC_IP}",
            f"powershell C:\\enrich_user.ps1 -username {username}"
        ], capture_output=True, text=True, timeout=15)
        return result.stdout if result.stdout else result.stderr
    except subprocess.TimeoutExpired:
        return "Enrichment timed out"


def log_enrichment(username, enrichment):
    timestamp = datetime.datetime.now().isoformat()
    log = {
        "timestamp": timestamp,
        "playbook": "alert_enrichment",
        "username": username,
        "enrichment": enrichment
    }
    with open("/home/ishan/playbooks/playbook.log", "a") as f:
        f.write(json.dumps(log) + "\n")
    print(f"\n[{timestamp}] Enrichment for {username}:")
    print(enrichment)

if __name__ == "__main__":
    print("Running alert enrichment playbook...")
    users = get_recent_alerts()
    if not users:
        print("No recent alerts found.")
    for user in users:
        print(f"Enriching user: {user}")
        enrichment = enrich_user(user)
        log_enrichment(user, enrichment)

