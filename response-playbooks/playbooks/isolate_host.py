#!/usr/bin/env python3
from elasticsearch import Elasticsearch
import subprocess
import datetime
import json

ES_HOST = "http://localhost:9200"
ES_USER = "elastic"
ES_PASS = "lolomomo"

HOST_IPS = {
    "WS01.lab.local": "192.168.56.11",
    "WS02.lab.local": "192.168.56.12",
    "DC01.lab.local": "192.168.56.10"
}

WIN_USER = "Administrator"
WIN_PASS = "whiksey_ratpor666#"

def get_lsass_hosts():
    es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS))
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"event.code": "10"}},
                    {"wildcard": {"winlog.event_data.TargetImage": "*lsass*"}},
                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "aggs": {
            "affected_hosts": {
                "terms": {
                    "field": "host.name",
                    "min_doc_count": 1
                }
            }
        },
        "size": 0
    }
    
    result = es.search(index="winlogbeat-*", body=query)
    hosts = []
    for bucket in result["aggregations"]["affected_hosts"]["buckets"]:
        hosts.append(bucket["key"])
    return hosts

def isolate_host(hostname):
    ip = HOST_IPS.get(hostname)
    if not ip:
        print(f"Unknown host: {hostname}")
        return None
    
    ps_command = "powershell C:\\isolate.ps1"
    
    try:
        result = subprocess.run([
            "sshpass", "-p", WIN_PASS,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{WIN_USER}@{ip}",
            ps_command
        ], capture_output=True, text=True, timeout=10)
        return result
    except subprocess.TimeoutExpired:
        print(f"[+] Host {hostname} isolated (connection dropped as expected)")
        return type('obj', (object,), {'returncode': 0, 'stdout': 'timeout_expected', 'stderr': ''})

def log_action(hostname, result):
    timestamp = datetime.datetime.now().isoformat()
    log = {
        "timestamp": timestamp,
        "playbook": "isolate_host",
        "action": "block_network",
        "hostname": hostname,
        "result": result.returncode if result else -1,
        "stdout": result.stdout if result else "",
        "stderr": result.stderr if result else ""
    }
    with open("/home/ishan/playbooks/playbook.log", "a") as f:
        f.write(json.dumps(log) + "\n")
    print(f"[{timestamp}] Host {hostname} isolated. RC={result.returncode if result else -1}")

if __name__ == "__main__":
    print("Running host isolation playbook...")
    hosts = get_lsass_hosts()
    if not hosts:
        print("No LSASS access detected.")
    for host in hosts:
        print(f"Isolating host: {host}")
        result = isolate_host(host)
        log_action(host, result)

