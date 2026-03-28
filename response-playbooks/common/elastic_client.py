#!/usr/bin/env python3
from elasticsearch import Elasticsearch
from datetime import datetime
import config

def get_es_client():
    return Elasticsearch(
        config.ES_HOST,
        basic_auth=(config.ES_USER, config.ES_PASS)
    )

def get_recent_alerts(technique_id=None, minutes=5):
    es = get_es_client()
    
    technique_queries = {
        "T1558.003": {"bool": {"must": [{"term": {"event.code": "4769"}}, {"term": {"winlog.event_data.TicketEncryptionType": "0x17"}}]}},
        "T1003.006": {"bool": {"must": [{"term": {"event.code": "4662"}}, {"wildcard": {"winlog.event_data.Properties": "*1131f6aa*"}}]}},
        "T1003.001": {"bool": {"must": [{"term": {"event.code": "10"}}, {"wildcard": {"winlog.event_data.TargetImage": "*lsass*"}}], "must_not": [{"wildcard": {"winlog.event_data.SourceImage": "*system32*"}}, {"wildcard": {"winlog.event_data.SourceImage": "*System32*"}}, {"wildcard": {"winlog.event_data.SourceImage": "*VBoxService*"}}, {"wildcard": {"winlog.event_data.SourceImage": "*Sysmon*"}}, {"wildcard": {"winlog.event_data.SourceImage": "*MsMpEng*"}}, {"wildcard": {"winlog.event_data.SourceImage": "*Edge*"}}]}},
        "T1110":     {"bool": {"must": [{"term": {"event.code": "4625"}}], "minimum_should_match": 1, "should": []}},
        "T1069":     {"bool": {"must": [{"term": {"event.code": "3"}}, {"term": {"winlog.event_data.DestinationPort": "389"}}]}},
        "T1550.002": {"bool": {"must": [{"term": {"event.code": "4624"}}, {"term": {"winlog.event_data.LogonType": "3"}}, {"term": {"winlog.event_data.AuthenticationPackageName": "NTLM"}}]}},
        "T1021.002": {"bool": {"must": [{"term": {"event.code": "7045"}}, {"wildcard": {"winlog.event_data.ImagePath": "*%systemroot%*"}}]}},
        "T1562.001": {"bool": {"must": [{"term": {"event.code": "7036"}}, {"term": {"winlog.event_data.param2": "stopped"}}]}},
        "T1070.001": {"bool": {"should": [{"term": {"event.code": "1102"}}, {"term": {"event.code": "104"}}]}},
        "T1558.004": {"bool": {"must": [{"term": {"event.code": "4768"}}, {"term": {"winlog.event_data.PreAuthType": "0"}}]}},
        "T1550.003": {"bool": {"must": [{"term": {"event.code": "4768"}}, {"term": {"winlog.event_data.TicketEncryptionType": "0x17"}}]}},
        "T1558.001": {"bool": {"must": [{"term": {"event.code": "4769"}}, {"term": {"winlog.event_data.TicketOptions": "0x40810010"}}]}},
        "T1484.001": {"bool": {"must": [{"term": {"event.code": "5136"}}, {"wildcard": {"winlog.event_data.ObjectDN": "*policies*"}}]}},
    }

    if technique_id and technique_id in technique_queries:
        base_query = technique_queries[technique_id]
    else:
        base_query = {"match_all": {}}

    query = {
        "query": {
            "bool": {
                "must": [
                    base_query,
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}
                ]
            }
        },
        "sort": [{"@timestamp": "desc"}],
        "size": 100
    }

    result = es.search(index="winlogbeat-*", body=query)
    return result["hits"]["hits"]

def get_alert_by_id(alert_id):
    es = get_es_client()
    result = es.get(index="winlogbeat-*", id=alert_id)
    return result["_source"]
