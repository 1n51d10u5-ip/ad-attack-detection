#!/usr/bin/env python3
import os
from dotenv import load_dotenv

load_dotenv()

# Elasticsearch
ES_HOST = os.getenv("ES_HOST", "http://192.168.56.20:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "")

# Domain Controller
DC_IP   = os.getenv("DC_IP", "192.168.56.10")
DC_USER = os.getenv("DC_USER", "Administrator")
DC_PASS = os.getenv("DC_PASS", "")

# Workstation credentials
WIN_USER = os.getenv("WIN_USER", "Administrator")
WIN_PASS = os.getenv("WIN_PASS", "")

# Host IP mapping
HOST_IPS = {
    "DC01.lab.local":  DC_IP,
    "WS01.lab.local": os.getenv("WS01_IP", "192.168.56.11"),
    "WS02.lab.local": os.getenv("WS02_IP", "192.168.56.12"),
}

# Playbook settings
AUTO_RESPONSE = os.getenv("AUTO_RESPONSE", "true").lower() == "true"
DRY_RUN       = os.getenv("DRY_RUN", "false").lower() == "true"
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))
