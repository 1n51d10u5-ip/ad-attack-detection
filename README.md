# Adversary-Informed Active Directory Attack Detection and Automated Incident Response

A MITRE ATT&CK aligned detection and response framework for Active Directory environments, built using open-source tools.

## Project Overview

This project implements a homelab-based Active Directory environment to simulate, detect, and automatically respond to common AD attack techniques. It combines Elastic Stack (SIEM), Sysmon, Winlogbeat, and custom Python playbooks to create an end-to-end detection and response pipeline.

**Formal Title:** Adversary-Informed Active Directory Attack Detection and Automated Incident Response: A MITRE ATT&CK Aligned Framework Using Open-Source Tools

## Lab Architecture
```
╔══════════════════════════════════════════════════════════════════════╗
║                       AD HOMELAB — lab.local                         ║
║                    VirtualBox · 192.168.56.0/24                      ║
║                                                                      ║
║  ┌─────────────────────────────────────────┐                         ║
║  │             Windows Domain              │                         ║
║  │                                         │                         ║
║  │  ┌──────────────────┐                   │   ┌──────────────────┐  ║
║  │  │       DC01       │                   │   │      SIEM        │  ║
║  │  │                  │ ─── logs ──────────── │                  │  ║
║  │  │  Win Server 2022 │                   │   │  Ubuntu 22.04    │  ║
║  │  │ [AD DS] · Sysmon │                   │   │  Elasticsearch   │  ║
║  │  └──────────────────┘                   │   │     Kibana       │  ║
║  │                                         │   │  Detection Rules │  ║
║  │  ┌──────────────────┐                   │   │    Playbooks     │  ║
║  │  │       WS01       │ ─── logs ──────────── │                  │  ║
║  │  │                  │                   │   └──────────────────┘  ║
║  │  │    Windows 10    │                   │            │            ║
║  │  │      Sysmon      │                   │        response         ║
║  │  └──────────────────┘                   │            │            ║
║  │                                         │            ▼            ║
║  │  ┌──────────────────┐                   │   ┌──────────────────┐  ║
║  │  │       WS02       │ ─── logs ──────────── │    Kali Linux    │  ║
║  │  │                  │                   │   │                  │  ║
║  │  │    Windows 10    │◄──── attacks ─────────│     OS X Host    │  ║
║  │  │      Sysmon      │                   │   │  Impacket · CME  │  ║
║  │  └──────────────────┘                   │   │    BloodHound    │  ║
║  │                                         │   └──────────────────┘  ║
║  └─────────────────────────────────────────┘                         ║
╚══════════════════════════════════════════════════════════════════════╝
```

## Detection Coverage

| Technique | ID | Detection Method | Event IDs |
|---|---|---|---|
| Kerberoasting | T1558.003 | RC4 TGS request | 4769 |
| DCSync | T1003.006 | Replication rights abuse | 4662 |
| LSASS Dump | T1003.001 | Process access to lsass.exe | Sysmon 10 |
| Brute Force | T1110 | Multiple failed logons | 4625 |
| AD Enumeration | T1069 | LDAP reconnaissance | Sysmon 3 |
| Pass-the-Hash | T1550.002 | NTLM network logon | 4624 |
| PSExec Lateral Movement | T1021.002 | Random service installation | 7045 |
| Defense Evasion | T1562.001 | Defender service stopped | 7036 |
| Log Clearing | T1070.001 | Event log cleared | 1102, 104 |
| AS-REP Roasting | T1558.004 | Pre-auth disabled request | 4768 |
| Pass-the-Ticket | T1550.003 | RC4 TGT request | 4768 |
| Golden Ticket | T1558.001 | Forged TGT ticket options | 4769 |
| GPO Abuse | T1484.001 | Group Policy modification | 5136 |

## Automated Response Playbooks

| Playbook | Trigger | Actions |
|---|---|---|
| Account Lockout | Brute Force (T1110) | Disable targeted AD account |
| Host Isolation | LSASS Dump (T1003.001) | Disable network adapters |
| Alert Enrichment | All techniques | Pull user/group info from AD |
| GPO Rollback | GPO Abuse (T1484.001) | Remove malicious GPO |

## Repository Structure
```
ad-attack-detection/
├── detections/              # Kibana detection rule configs
├── sigma-rules/             # Sigma format detection rules
├── response-playbooks/
│   ├── common/              # Shared utilities
│   ├── playbooks/           # Individual response playbooks
│   ├── orchestrator.py      # Alert routing engine
│   └── config.py            # Configuration
├── attack-simulation/
│   └── techniques/          # Attack simulation scripts
└── docs/                    # Setup guides and documentation
```

## Tech Stack

- **SIEM:** Elastic Stack 8.x (Elasticsearch + Kibana)
- **Log Shipping:** Winlogbeat 8.x
- **Endpoint Monitoring:** Sysmon with SwiftOnSecurity config
- **Attack Tools:** Impacket, CrackMapExec, BloodHound
- **Response Automation:** Python 3, Flask, paramiko
- **Detection Format:** KQL (Kibana), Sigma

## Setup

See [docs/setup-guide.md](docs/setup-guide.md) for full lab setup instructions.

## Results

- **13 MITRE ATT&CK techniques** detected
- **4 automated response playbooks** implemented
- **Mean Time to Detect (MTTD):** < 5 minutes
- **Mean Time to Respond (MTTR):** < 2 minutes

## Author

Ishan Panchal — M.Eng Computer Engineering, Virginia Tech  
Project, May 2026