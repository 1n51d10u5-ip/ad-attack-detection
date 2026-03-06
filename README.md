# Active Directory Attack Detection & Automated Response Framework

A MITRE ATT&CK-aligned detection and automated incident response framework targeting 12 Active Directory attack techniques. Built as a Master of Engineering capstone project at Virginia Tech, this framework demonstrates enterprise-grade AD security monitoring using entirely open-source tooling.

---

## Overview

Active Directory is implicated in the majority of enterprise breaches, yet most organizations lack systematic, measurable detection coverage for documented AD attack techniques. This project addresses that gap by:

- Simulating 12 real-world AD attack techniques in a virtualized lab environment
- Engineering custom detection rules in Elastic Stack mapped explicitly to MITRE ATT&CK technique IDs
- Implementing automated Python and PowerShell response playbooks for threat containment

**Performance Targets:**
| Metric | Target |
|---|---|
| Detection Rate | > 90% |
| False Positive Rate | < 5% |
| Time-to-Detect (TTD) | < 60 seconds |
| Mean Time to Respond (MTTR) | < 3 minutes |

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│                  VirtualBox Network                  │
│                                                     │
│  ┌─────────────┐        ┌─────────────────────────┐ │
│  │   DC01      │        │       WS01 / WS02       │ │
│  │  (Domain    │◄──────►│    (Windows 11 Clients) │ │
│  │Controller)  │        │                         │ │
│  └──────┬──────┘        └───────────┬─────────────┘ │
│         │                           │               │
│         ▼                           ▼               │
│  ┌─────────────────────────────────────────────┐    │
│  │            Elastic Stack (SIEM)             │    │
│  │   Winlogbeat + Sysmon → Logstash → Elastic  │    │
│  │              Kibana Dashboards              │    │
│  └─────────────────────────────────────────────┘    │
│                                                     │
│  ┌─────────────┐                                    │
│  │  Kali Linux │  (Attack simulation)               │
│  │  (Attacker) │                                    │
│  └─────────────┘                                    │
└─────────────────────────────────────────────────────┘
```

**Host Machines:**
- Mac M1 — runs Kali Linux VM (attacker)
- Intel i7 Windows 11 — runs DC01, WS01 (AD domain)
- Elastic Stack — log ingestion and detection

---

## MITRE ATT&CK Coverage

| # | Technique | ATT&CK ID | Tactic |
|---|---|---|---|
| 1 | Kerberoasting | T1558.003 | Credential Access |
| 2 | AS-REP Roasting | T1558.004 | Credential Access |
| 3 | DCSync | T1003.006 | Credential Access |
| 4 | Pass-the-Hash | T1550.002 | Lateral Movement |
| 5 | Pass-the-Ticket | T1550.003 | Lateral Movement |
| 6 | Golden Ticket Forgery | T1558.001 | Credential Access |
| 7 | Silver Ticket Forgery | T1558.002 | Credential Access |
| 8 | BloodHound Enumeration | T1069.002 | Discovery |
| 9 | LDAP Reconnaissance | T1018 | Discovery |
| 10 | Remote Service Execution (PsExec) | T1569.002 | Execution |
| 11 | Scheduled Task Persistence | T1053.005 | Persistence |
| 12 | LSASS Memory Dumping | T1003.001 | Credential Access |

---

## Tech Stack

| Category | Tools |
|---|---|
| Virtualization | VirtualBox |
| AD Environment | Windows Server 2022, Windows 11 |
| Telemetry | Sysmon, Winlogbeat, Filebeat |
| SIEM | Elastic Stack (Elasticsearch, Logstash, Kibana) |
| Detection | KQL (Kibana Query Language) |
| Attack Simulation | Mimikatz, Rubeus, Impacket, BloodHound, CrackMapExec |
| Response Automation | Python, PowerShell |
| Attacker OS | Kali Linux |

---

## Repository Structure

```
ad-attack-detection/
├── detection-rules/        # KQL detection rules mapped to ATT&CK IDs
│   ├── credential-access/
│   ├── lateral-movement/
│   ├── persistence/
│   └── discovery/
├── playbooks/              # Automated response scripts
│   ├── python/
│   └── powershell/
├── lab-setup/              # Environment configuration guides
│   ├── ad-setup.md
│   ├── elastic-setup.md
│   └── sysmon-config.xml
└── README.md
```

---

## Detection Rules

Each rule in `detection-rules/` follows this structure:

```
technique-name/
├── rule.kql          # KQL query for Kibana alert
├── description.md    # What the rule detects and why
└── test-case.md      # How to trigger and validate the rule
```

Example — Kerberoasting detection (T1558.003):
```kql
event.code: "4769" and
winlog.event_data.TicketEncryptionType: "0x17" and
winlog.event_data.ServiceName: (* and not $krbtgt)
```

---

## Response Playbooks

Automated playbooks in `playbooks/` trigger on Elastic alerts and execute containment actions:

- **Account isolation** — disable compromised AD accounts via PowerShell
- **Host quarantine** — block lateral movement by isolating affected workstations
- **Ticket invalidation** — force Kerberos ticket expiry on affected accounts
- **Alert enrichment** — auto-enrich alerts with AD context before escalation

---

## Status

🔄 **In Progress** — Active development, February 2026 – May 2026

- [x] Lab architecture designed and deployed
- [x] Sysmon + Winlogbeat telemetry pipeline validated
- [ ] Detection rules — 4/12 complete
- [ ] Response playbooks — in development
- [ ] Final evaluation and metrics

---

## Author

**Ishan Panchal**
M.Eng. Computer Engineering, Virginia Tech
[linkedin.com/in/panchalishan](https://linkedin.com/in/panchalishan)

---

## Acknowledgments

Aligned with the Five Eyes intelligence advisory on Active Directory compromise and MITRE ATT&CK Enterprise framework v14.
