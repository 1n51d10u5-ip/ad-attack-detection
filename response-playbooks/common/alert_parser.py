#!/usr/bin/env python3

TECHNIQUE_MAP = {
    "4769_0x17":     "T1558.003",  # Kerberoasting
    "4662_1131f6aa": "T1003.006",  # DCSync
    "10_lsass":      "T1003.001",  # LSASS Dump
    "4625":          "T1110",      # Brute Force
    "3_389":         "T1069",      # AD Enumeration
    "4624_ntlm_3":   "T1550.002",  # Pass-the-Hash
    "7045_systemroot":"T1021.002", # PSExec
    "7036_defender": "T1562.001",  # Defense Evasion
    "1102_104":      "T1070.001",  # Log Clearing
    "4768_preauth0": "T1558.004",  # AS-REP Roasting
    "4768_0x17":     "T1550.003",  # Pass-the-Ticket
    "4769_0x40810010":"T1558.001", # Golden Ticket
    "5136_policies": "T1484.001",  # GPO Abuse
}

def parse_alert(alert):
    source = alert.get("_source", alert)
    
    event_code = source.get("event", {}).get("code", "")
    winlog = source.get("winlog", {}).get("event_data", {})
    
    parsed = {
        "timestamp":    source.get("@timestamp", ""),
        "event_code":   event_code,
        "host":         source.get("host", {}).get("name", ""),
        "username":     winlog.get("TargetUserName", ""),
        "source_ip":    winlog.get("IpAddress", ""),
        "technique_id": _detect_technique(event_code, winlog),
        "raw":          source
    }
    
    return parsed

def _detect_technique(event_code, winlog):
    enc_type = winlog.get("TicketEncryptionType", "")
    logon_type = winlog.get("LogonType", "")
    auth_pkg = winlog.get("AuthenticationPackageName", "")
    target_image = winlog.get("TargetImage", "")
    properties = winlog.get("Properties", "")
    dest_port = winlog.get("DestinationPort", "")
    pre_auth = winlog.get("PreAuthType", "")
    ticket_opts = winlog.get("TicketOptions", "")
    object_dn = winlog.get("ObjectDN", "")
    param2 = winlog.get("param2", "")
    image_path = winlog.get("ImagePath", "")

    if event_code == "4769" and enc_type == "0x17":
        return "T1558.003"
    if event_code == "4662" and "1131f6aa" in properties:
        return "T1003.006"
    if event_code == "10" and "lsass" in target_image.lower():
        return "T1003.001"
    if event_code == "4625":
        return "T1110"
    if event_code == "3" and dest_port == "389":
        return "T1069"
    if event_code == "4624" and logon_type == "3" and auth_pkg == "NTLM":
        return "T1550.002"
    if event_code == "7045" and "%systemroot%" in image_path.lower():
        return "T1021.002"
    if event_code in ["7036"] and "stopped" in param2.lower():
        return "T1562.001"
    if event_code in ["1102", "104"]:
        return "T1070.001"
    if event_code == "4768" and pre_auth == "0":
        return "T1558.004"
    if event_code == "4768" and enc_type == "0x17":
        return "T1550.003"
    if event_code == "4769" and ticket_opts == "0x40810010":
        return "T1558.001"
    if event_code == "5136" and "policies" in object_dn.lower():
        return "T1484.001"
    
    return "UNKNOWN"
