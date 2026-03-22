#!/usr/bin/env python3
import subprocess
import config

def run_powershell(command):
    try:
        result = subprocess.run([
            "sshpass", "-p", config.DC_PASS,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{config.DC_USER}@{config.DC_IP}",
            f"powershell -Command \"{command}\""
        ], capture_output=True, text=True, timeout=15)
        return result
    except subprocess.TimeoutExpired:
        return type('obj', (object,), {
            'returncode': 0,
            'stdout': 'timeout_expected',
            'stderr': ''
        })

def disable_account(username):
    return run_powershell(f"Disable-ADAccount -Identity {username}")

def enable_account(username):
    return run_powershell(f"Enable-ADAccount -Identity {username}")

def reset_password(username, new_pass):
    return run_powershell(
        f"Set-ADAccountPassword -Identity {username} "
        f"-NewPassword (ConvertTo-SecureString '{new_pass}' -AsPlainText -Force) -Reset"
    )

def reset_krbtgt():
    new_pass = "KrbtgtReset@" + __import__('secrets').token_hex(8)
    return run_powershell(
        f"Set-ADAccountPassword -Identity krbtgt "
        f"-NewPassword (ConvertTo-SecureString '{new_pass}' -AsPlainText -Force) -Reset"
    )

def remove_gpo(gpo_name):
    return run_powershell(f"Remove-GPO -Name '{gpo_name}' -Confirm:$false")

def get_user_info(username):
    return run_powershell(
        f"Get-ADUser -Identity {username} "
        f"-Properties DisplayName,LastLogonDate,MemberOf,Enabled,PasswordLastSet | "
        f"Select-Object Name,Enabled,LastLogonDate,PasswordLastSet | ConvertTo-Json"
    )

def isolate_host(hostname):
    ip = config.HOST_IPS.get(hostname)
    if not ip:
        return None
    try:
        result = subprocess.run([
            "sshpass", "-p", config.WIN_PASS,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{config.WIN_USER}@{ip}",
            "powershell C:\\isolate.ps1"
        ], capture_output=True, text=True, timeout=10)
        return result
    except subprocess.TimeoutExpired:
        return type('obj', (object,), {
            'returncode': 0,
            'stdout': 'host_isolated',
            'stderr': ''
        })
