Windows Persistance: 
Invoke-AtomicTest T1053.005 -TestNumbers 1

Linux Persistance:
Invoke-AtomicTest T1136.001


Windows:
powershell
Invoke-AtomicTest T1133
Invoke-AtomicTest T1059.001
Invoke-AtomicTest T1053.003
Invoke-AtomicTest T1548.002
Invoke-AtomicTest T1070.001
Invoke-AtomicTest T1083
Invoke-AtomicTest T1021.002
Invoke-AtomicTest T1115
Invoke-AtomicTest T1567
Invoke-AtomicTest T1486


Linux:
pwsh
Invoke-AtomicTest T1053.003 
Invoke-AtomicTest T1083
Invoke-AtomicTest T1115
Invoke-AtomicTest T1133
Invoke-AtomicTest T1486


Windows hardening -
secedit /export /cfg C:\secpol.cfg /quiet
Get-Content C:\secpol.cfg | Select-String "MinimumPasswordAge"
$content = Get-Content C:\secpol.cfg

if ($content -match 'MinimumPasswordAge = 0') {
    $content -replace 'MinimumPasswordAge = 0','MinimumPasswordAge = 1' | Set-Content C:\secpol.cfg
} else {
    $content -replace '\[System Access\]',"[System Access]`r`nMinimumPasswordAge = 1" | Set-Content C:\secpol.cfg
}
secedit /configure /db C:\windows\security\local.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY /quiet
secedit /export /cfg C:\secpol_verify.cfg /quiet
Get-Content C:\secpol_verify.cfg | Select-String "MinimumPasswordAge"
Restart-Service WazuhSvc
Start-Sleep -Seconds 5
Get-Service WazuhSvc



secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace 'MinimumPasswordLength = \d+','MinimumPasswordLength = 14' | Set-Content C:\secpol.cfg
secedit /configure /db C:\windows\security\local.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY
Get-Content C:\secpol_verify.cfg | Select-String "MinimumPasswordLength"
Restart-Service WazuhSvc
Start-Sleep -Seconds 5
Get-Service WazuhSvc




Linux Hardening - 
sudo grep "^PermitRootLogin" /etc/ssh/sshd_config
sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
sudo grep "^PermitRootLogin" /etc/ssh/sshd_config
sudo systemctl restart wazuh-agent


sudo grep "deny" /etc/security/faillock.conf
sudo sed -i 's/^\s*deny\s*=\s*.*/deny = 5/' /etc/security/faillock.conf
sudo grep -q "^deny" /etc/security/faillock.conf || echo "deny = 5" | sudo tee -a /etc/security/faillock.conf
sudo grep -Pl -- '\bpam_faillock\.so\h+([^#\n\r]+\h+)?deny\b' /usr/share/pam-configs/* 2>/dev/null
sudo grep "deny" /etc/security/faillock.conf
sudo systemctl restart wazuh-agent

