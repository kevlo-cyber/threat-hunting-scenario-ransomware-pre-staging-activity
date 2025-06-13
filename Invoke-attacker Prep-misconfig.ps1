# Purpose‑built script: forces 10 specific Windows 10 STIG controls into a non‑compliant state
# Runs silently; require elevated PowerShell

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }
$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'

function EP($p){if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}}

# WN10‑CC‑000327 – disable PowerShell Transcription
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -Type DWord -Value 0 -Force

# WN10‑SO‑000245 – disable Admin Approval Mode for built‑in Administrator
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -Type DWord -Value 0 -Force

# WN10‑SO‑000250 – remove secure‑desktop consent prompt for admins
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 0 -Force

# WN10‑AU‑000585 – disable command‑line process auditing failures
EP 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 0 -Force

# WN10‑AU‑000050 – stop auditing Process Creation successes
AuditPol /set /subcategory:"Process Creation" /success:disable | Out-Null

# WN10‑SO‑000100 – turn off SMB client signing requirement
EP 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Type DWord -Value 0 -Force

# WN10‑SO‑000120 – turn off SMB server signing requirement
EP 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Type DWord -Value 0 -Force

# WN10‑CC‑000360 – allow WinRM Digest auth
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name AllowDigest -Type DWord -Value 1 -Force

# WN10‑CC‑000335 – allow unencrypted WinRM traffic
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name AllowUnencryptedTraffic -Type DWord -Value 1 -Force

# WN10‑SO‑000230 – disable FIPS mode
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name FIPSAlgorithmPolicy -Type DWord -Value 0 -Force
