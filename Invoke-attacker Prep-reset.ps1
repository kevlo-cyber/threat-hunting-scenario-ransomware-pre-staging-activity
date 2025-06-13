<#
Restores compliance for the 10 STIG controls altered by Invoke‑AttackerPrep‑Misconfig.ps1.
Run from an elevated PowerShell session. Requires no interaction and suppresses
output so the remediation can be executed quietly before a Nessus re‑scan.
#>
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }
$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'
function EP($p){if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}}

# WN10-CC-000327 – enable PowerShell Transcription
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -Type DWord -Value 1 -Force

# WN10-SO-000245 – enable Admin Approval Mode for built‑in Administrator
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -Type DWord -Value 1 -Force

# WN10-SO-000250 – prompt administrators for consent on secure desktop
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2 -Force

# WN10-AU-000585 – enable command‑line process auditing failures
EP 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 1 -Force

# WN10-AU-000050 – audit Process Creation successes
AuditPol /set /subcategory:"Process Creation" /success:enable | Out-Null

# WN10-SO-000100 – require SMB client signing
EP 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Type DWord -Value 1 -Force

# WN10-SO-000120 – require SMB server signing
EP 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Type DWord -Value 1 -Force

# WN10-CC-000360 – disallow WinRM Digest authentication
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name AllowDigest -Type DWord -Value 0 -Force

# WN10-CC-000335 – disallow unencrypted WinRM traffic
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name AllowUnencryptedTraffic -Type DWord -Value 0 -Force

# WN10-SO-000230 – enable FIPS compliant algorithms
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name FIPSAlgorithmPolicy -Type DWord -Value 1 -Force

# (Optional) set ConsentPromptBehaviorUser to 3 to fully restore secure desktop for standard users
# Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Type DWord -Value 3 -Force

# Complete – reboot recommended for SMB & FIPS changes
