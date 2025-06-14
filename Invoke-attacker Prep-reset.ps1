<#
Invoke‑AttackerPrep‑Reset.ps1
Restores **9** STIG controls to compliance after the attacker‑prep simulation.
Controls: WN10‑CC‑000327, WN10‑SO‑000245, WN10‑SO‑000250, WN10‑AU‑000050,
          WN10‑SO‑000100, WN10‑SO‑000120, WN10‑CC‑000360, WN10‑CC‑000335, WN10‑SO‑000230
The script runs silently from an elevated PowerShell session and forces an
immediate reboot when changes are applied.
#>
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }
$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'
function EP($p){ if(!(Test-Path $p)){ New-Item -Path $p -Force | Out-Null } }

# 1. Enable PowerShell Transcription (WN10‑CC‑000327)
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -Type DWord -Value 1 -Force

# 2. Enable Admin Approval Mode for built‑in Administrator (WN10‑SO‑000245)
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -Type DWord -Value 1 -Force

# 3. Prompt administrators on secure desktop (WN10‑SO‑000250)
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2 -Force

# 4. Audit Process Creation successes (WN10‑AU‑000050)
AuditPol /set /subcategory:"Process Creation" /success:enable | Out-Null

# 5. Require SMB client signing (WN10‑SO‑000100)
EP 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Type DWord -Value 1 -Force

# 6. Require SMB server signing (WN10‑SO‑000120)
EP 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Type DWord -Value 1 -Force

# 7. Disallow WinRM Digest authentication (WN10‑CC‑000360)
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name AllowDigest -Type DWord -Value 0 -Force

# 8. Disallow unencrypted WinRM traffic (WN10‑CC‑000335)
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'   -Name AllowUnencryptedTraffic -Type DWord -Value 0 -Force
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowUnencryptedTraffic -Type DWord -Value 0 -Force

# 9. Enable FIPS compliant algorithms (WN10‑SO‑000230)
EP 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name Enabled -Type DWord -Value 1 -Force

# Reboot immediately to apply UAC, SMB, WinRM and FIPS changes
shutdown.exe /r /t 0 /c "STIG compliance reset (9 controls) – rebooting"
