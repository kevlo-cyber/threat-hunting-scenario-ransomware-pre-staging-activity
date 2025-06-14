<#
Restores compliance for **9** STIG controls (all except WN10‑AU‑000585) altered by
Invoke‑AttackerPrep‑Misconfig.ps1.  Runs silently from an elevated PowerShell
session, suppresses output, then forces an immediate reboot so SMB, WinRM, UAC,
and FIPS settings are fully applied before the next Nessus scan.
#>
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }
$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'
function EP($p){ if(!(Test-Path $p)){ New-Item -Path $p -Force | Out-Null } }

# --- 1. PowerShell Transcription (WN10‑CC‑000327) ---------------------------
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -Type DWord -Value 1 -Force

# --- 2. Built‑in Administrator UAC (WN10‑SO‑000245) -------------------------
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -Type DWord -Value 1 -Force

# --- 3. Secure‑desktop prompt for admins (WN10‑SO‑000250) -------------------
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2 -Force

# --- 4. Audit Process Creation successes (WN10‑AU‑000050) -------------------
AuditPol /set /subcategory:"Process Creation" /success:enable | Out-Null

# --- 5. SMB client signing (WN10‑SO‑000100) --------------------------------
EP 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Type DWord -Value 1 -Force

# --- 6. SMB server signing (WN10‑SO‑000120) --------------------------------
EP 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Type DWord -Value 1 -Force

# --- 7. WinRM: disallow Digest (WN10‑CC‑000360) -----------------------------
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name AllowDigest -Type DWord -Value 0 -Force

# --- 8. WinRM: require encryption (WN10‑CC‑000335) --------------------------
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'   -Name AllowUnencryptedTraffic -Type DWord -Value 0 -Force
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowUnencryptedTraffic -Type DWord -Value 0 -Force

# --- 9. Enable FIPS algorithms (WN10‑SO‑000230) -----------------------------
EP 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name Enabled -Type DWord -Value 1 -Force

# --- Force immediate reboot -------------------------------------------------
shutdown.exe /r /t 0 /c "STIG compliance reset (9 controls) – rebooting"
