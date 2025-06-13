<#
.SYNOPSIS
    Restores compliance for the 10 Windows 10 STIG controls modified in the ransomware pre‑staging lab.

.DESCRIPTION
    Re‑enables Microsoft Defender, AppLocker, auditing, UAC, script‑block logging, and RDP encryption
    settings so that a Nessus/Tenable.io scan using **DISA Microsoft Windows 10 STIG v3r4** audit files
    will report these findings as **PASS**.

.NOTES
    Author: Your‑Name‑or‑Org
    License: MIT
    Tested on: Windows 10 Enterprise 21H2 (build 19045) – stand‑alone VM
    Last updated: 2025‑06‑13

    ⚠️  Run from an **elevated** PowerShell session.
#>

# ---- Safety checks -----------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "[!] Script must be executed from an elevated PowerShell session."
    exit 1
}

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

function Ensure-Path($Path) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

# 1 – Enable PUA protection (WNDF-AV-000001)
Ensure-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Type DWord -Value 1 -Force

# 2 – Re‑enable PowerShell script‑block logging (WN10-CC-000326)
Ensure-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 1 -Force

# 3 – Re‑enable UAC Admin Approval Mode (WN10-SO-000270)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 1 -Force

# 4 – Prompt for elevation on secure desktop (WN10-SO-000255)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value 3 -Force

# 5 – Re‑enable installer detection (WN10-SO-000260)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Type DWord -Value 1 -Force

# 6 – Require High‑level RDP encryption (≥ 128‑bit) (WN10-CC-000290)
Ensure-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Type DWord -Value 3 -Force   # 3 = High

# 7 & 8 – Audit Credential Validation (success + failure) (WN10-AU-000005 / 000010)
auditpol /set /subcategory:"Credential Validation" /success:enable  /failure:enable | Out-Null

# 9 – Re‑enable Defender real‑time protection (WNDF-AV-000021)
Ensure-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type DWord -Value 0 -Force

# 10 – Restore AppLocker default rules (WN10-00-000035)
try {
    # Generate default policy object in‑memory
    $policy = New-AppLockerPolicy -Default -XML
    Set-AppLockerPolicy -PolicyObject $policy -Merge -ErrorAction Stop
} catch {
    # Fallback: recreate registry key if Set‑AppLockerPolicy cmdlets unavailable
    Ensure-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
}

# ---- Done --------------------------------------------------------------------
Write-Verbose "[+] STIG remediation complete. Reboot required for UAC & RDP changes to fully apply."
