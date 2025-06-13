<#
.SYNOPSIS
    Purposely misconfigures 10 Windows 10 STIG controls for ransomware pre‑staging lab scenarios.

.DESCRIPTION
    Executes registry and audit‑policy changes that weaken host defenses. Designed for a single
    stand‑alone Windows 10 Enterprise VM onboarded to Microsoft Defender for Endpoint.
    Run **once** with administrative privileges. Requires no user interaction.

.NOTES
    Author: Your‑Name‑or‑Org
    License: MIT
    Last updated: 2025‑06‑13
#>

# ---- Safety checks -----------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "[!] Script must be executed from an elevated PowerShell session."
    exit 1
}

$ErrorActionPreference = "SilentlyContinue"   # Suppress non‑critical errors
$ProgressPreference    = "SilentlyContinue"   # Hide progress bars

# Helper: Ensure a registry path exists
function Ensure-Path($Path) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

# 1 – Disable PUA protection (WNDF‑AV‑000001)
Ensure-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Type DWord -Value 0 -Force

# 2 – Disable PowerShell script‑block logging (WN10‑CC‑000326)
Ensure-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 0 -Force

# 3 – Disable UAC Admin Approval Mode (WN10‑SO‑000270)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 0 -Force

# 4 – Auto‑deny elevation prompts (WN10‑SO‑000255)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value 0 -Force

# 5 – Disable installer detection (WN10‑SO‑000260)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Type DWord -Value 0 -Force

# 6 – Weaken RDP encryption (WN10‑CC‑000290)
Ensure-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Type DWord -Value 1 -Force

# 7 – Stop auditing Credential Validation failures (WN10‑AU‑000005)
auditpol /set /subcategory:"Credential Validation" /failure:disable | Out-Null

# 8 – Stop auditing Credential Validation success (WN10‑AU‑000010)
auditpol /set /subcategory:"Credential Validation" /success:disable | Out-Null

# 9 – Disable Defender real‑time protection (WNDF‑AV‑000021)
Ensure-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type DWord -Value 1 -Force

# 10 – Remove AppLocker policies (WN10‑00‑000035)
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Recurse -Force -ErrorAction SilentlyContinue

# ---- Done --------------------------------------------------------------------
Write-Verbose "[+] STIG misconfiguration complete. Check Defender for Endpoint for telemetry."
