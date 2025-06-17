<#
.SYNOPSIS
    Disables WinRM Digest authentication (STIG WN10-CC-000360) on Windows 10.

.NOTES
    Author          : Kevin Lopez
    LinkedIn        : https://www.linkedin.com/in/kevlo-cyber/
    GitHub          : https://github.com/kevlo-cyber
    Date Created    : 06/17/2025
    Last Modified   : 06/17/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000360

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example:
    PS C:\> .\scripts\WN10-CC-000360.ps1
    Disables Digest authentication for the WinRM client.
#>

# ── Silent-run defaults ───────────────────────────────────────────────────────
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

# ── Require elevation ─────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host '[!] Run this script as Administrator.' -ForegroundColor Yellow
    exit 1
}

# ── Remediation ───────────────────────────────────────────────────────────────
$Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name 'AllowDigest' -Type DWord -Value 0 -Force

# ── Logging ──────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path 'C:\Temp' -Force | Out-Null
"STIG remediation applied (WN10-CC-000360) – $(Get-Date)" |
    Out-File "C:\Temp\STIG_WN10-CC-000360_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Write-Host '[+] WinRM Digest authentication DISABLED (value 0).' -ForegroundColor Green
exit 0
