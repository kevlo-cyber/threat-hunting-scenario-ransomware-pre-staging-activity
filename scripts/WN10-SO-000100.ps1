<#
.SYNOPSIS
    Requires SMB client signing (STIG WN10-SO-000100).

.NOTES
    Author          : Kevin Lopez
    LinkedIn        : https://www.linkedin.com/in/kevlo-cyber/
    GitHub          : https://github.com/kevlo-cyber
    Date Created    : 06/17/2025
    Last Modified   : 06/17/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000100

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example:
    PS C:\> .\scripts\WN10-SO-000100.ps1
    Enforces SMB client signing; reboot may be required.
#>

$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) { exit 1 }

# Require client signing
$Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name 'RequireSecuritySignature' -Type DWord -Value 1 -Force

# Log action
New-Item -ItemType Directory -Path 'C:\Temp' -Force | Out-Null
"STIG remediation applied (WN10-SO-000100) – $(Get-Date)" |
    Out-File "C:\Temp\STIG_WN10-SO-000100_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Write-Host '[+] SMB client signing REQUIRED. A reboot or Workstation service restart may be needed.' -ForegroundColor Yellow
exit 0
