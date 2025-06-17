<#
.SYNOPSIS
    Enables FIPS-compliant algorithms (STIG WN10-SO-000230) on Windows 10.

.NOTES
    Author          : Kevin Lopez
    LinkedIn        : https://www.linkedin.com/in/kevlo-cyber/
    GitHub          : https://github.com/kevlo-cyber
    Date Created    : 06/17/2025
    Last Modified   : 06/17/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000230

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example:
    PS C:\> .\scripts\WN10-SO-000230.ps1
    Enables FIPS mode and reminds you to reboot.
#>

$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) { exit 1 }

# Enable FIPS mode
$RegPath = 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'
if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
Set-ItemProperty -Path $RegPath -Name 'Enabled' -Type DWord -Value 1 -Force

# Log action
New-Item -ItemType Directory -Path 'C:\Temp' -Force | Out-Null
"STIG remediation applied (WN10-SO-000230) – $(Get-Date)" |
    Out-File "C:\Temp\STIG_WN10-SO-000230_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Write-Host '[+] FIPS mode ENABLED. ***Please reboot to complete enforcement.***' -ForegroundColor Yellow
exit 0
