<#
.SYNOPSIS
    Enables Admin Approval Mode for the built-in Administrator (STIG WN10-SO-000245).

.NOTES
    Author          : Kevin Lopez
    LinkedIn        : https://www.linkedin.com/in/kevlo-cyber/
    GitHub          : https://github.com/kevlo-cyber
    Date Created    : 06/17/2025
    Last Modified   : 06/17/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000245

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example:
    PS C:\> .\scripts\WN10-SO-000245.ps1
    Enables Admin Approval Mode; log-off recommended.
#>

$ErrorActionPreference = 'SilentlyContinue'

if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) { exit 1 }

# Enable Admin Approval Mode
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                 -Name 'FilterAdministratorToken' -Type DWord -Value 1 -Force

# Log action
New-Item -ItemType Directory -Path 'C:\Temp' -Force | Out-Null
"STIG remediation applied (WN10-SO-000245) – $(Get-Date)" |
    Out-File "C:\Temp\STIG_WN10-SO-000245_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Write-Host '[+] Admin Approval Mode ENABLED. Log off & back on to finalize.' -ForegroundColor Yellow
exit 0
