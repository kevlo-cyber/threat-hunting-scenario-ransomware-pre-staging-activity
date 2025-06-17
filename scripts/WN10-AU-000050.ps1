<#
.SYNOPSIS
    Enables success auditing for Process Creation events (STIG WN10-AU-000050).

.NOTES
    Author          : Kevin Lopez
    LinkedIn        : https://www.linkedin.com/in/kevlo-cyber/
    GitHub          : https://github.com/kevlo-cyber
    Date Created    : 06/17/2025
    Last Modified   : 06/17/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000050

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example:
    PS C:\> .\scripts\WN10-AU-000050.ps1
    Enables success auditing for process creation.
#>

$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host '[!] Run this script as Administrator.' -ForegroundColor Yellow
    exit 1
}

# Enable success auditing
AuditPol /set /subcategory:"Process Creation" /success:enable | Out-Null

# Log action
try {
    New-Item -ItemType Directory -Path 'C:\Temp' -Force | Out-Null
    "STIG remediation applied (WN10-AU-000050) – $(Get-Date)" |
        Out-File "C:\Temp\STIG_WN10-AU-000050_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
} catch {}

Write-Host '[+] Process-creation success auditing ENABLED.' -ForegroundColor Green
exit 0
