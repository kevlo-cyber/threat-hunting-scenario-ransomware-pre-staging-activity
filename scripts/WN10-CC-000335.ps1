<#
.SYNOPSIS
    Disallows unencrypted WinRM traffic (STIG WN10-CC-000335) on Windows 10.

.NOTES
    Author          : Kevin Lopez
    LinkedIn        : https://www.linkedin.com/in/kevlo-cyber/
    GitHub          : https://github.com/kevlo-cyber
    Date Created    : 06/17/2025
    Last Modified   : 06/17/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000335

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example:
    PS C:\> .\scripts\WN10-CC-000335.ps1
    Blocks unencrypted WinRM traffic for client and service.
#>

$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) { exit 1 }

function Set-WinRMValue { param($RegPath, [int]$Val)
    if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
    Set-ItemProperty -Path $RegPath -Name 'AllowUnencryptedTraffic' -Type DWord -Value $Val -Force
}

# Client & Service keys
Set-WinRMValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'   0
Set-WinRMValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'  0

# Logging
New-Item -ItemType Directory -Path 'C:\Temp' -Force | Out-Null
"STIG remediation applied (WN10-CC-000335) – $(Get-Date)" |
    Out-File "C:\Temp\STIG_WN10-CC-000335_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Write-Host '[+] Unencrypted WinRM traffic DISALLOWED (value 0).' -ForegroundColor Green
exit 0
