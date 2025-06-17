<#
.SYNOPSIS
    Enables PowerShell script-block logging (STIG WN10-CC-000326) on Windows 10.

.NOTES
    Author          : Kevin Lopez
    LinkedIn        : https://www.linkedin.com/in/kevlo-cyber/
    GitHub          : https://github.com/kevlo-cyber
    Date Created    : 06/17/2025
    Last Modified   : 06/17/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000326

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example:
    PS C:\> .\scripts\WN10-CC-000326.ps1
    Enables script-block logging without rebooting.
#>

$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host '[!] Run this script as Administrator.' -ForegroundColor Yellow
    exit 1
}

function Set-RegValue { param($Path,$Name,$Val)
    if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Type DWord -Value $Val -Force
}

# Enable script-block logging
Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
             'EnableScriptBlockLogging' 1

# Log action
New-Item -ItemType Directory -Path 'C:\Temp' -Force | Out-Null
"STIG remediation applied (WN10-CC-000326) – $(Get-Date)" |
    Out-File "C:\Temp\STIG_WN10-CC-000326_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Write-Host '[+] Script-block logging ENABLED. No reboot required.' -ForegroundColor Green
exit 0
