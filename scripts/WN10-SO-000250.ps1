<#
.SYNOPSIS
    Restores secure-desktop elevation prompts for administrators (STIG WN10-SO-000250).

.NOTES
    Author          : Kevin Lopez
    LinkedIn        : https://www.linkedin.com/in/kevlo-cyber/
    GitHub          : https://github.com/kevlo-cyber
    Date Created    : 06/17/2025
    Last Modified   : 06/17/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000250

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example:
    PS C:\> .\scripts\WN10-SO-000250.ps1
    Restores secure-desktop UAC prompts.
#>

$ErrorActionPreference = 'SilentlyContinue'

if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) { exit 1 }

# Restore secure-desktop prompt
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                 -Name 'ConsentPromptBehaviorAdmin' -Type DWord -Value 2 -Force

# Log action
New-Item -ItemType Directory -Path 'C:\Temp' -Force | Out-Null
"STIG remediation applied (WN10-SO-000250) – $(Get-Date)" |
    Out-File "C:\Temp\STIG_WN10-SO-000250_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Write-Host '[+] Secure-desktop UAC prompt RESTORED (value 2). Log off to apply.' -ForegroundColor Yellow
exit 0
