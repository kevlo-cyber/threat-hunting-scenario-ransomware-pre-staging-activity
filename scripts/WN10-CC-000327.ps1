<#
.SYNOPSIS
    Enables PowerShell transcription logging (STIG WN10-CC-000327) on Windows 10.

.NOTES
    Author          : Kevin Lopez
    LinkedIn        : https://www.linkedin.com/in/kevlo-cyber/
    GitHub          : https://github.com/kevlo-cyber
    Date Created    : 06/17/2025
    Last Modified   : 06/17/2025
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000327

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example:
    PS C:\> .\scripts\WN10-CC-000327.ps1
    Enables transcription logging for all PowerShell sessions.
#>

# Suppress all output for silent execution
$ErrorActionPreference  = 'SilentlyContinue'
$WarningPreference      = 'SilentlyContinue'
$VerbosePreference      = 'SilentlyContinue'

# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host '[!] Run this script as Administrator.' -ForegroundColor Yellow
    exit 1
}

# Function to set a registry value silently
function Set-RegistryValue {
    param([string]$Path, [string]$Name, [Int32]$Value)
    try {
        if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Type DWord -Value $Value -Force
    } catch {}
}

# Enable PowerShell transcription
Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
                  -Name 'EnableTranscripting' -Value 1

# Log action
try {
    New-Item -ItemType Directory -Path 'C:\Temp' -Force | Out-Null
    "STIG remediation applied (WN10-CC-000327) – $(Get-Date)" |
        Out-File "C:\Temp\STIG_WN10-CC-000327_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
} catch {}

Write-Host '[+] PowerShell transcription logging ENABLED.' -ForegroundColor Green
exit 0
