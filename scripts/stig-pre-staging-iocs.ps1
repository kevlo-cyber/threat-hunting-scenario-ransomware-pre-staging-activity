<#
Purpose : Force **10** Windows 10 STIG controls into a non-compliant state
          for attacker pre-staging simulation.
Controls: WN10-CC-000327  (PowerShell Transcription)
          WN10-CC-000326  (PowerShell Script-Block Logging)
          WN10-SO-000245  (Admin Approval Mode for built-in Administrator)
          WN10-SO-000250  (Secure-desktop elevation prompt)
          WN10-AU-000050  (Audit Process Creation successes)
          WN10-SO-000100  (SMB client signing)
          WN10-SO-000120  (SMB server signing)
          WN10-CC-000360  (WinRM Digest authentication)
          WN10-CC-000335  (Unencrypted WinRM traffic)
          WN10-SO-000230  (FIPS mode)
Silent run; auto-reboots when finished.
#>

# Abort if not running as Administrator
if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Warning "Script must be run from an elevated PowerShell session."
    exit 1
}

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

function EP ($p) { if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null } }

# 1. Disable PowerShell Transcription (WN10-CC-000327)
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
                 -Name EnableTranscripting -Type DWord -Value 0 -Force

# 2. Disable PowerShell Script-Block Logging (WN10-CC-000326)
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
                 -Name EnableScriptBlockLogging -Type DWord -Value 0 -Force

# 3. Disable Admin Approval Mode for built-in Administrator (WN10-SO-000245)
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                 -Name FilterAdministratorToken -Type DWord -Value 0 -Force

# 4. Remove secure-desktop prompt for admins (WN10-SO-000250)
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                 -Name ConsentPromptBehaviorAdmin -Type DWord -Value 0 -Force

# 5. Disable audit: Process Creation successes (WN10-AU-000050)
AuditPol /set /subcategory:"Process Creation" /success:disable | Out-Null

# 6. Disable SMB client signing (WN10-SO-000100)
EP 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
                 -Name RequireSecuritySignature -Type DWord -Value 0 -Force

# 7. Disable SMB server signing (WN10-SO-000120)
EP 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                 -Name RequireSecuritySignature -Type DWord -Value 0 -Force

# 8. Allow WinRM Digest authentication (WN10-CC-000360)
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
                 -Name AllowDigest -Type DWord -Value 1 -Force

# 9. Allow unencrypted WinRM traffic (WN10-CC-000335)
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
                 -Name AllowUnencryptedTraffic -Type DWord -Value 1 -Force
EP 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
                 -Name AllowUnencryptedTraffic -Type DWord -Value 1 -Force

# 10. Disable FIPS mode (WN10-SO-000230)
EP 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' `
                 -Name Enabled -Type DWord -Value 0 -Force

# Immediate reboot to commit all changes
shutdown.exe /r /t 0 /c "STIG misconfig (10 controls) – rebooting"
