# Threat-Hunting Scenario – Crimson Mongoose Ransomware Pre-Staging (((DRAFT)))
_Single-VM · Microsoft Defender for Endpoint Advanced Hunting_

---

## 1. Intro
LogN Pacific has been alerted to a new ransomware crew, **“Crimson Mongoose,”** that quietly breaches logistics companies.  
Their confirmed trade-mark: **exactly ten Windows 10 STIG settings are flipped to non-compliant minutes after initial foothold**, then the actors lie low for ≤ 24 hours before detonation.  
Your goal: use **Defender for Endpoint Advanced Hunting (KQL)** to prove all ten flips occurred on the victim VM, link them to the same privileged account and escalate **before hour 24**.

---

## 2. Steps the Bad Actor Took

| Step | Action (attacker script) | Resulting IOC |
|------|-------------------------|---------------|
| 1 | Runs `stig-pre-staging-iocs.ps1` as a privileged account | Flips ten STIG controls (logging, UAC, SMB, WinRM, FIPS). |
| 2 | Monitors Defender noise (< 24 h) | Minimal activity (`whoami`, PowerShell heartbeat). |
| 3 | _(Hypothetical)_ Drops encryptor & schedules task at hour 23-24 | **Not executed** in lab—exercise ends once flips are confirmed. |

> *Incident response is triggered **only after all ten flips are verified**.*

### STIG Controls Disabled by Crimson Mongoose

| STIG ID | Control / Setting | Why it aids pre-staging for ransomware |
|---------|-------------------|----------------------------------------|
| **WN10-CC-000327** | PowerShell Transcription Logging | Hides plain-text PowerShell commands used to download, stage, or launch payloads. |
| **WN10-CC-000326** | PowerShell Script-Block Logging | Removes decoded script-block telemetry that would reveal obfuscated malware logic. |
| **WN10-SO-000245** | Admin Approval Mode (built-in Administrator) | Grants full admin rights with **no UAC prompt**, streamlining silent privilege escalation. |
| **WN10-SO-000250** | Secure-desktop UAC prompt | Elevation prompts appear on user desktop instead of isolating screen → easier to spoof or auto-dismiss. |
| **WN10-AU-000050** | Audit → Process-Creation (success) | Kills Event ID 4688 success records, erasing forensic traces of loader and encryption processes. |
| **WN10-SO-000100** | SMB **client** signing | Lets malware connect to remote shares without integrity checks → faster lateral payload copy. |
| **WN10-SO-000120** | SMB **server** signing | Accepts unsigned inbound sessions → attacker can push tools to host or exfiltrate files invisibly. |
| **WN10-CC-000360** | WinRM Digest Authentication | Enables weaker auth so stolen hashes or sprayed passwords work for remote PowerShell. |
| **WN10-CC-000335** | WinRM Unencrypted Traffic | Allows remote PowerShell over HTTP 5985 (clear-text) to avoid TLS setup and speed automation. |
| **WN10-SO-000230** | FIPS-compliant algorithms | Disables strong crypto; ransomware can use faster or custom encryption routines without failure. |


---

## 3. Tables Used to Detect IoCs
| **Parameter** | **Description** |
|-----------|-------------|
| **Name** | DeviceRegistryEvents |
| **Info** | https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceregistryevents-table |
| **Purpose** | Detects every registry-value change (all ten STIG flips appear here). |

| **Parameter** | **Description** |
|-----------|-------------|
| **Name** | DeviceProcessEvents |
| **Info** | https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-device-processevents-table |
| **Purpose** | Shows which process / command line and which account performed each flip (reg.exe, Set-ItemProperty, auditpol.exe). |

| **Parameter** | **Description** |
|-----------|-------------|
| **Name** | DeviceEvents |
| **Info** | https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table |
| **Purpose** | High-level security events such as *Audit Policy Change* (4719) that accompany logging or UAC modifications. |

| **Parameter** | **Description** |
|-----------|-------------|
| **Name** | DeviceNetworkEvents |
| **Info** | https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicenetworkevents-table |
| **Purpose** | Confirms follow-on network activity: unsigned SMB traffic and WinRM HTTP (5985) sessions after the mis-configs. |

> *If any link 404s, search the table name on Microsoft Learn — URL slugs occasionally change.*


## 4. Related Queries

> **Tip:** Run them one by one in **Microsoft 365 Defender ▸ Advanced Hunting**.  
> Adjust the `ago(24h)` time window if needed.

---

Query A – Registry changes for any of the ten STIG keys

```kusto
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where ActionType == "RegistryValueSet" 
| where RegistryKey has_any (
    @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
    @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    @"SYSTEM\CurrentControlSet\Services\Lanmanworkstation\Parameters",
    @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    @"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client",
    @"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
    @"SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
)
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, 
         RegistryValueData, InitiatingProcessAccountName,  
         InitiatingProcessFileName  
| order by Timestamp desc

What to look for:
EnableTranscripting = 0, EnableScriptBlockLogging = 0, FilterAdministratorToken = 0, etc.
```

Query B – Processes that likely made the changes

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("reg add", "Set-ItemProperty", "auditpol")
| project Timestamp, DeviceName,
         InitiatingProcessAccountUpn, FileName, ProcessCommandLine
| order by Timestamp desc

What to look for:
reg add HKLM\...\EnableTranscripting 0,
powershell Set-ItemProperty -Path ...,
auditpol /set /subcategory:"Process Creation" /success:disable.
```

Query C – Suspicious network after the flips (WinRM HTTP & unsigned SMB)

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where (RemotePort == 5985 and Protocol == "Tcp")  
   or (LocalPort == 445 and Protocol == "Tcp")
| project Timestamp, DeviceName, RemoteIP, RemotePort,
         InitiatingProcessFileName
| order by Timestamp desc

What to look for:
WinRM traffic (RemotePort 5985) and SMB sessions with SmbIsSigned = false that begin after the registry flips.
```

Query D - Validate all 10 controls modified

```kusto
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any ([list all 10 paths])
| summarize ModifiedCount = dcount(RegistryKey) by DeviceName, InitiatingProcessAccountName
| where ModifiedCount == 10
```


---

## Created By:
- **Author Name**: Kevin Lopez
- **Author Contact**: https://www.linkedin.com/in/kevlo-cyber/
- **Date**: June 17, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `June  17, 2025`  | `Kevin Lopez`   


