# Threat-Hunting Scenario – Crimson Mongoose Ransomware Pre-Staging  
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

---

## 3. Tables Used to Detect IoCs
| **Parameter** | **Description** |
|-----------|-------------|
| **Name** | DeviceRegistryEvents |
| **Info** |https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceregistryevents-table|
| **Purpose** | Detects every registry-value change (all ten STIG flips appear here). |

| **Parameter** | **Description** |
|-----------|-------------|
| **Name** | DeviceProcessEvents |
| **Info** |https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-device-processevents-table>|
| **Purpose** | Shows which process / command line and which account performed each flip (reg.exe, Set-ItemProperty, auditpol.exe). |

| **Parameter** | **Description** |
|-----------|-------------|
| **Name** | DeviceEvents |
| **Info** |https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table> |
| **Purpose** | High-level security events such as *Audit Policy Change* (4719) that accompany logging or UAC modifications. |

| **Parameter** | **Description** |
|-----------|-------------|
| **Name** | DeviceNetworkEvents |
| **Info** |https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicenetworkevents-table>|
| **Purpose** | Confirms follow-on network activity: unsigned SMB traffic and WinRM HTTP (5985) sessions after the mis-configs. |

> *If any link 404s, search the table name on Microsoft Learn — URL slugs occasionally change.*


## 4. Related Queries

```kusto
// A. Confirm ALL 10 STIG flips on the device
let bad =
datatable(KeyValue:string, BadData:string)
[
  @"\PowerShell\Transcription|EnableTranscripting",            "0",
  @"\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging",  "0",
  @"\Policies\System|FilterAdministratorToken",                "0",
  @"\Policies\System|ConsentPromptBehaviorAdmin",              "0",
  @"\System\Audit|ProcessCreationIncludeCmdLine_Enabled",      "0",
  @"\LanmanWorkstation|RequireSecuritySignature",              "0",
  @"\LanmanServer|RequireSecuritySignature",                   "0",
  @"\WinRM\Client|AllowDigest",                                "1",
  @"\WinRM\Client|AllowUnencryptedTraffic",                    "1",
  @"\WinRM\Service|AllowUnencryptedTraffic",                   "1",
  @"\Lsa\FipsAlgorithmPolicy|Enabled",                         "0"
];
DeviceRegistryEvents
| where Timestamp > ago(24h)
| extend KV = strcat(RegistryKey,"|",RegistryValueName)
| join kind=inner bad on $left.KV==$right.KeyValue
| where RegistryValueData == BadData
| summarize flips = make_set(KV) by DeviceName, InitiatingProcessAccountUpn, earliest=min(Timestamp)
| where array_length(flips) == 10      // ⇐ all ten present
| project earliest, DeviceName, InitiatingProcessAccountUpn, flips

// B. Processes / accounts that made the changes
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("reg add","Set-ItemProperty","auditpol")
| project Timestamp, DeviceName, InitiatingProcessAccountUpn,
         FileName, ProcessCommandLine
| order by Timestamp desc

// C. Supporting network indicators (WinRM HTTP & unsigned SMB)
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where (RemotePort == 5985 and Protocol == "TCP")          // WinRM over HTTP
   or (Protocol == "SMB" and SmbIsSigned == false)          // Unsigned SMB
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, ActionType
```


5. Created By
Kevin Lopez

6. Validated By
(leave blank for now)

7. Additional Notes
Learners must confirm all ten flips before declaring an incident.

Encryption phase is hypothetical and will not run in the lab.

A single Windows 10 VM is used; no domain controller or mail telemetry available.

8. Revision History
Date	Version	Notes
2025-06-17	1.0	Initial scenario (Crimson Mongoose STIG flips).


