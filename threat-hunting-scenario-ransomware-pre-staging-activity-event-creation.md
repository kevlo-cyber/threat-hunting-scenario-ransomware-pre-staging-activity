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

## 3. Tables Used to Detect IOCs

| Defender Table | Microsoft Docs Link | Why it’s useful here |
|----------------|---------------------|----------------------|
| **RegistryEvents** | <https://learn.microsoft.com/security/defender-endpoint/advanced-hunting-registry-events> | Captures each STIG registry value changed to the bad state. |
| **ProcessCreationEvents** | <https://learn.microsoft.com/security/defender-endpoint/advanced-hunting-process-events> | Shows `reg.exe`, `Set-ItemProperty`, `auditpol.exe` commands that performed the flips and the initiating account. |
| **DeviceNetworkEvents** | <https://learn.microsoft.com/security/defender-endpoint/advanced-hunting-network-events> | Lets you spot outbound SMB without signing and WinRM HTTP 5985 sessions—supporting indicators. |

---

## 4. Related Queries (run in **security.microsoft.com → Hunting → Advanced Hunting**)

<details>
<summary>Query A – Registry flips (all ten controls)</summary>

```kusto
let badValues = dynamic([
  // PowerShell logging
  @"EnableTranscripting=0", @"EnableScriptBlockLogging=0",
  // UAC / Admin Approval
  @"FilterAdministratorToken=0", @"ConsentPromptBehaviorAdmin=0",
  // Audit
  @"Process Creation|success:disable",
  // SMB signing
  @"LanmanWorkstation|RequireSecuritySignature=0",
  @"LanmanServer|RequireSecuritySignature=0",
  // WinRM
  @"AllowDigest=1", @"AllowUnencryptedTraffic=1",
  // FIPS
  @"FipsAlgorithmPolicy|Enabled=0"
]);
RegistryEvents
| where Timestamp > ago(24h)
| extend IOC = strcat(RegistryKey,"|",RegistryValueName,"=",RegistryValueData)
| where IOC in (badValues)
| summarize flips = make_set(IOC) by DeviceName, InitiatingProcessAccountUpn
| where array_length(flips) == 10   // all ten present
```
</details> <details> <summary>Query B – Processes that changed the keys</summary>
ProcessCreationEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("reg add", "Set-ItemProperty", "auditpol")
| project Timestamp, DeviceName, InitiatingProcessAccountUpn,
         FileName, ProcessCommandLine
</details> <details> <summary>Query C – Unsigned SMB & WinRM HTTP traffic</summary>
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where (RemotePort == 5985 and Protocol == "TCP")  // WinRM HTTP
   or (Protocol == "SMB" and SmbIsSigned == false) // unsigned SMB
| project Timestamp, DeviceName, RemoteIP, RemotePort, ReportId
</details>
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


