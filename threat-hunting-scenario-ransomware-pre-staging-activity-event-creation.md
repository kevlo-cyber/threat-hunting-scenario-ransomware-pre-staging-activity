# Threat‑Hunting Scenario: Ransomware Pre‑Staging Activity (Windows 10 / Azure)

## Overview

This playbook walks through **simulating** and **detecting** the techniques that modern ransomware operators (e.g., BlackCat, LockBit 3.0) use *weeks* before detonation: systematically weakening host‑level security controls.
The end goal is to validate that Microsoft **Defender for Endpoint (MDE)** surfaces the right telemetry so that the SOC can hunt and respond *before* encryption.

> **Why this matters**: Recent FS‑ISAC reporting (March 2025) shows affiliates spending **2–3 weeks** disabling Windows protections across finance sector victims before dropping their payloads.

---

## Hypothesis

If an attacker is preparing a ransomware campaign, we will observe **STIG‑defined mis‑configurations** and classic “pre‑ransomware” behaviors such as:

1. Disabling Microsoft Defender components
2. Turning off audit logging & recovery features
3. Clearing event logs
   These actions should be visible in MDE Advanced Hunting and, optionally, forwarded to Microsoft Sentinel.

---

## Lab Environment

| Component           | Details                                                                                                    |
| ------------------- | ---------------------------------------------------------------------------------------------------------- |
| **Cloud**           | Azure subscription (any tier)                                                                              |
| **Host**            | 1× Windows 10 Enterprise 21H2 VM (no domain join required)                                                 |
| **Access**          | Local Administrator                                                                                        |
| **Security stack**  | Microsoft Defender for Endpoint (latest), optional Sysmon for extra telemetry                              |
| **Log destination** | MDE portal; devices are already onboarded. Sentinel is available but **hunting will be performed in MDE**. |

> ⚠️ **No domain controller is needed.** All registry and policy tweaks are performed locally on the single VM.

---

## Step 1 – Baseline the VM

1. **Snapshot** the clean state.
2. Ensure **PowerShell script‑block logging** is **ON**
   `Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1 -Type DWord -Force`
3. Confirm **Microsoft Defender** real‑time protection is **ON** and cloud‑delivered protection is enabled.
4. Enable recommended **Audit Policy** settings (STIG) with `auditpol /set` or LGPO.
5. Validate that the VM is reporting into **MDE**.

---

## Step 2 – Simulate Pre‑Staging Techniques

> Run the following commands **as Administrator**. Wait \~2 minutes between groups to mimic realistic dwell time.

### Phase A – Security Control Degradation (10 STIG Violations)

| #  | Technique                                      | STIG ID          | Command                                                                       |
| -- | ---------------------------------------------- | ---------------- | ----------------------------------------------------------------------------- |
| 1  | Disable PUA protection                         | `WNDF‑AV‑000001` | `Set‑ItemProperty -Path "HKLM:\...\MpEngine" -Name MpEnablePus -Value 0`      |
| 2  | Disable script‑block logging                   | `WN10‑CC‑000326` | `Set‑ItemProperty HKLM:\...\ScriptBlockLogging EnableScriptBlockLogging 0`    |
| 3  | Disable UAC (Admin Approval Mode)              | `WN10‑SO‑000270` | `Set‑ItemProperty HKLM:\...\Policies\System EnableLUA 0`                      |
| 4  | Auto‑approve elevation prompts                 | `WN10‑SO‑000255` | `Set‑ItemProperty HKLM:\...\Policies\System ConsentPromptBehaviorUser 0`      |
| 5  | Disable installer detection                    | `WN10‑SO‑000260` | `Set‑ItemProperty HKLM:\...\Policies\System EnableInstallerDetection 0`       |
| 6  | Weaken RDP encryption                          | `WN10‑CC‑000290` | `Set‑ItemProperty HKLM:\...\Terminal Services MinEncryptionLevel 1`           |
| 7  | Stop auditing *Credential Validation* failures | `WN10‑AU‑000005` | `auditpol /set /subcategory:"Credential Validation" /failure:disable`         |
| 8  | Stop auditing *Credential Validation* success  | `WN10‑AU‑000010` | `auditpol /set /subcategory:"Credential Validation" /success:disable`         |
| 9  | Disable Defender real‑time protection          | `WN10‑00‑000050` | `Set‑ItemProperty HKLM:\...\Real‑Time Protection DisableRealtimeMonitoring 1` |
| 10 | Remove AppLocker policies                      | `WN10‑00‑000040` | `Remove‑Item HKLM:\...\SrpV2 -Recurse -Force`                                 |

### Phase B – Classic Ransomware Preparation

```powershell
# Delete shadow copies
vssadmin delete shadows /all /quiet

# Disable System Restore
Disable-ComputerRestore -Drive "C:"

# Turn off Windows Recovery Environment
bcdedit /set {default} recoveryenabled no
bcdedit /set {default} bootstatuspolicy ignoreallfailures

# Persistence – fake Windows Update task
$action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command Write-Host 'Beacon'"
$trigger = New-ScheduledTaskTrigger -Daily -At 09:00
Register-ScheduledTask -TaskName "WindowsUpdateHelper" -Action $action -Trigger $trigger -RunLevel Highest

# Wipe security logs
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```

---

## Step 3 – Hunt in Defender for Endpoint

### 3.1 Key Telemetry Tables

| Table                  | Use                                                           |
| ---------------------- | ------------------------------------------------------------- |
| `DeviceRegistryEvents` | Track security‑relevant registry changes                      |
| `DeviceProcessEvents`  | Process creation (e.g., `vssadmin`, `bcdedit`)                |
| `DeviceEvents`         | Security log clear, audit policy change (Event ID 1102, 4719) |

### 3.2 Advanced‑Hunting Queries

**Registry changes touching security controls**

```kusto
DeviceRegistryEvents
| where RegistryKey has_any (
      @"\\Windows Defender\\",
      @"\\Policies\\System",
      @"\\Terminal Services")
| summarize count() by DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, bin(Timestamp, 1h)
| order by Timestamp desc
```

**Audit policy modifications**

```kusto
DeviceEvents
| where ActionType == "AuditPolicyChanged"
| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields
```

**Shadow copy deletion & recovery sabotage**

```kusto
DeviceProcessEvents
| where FileName in~ ("vssadmin.exe", "bcdedit.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```

> 📌 **Optional**: Stream `Device*` tables to **Microsoft Sentinel** with the built‑in connector for centralized hunting.

---

## MITRE ATT\&CK Mapping

| Tactic          | Technique (sub‑ID)                           | Evidence in Lab                    |
| --------------- | -------------------------------------------- | ---------------------------------- |
| Defense Evasion | T1562.001 *Impair Defenses*                  | Disable Defender & AppLocker       |
| Defense Evasion | T1112 *Modify Registry*                      | All STIG registry edits            |
| Discovery       | T1087.002 *Domain Account Discovery (Local)* | N/A (single host)                  |
| Impact          | T1490 *Inhibit System Recovery*              | Shadow copies deletion, RE disable |
| Defense Evasion | T1070.001 *Clear Windows Event Logs*         | `wevtutil cl`                      |

---

## Success Criteria

* **≥10** STIG‑defined mis‑configurations are detected in MDE.
* Shadow copy deletion and boot‑config tampering generate alerts or query matches.
* SOC analysts can build an incident timeline from MDE telemetry *without relying on Defender alerts alone*.

---

## Cleanup

1. Revert to the **baseline snapshot** or run the provided `Reset‑Config.ps1` script (not included) to re‑enable all protections.
2. Confirm the VM once again reports healthy to MDE.

---

## Further Improvements

* Import Sysmon for richer process‑tree context.
* Extend to a multi‑VM, domain‑joined lab for lateral‑movement detection.
* Use **Azure Logic Apps** to auto‑notify when queries return hits.

---

## Created By:
- **Author Name**: Kevin Lopez
- **Author Contact**: https://www.linkedin.com/in/kevlo-cyber/
- **Date**: June 13, 2025

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
| 1.0         | Initial draft                  | `June  13, 2025`  | `Kevin Lopez`   
