# LogN Pacific – Crimson Mongoose Ransomware Pre-Staging Hunt  
_Single-VM exercise for the Josh Madakor Cyber Range – **Defender-only hunting**_

---

## Background Story – LogN Pacific vs. “Crimson Mongoose”

LogN Pacific keeps 42 ports humming across the Asia-Pacific region.  
Yesterday the CISO received a CERT flash: a new ransomware crew nick-named **“Crimson Mongoose”** is actively breaching logistics firms just like LogN Pacific.

### What investigators know so far

| Stage | Details |
|-------|---------|
| **Initial access** | Highly tailored spear-phish to high-privilege users (domain admins, SCCM operators, Azure AD Global Admins). |
| **Immediate action** | Within minutes of foothold the intruders flip **_exactly ten_ Windows 10 STIG settings** from compliant to non-compliant. |
| **Dwell time** | They lie low for **up to 24 hours**, monitoring Defender noise to stay invisible. |
| **Impact** | A custom Go-based encryptor detonates after the 24-hour mark, crippling operations and demanding an eight-figure ransom. |

These ten STIG mis-configurations all **erase visibility or weaken host defenses**, PowerShell logging, UAC hardening, SMB & WinRM security, FIPS crypto, and more. In every confirmed Crimson Mongoose incident the same ten flips appeared, no more, no less, making them the most reliable early-warning indicator.

### Your threat-hunting mission

> **Use Microsoft Defender for Endpoint Advanced Hunting to detect _all ten_ STIG flips on the single Windows 10 victim VM, tie them to the same privileged account, and escalate before the 24-hour fuse burns down.**

Catch the mis-configurations in time and LogN Pacific’s cargo keeps moving; miss them and Crimson Mongoose will lock every manifest and invoice behind an eight-figure ransom demand.

---

## 2 Tools in Scope

| Tool | Role in this exercise |
|------|-----------------------|
| **Microsoft Defender for Endpoint** | **Only hunting console** (Advanced Hunting queries, timeline, isolation). |
| **Tenable** | *Instructor-only* baseline check (not used by learner). |
| **Azure VM** | Single Windows 10 **victim host** running the MDE sensor. |

---

## 3 Lab Topology

Internet Phish → Victim Win10 VM (Azure)
▲ Defender for Endpoint sensor
Hunter (browser) ────┘ security.microsoft.com (Advanced Hunting)


---

## 4 Lab Setup (Instructor)

```powershell
# 1. Restore STIG compliance (baseline)
iwr "https://raw.githubusercontent.com/kevlo-cyber/threat-hunting-scenario-ransomware-pre-staging-activity/main/scripts/stig-remediation.ps1" -OutFile "$env:TMP\stig-remediation.ps1"
powershell -ExecutionPolicy Bypass -File "$env:TMP\stig-remediation.ps1"

# (Instructor may verify with Tenable scan here.)

```

Learners begin after this baseline is set.

## 5 Inject the IOCs (Attacker script)

iwr "https://raw.githubusercontent.com/kevlo-cyber/threat-hunting-scenario-ransomware-pre-staging-activity/main/scripts/stig-pre-staging-iocs.ps1" -OutFile "$env:TMP\stig-pre-staging-iocs.ps1"
powershell -ExecutionPolicy Bypass -File "$env:TMP\stig-pre-staging-iocs.ps1"

That flips these ten STIG controls:

#	Mis-configuration	STIG ID
1	PS transcription OFF	WN10-CC-000327
2	Script-block logging OFF	WN10-CC-000326
3	Admin Approval Mode OFF	WN10-SO-000245
4	Secure-desktop UAC prompt OFF	WN10-SO-000250
5	Process-Creation success auditing OFF	WN10-AU-000050
6	SMB client signing OFF	WN10-SO-000100
7	SMB server signing OFF	WN10-SO-000120
8	WinRM Digest auth ON	WN10-CC-000360
9	WinRM unencrypted traffic ON	WN10-CC-000335
10	FIPS mode OFF	WN10-SO-000230

## 6 Adversary Timeline (context)
(Rows after Hour 0 are hypothetical encryption will not run in this lab.)

Hour	Action	MDE telemetry
0	Runs mis-config script.	ProcessCreationEvents for reg.exe / auditpol.exe / powershell.exe
RegistryEvents with the ten key paths.
1-23	Quiet recon.	Occasional whoami, Defender device heartbeat.
23	Drops encryptor.	New file in %PROGRAMDATA%, ProcessCreationEvents.
23.5	Deletes shadow copies.	ProcessCreationEvents vssadmin.exe.
24	Schedules encryptor.	Task scheduler events (not executed here).

IR is triggered only after all ten STIG flips are verified.

## 7 Hunting Tasks (Defender Advanced Hunting)

1. Find the registry flips

RegistryEvents
| where Timestamp > ago(24h)
| where (
    RegistryKey has @"\PowerShell\Transcription" and RegistryValueName == "EnableTranscripting" and RegistryValueData == "0"
    or RegistryKey has @"\PowerShell\ScriptBlockLogging" and RegistryValueData == "0"
    or RegistryKey has @"\FipsAlgorithmPolicy" and RegistryValueData == "0"
    or RegistryKey has @"\WinRM\Client"     and RegistryValueName == "AllowDigest"
    or RegistryKey has @"\WinRM\Client"     and RegistryValueName == "AllowUnencryptedTraffic"
    or RegistryKey has @"\WinRM\Service"    and RegistryValueName == "AllowUnencryptedTraffic"
    or RegistryKey has @"\LanmanWorkstation" and RegistryValueName == "RequireSecuritySignature" and RegistryValueData == "0"
    or RegistryKey has @"\LanmanServer"      and RegistryValueName == "RequireSecuritySignature" and RegistryValueData == "0"
    or RegistryKey has @"\Policies\System"   and RegistryValueName in ("FilterAdministratorToken","ConsentPromptBehaviorAdmin")
  )

2. Correlate to the modifying process & account

DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 5985 and Protocol == "TCP"   // WinRM HTTP
  or (Protocol == "SMB" and SmbIsSigned == false)  // Unsigned SMB

3. Network clues – Defender network sensor:

DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 5985 and Protocol == "TCP"   // WinRM HTTP
  or (Protocol == "SMB" and SmbIsSigned == false)  // Unsigned SMB

4. Validate that all ten controls are flipped; only then escalate.

## 8 Success Criteria
Tier	Requirement
Bronze	Use MDE queries to list all ten non-compliant settings.
Silver	Show the exact privileged account & timestamp for each flip.
Gold	Create an MDE custom detection rule that fires after all ten flips (AND logic).
Platinum	Use Defender to isolate the VM or disable the compromised account before hour 24.

## 9 Cleanup
The VM will be deleted after the exercise, so remediation is optional.
(Optional) rerun stig-remediation.ps1 for practice.

## 10 References
DISA Windows 10 STIG v2r9

MITRE ATT&CK v14

Defender for Endpoint Advanced Hunting docs

Josh Madakor Cyber Range – https://joshmadakor.tech/cyber/

Kevin Lopez – LinkedIn · GitHub

“Validate every flip, correlate every account, then pull the isolation trigger before the fuse burns down.”
