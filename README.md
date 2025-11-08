# **Local IDS + IPS Defender Hardening**

This configuration converts **Windows Defender + Sysmon** into a **local-only intrusion detection and prevention stack**, without using Microsoft’s cloud threat services, telemetry submission systems, or third-party monitoring services.

This setup is designed for:

* Independent professionals
* Security-focused personal systems
* Offline or privacy-preserving workstations
* Systems where cloud-based “smart security” is not acceptable

No data leaves your machine.
The system protects itself **locally**, in real time.

---

## **What This Setup Does**

### ✅ Intrusion Prevention (IPS)

The script configures Microsoft Defender in *enterprise-level prevention mode*:

| Feature                                  | Purpose                                                                                   |
| ---------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Attack Surface Reduction (ASR) rules** | Blocks common malware execution vectors (macros, script abuse, LOLBins, credential theft) |
| **Controlled Folder Access**             | Stops ransomware from modifying personal and work folders                                 |
| **Network Protection**                   | Blocks malicious script beacons and known exploit infrastructure                          |
| **Local-Only Mode**                      | Cloud scanning & telemetry submission disabled                                            |

This turns Defender into a **real prevention engine**, not a consumer antivirus.

---

### ✅ Intrusion Detection (IDS)

The script installs and configures **Sysmon** (from Microsoft Sysinternals):

| Logged Activity                      | Benefit                                  |
| ------------------------------------ | ---------------------------------------- |
| Process creation & execution history | Detect silent code execution             |
| Network connections                  | Detect unexpected outbound traffic       |
| File modifications                   | Detect staged malware and tampering      |
| Registry changes                     | Detect persistence installation attempts |

Logs are stored **locally** in the Windows Event Log:

```
Event Viewer →
 Applications and Services Logs →
  Microsoft →
   Windows →
    Sysmon / Operational
```

No cloud.
No external endpoints.
Nothing leaves your machine.

---

## **Privacy Notes**

This setup:

* **Disables MAPS Online Threat Reporting**
* **Prevents sample uploads to Microsoft**
* **Keeps all logs & detection logic on-device**
* **Does not communicate with any external SIEM or cloud analytics**

Your system remains **secure** while remaining **private**.

---

## **Performance Impact**

* Sysmon runs as an efficient kernel driver
* ASR rules block execution paths but do not consume CPU when the system is idle
* Controlled Folder Access may require approving apps once on first run (expected)

Overall impact: **Low overhead**, **high security gain**.

---

## **How to Run**

Right-click PowerShell → **Run as Administrator**, then:

```
powershell.exe -ExecutionPolicy Bypass -File .\Local-IDS-IPS-Hardening.ps1
```

A restart is recommended after installation to fully activate Defender Network Protection.

---

## **How to Verify It’s Working**

### Defender IPS Status

```
Get-MpPreference | Select-Object EnableNetworkProtection,EnableControlledFolderAccess
```

### ASR Rules Status

```
Get-MpPreference | Select -ExpandProperty AttackSurfaceReductionRules_Ids
```

### Sysmon Logging

Open:

```
eventvwr.msc
```

Navigate to:

```
Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

You should see entries shortly after running applications or processes.

---

## **How to Remove / Undo**

Sysmon uninstall:

```
Sysmon64.exe -u
```

Revert Defender ASR:

```
Set-MpPreference -AttackSurfaceReductionRules_Actions 0
```

Disable Controlled Folder Access:

```
Set-MpPreference -EnableControlledFolderAccess Disabled
```

---
