# 🔒 **Windows Security Baseline Auditor**

A PowerShell script that audits **Windows Server and Workstation security posture** against simplified best practices inspired by **CIS**, **NIST**, and **Microsoft** baselines.

Outputs **colorized console status**, **timestamped logs**, and an **exportable CSV** of failed/warning checks—ready for **RMM deployment at scale**.

---

## ✨ **Highlights**

| Feature               | Description                                                                                                                                                                 |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Baseline Coverage** | Account policies, local security policy (UAC, built-ins), audit policy, services, firewall, network stack (SMB1/NetBIOS/IPv6), Defender, BitLocker, Windows Update recency. |
| **Clear Results**     | Pass / Warning / Fail with expected vs. actual, severity, and remediation guidance.                                                                                         |
| **RMM-Ready**         | Zero interactive prompts; logs + CSV stored under `C:\Logs\SecurityAudit\...`.                                                                                              |
| **Self-Contained**    | Creates its log directory, handles temp exports (`secedit` / `auditpol`), and cleans up.                                                                                    |
| **Score at a Glance** | Overall Compliance Score based on pass ratio.                                                                                                                               |

---

## ✅ **Compatibility**

| Requirement    | Details                                                                                      |
| -------------- | -------------------------------------------------------------------------------------------- |
| **OS**         | Windows Server 2016+, Windows 10/11                                                          |
| **PowerShell** | Windows PowerShell 5.1 (built-in on supported OSes)                                          |
| **Rights**     | Run as **Administrator** (required for security policy export, services, and registry reads) |

---

## 🚀 **Quick Start (One-Liner)**

Runs from GitHub Raw and immediately audits the local machine.

```powershell
iwr https://raw.githubusercontent.com/Coach40oz/Windows-SecurityBaselineAuditor/refs/heads/main/script.ps1 -UseBasicParsing | iex
```

> **Tip (RMM):** If your RMM requires an explicit bypass:
>
> ```powershell
> powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "iwr https://raw.githubusercontent.com/Coach40oz/Windows-SecurityBaselineAuditor/refs/heads/main/script.ps1 -UseBasicParsing | iex"
> ```

---

## 🧠 **Audit Categories**

### **Account Policies**

* Password history, minimum/maximum age, length, complexity
* Lockout threshold, duration, and reset window

### **Local Security Policies**

* Built-in **Administrator/Guest** account status
* **Deny access from network** for Guest
* Local account model: *Classic* vs. *Guest-only*
* **UAC** settings and Admin Approval Mode

### **Audit Policies**

* Credential Validation, Logon, User Account Management
* File System auditing enabled for sensitive paths

### **Registry & Host Controls**

* **Remote Registry** service disabled
* **Windows Firewall** active across Domain/Public/Private
* **Autoplay/Autorun** disabled
* **Automatic Updates** correctly configured

### **Services & Network Settings**

* Disabled: ICS, UPnP, SMB helpers, etc.
* Running: Event Log, Firewall, Defender
* **SMBv1** and **NetBIOS** disabled
* **IPv6** warnings (when misconfigured)
* Shared resources enumerated and validated

### **Advanced Checks**

* **Windows Defender** health & signature age
* **BitLocker** OS drive protection
* **Windows Update** last detection recency

---

## 📂 **Output Files**

| File           | Description                                                                         |
| -------------- | ----------------------------------------------------------------------------------- |
| **Log File**   | `C:\Logs\SecurityAudit\SecurityAudit_YYYYMMDD_HHMMSS.log` (full details)            |
| **CSV Report** | `C:\Logs\SecurityAudit\SecurityAudit_YYYYMMDD_HHMMSS.csv` (failed & warning checks) |

> To export all results (not just fails/warnings), toggle `$IncludeAllResults = $true` inside the script.

---

## 🔧 **How It Works**

| Component                          | Method                                                                         |
| ---------------------------------- | ------------------------------------------------------------------------------ |
| **Local Security Policy**          | Uses `secedit` to export policy data and parse values.                         |
| **Audit Policy**                   | Executes `auditpol /get /category:* /r` for inclusion checks.                  |
| **Services & Registry**            | Reads via native cmdlets and registry paths.                                   |
| **Defender / BitLocker / Updates** | Pulls via `Get-MpComputerStatus`, `Get-BitLockerVolume`, and registry queries. |
| **Scoring**                        | `ComplianceScore = (Passed / Total) * 100`, rounded to 2 decimals.             |

---

## 🛠️ **RMM Deployment Tips**

* Always run as **System or Admin**.
* Compatible with: **Gorelo**, **NinjaOne**, **Datto**, **Atera**, **Kaseya**, etc.
* Generates output locally; **no external dependencies or network calls**.

Example RMM execution:

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\script.ps1
```

---

## 🔒 **Security & Compliance Notes**

* **Read-Only Audit:** Makes **no changes** to the system.
* **Requires Elevation:** Some checks (BitLocker, Defender) need admin rights.
* **Safe for Offline Use:** No internet dependency post-download.
* **Data Ownership:** Logs remain on the host; no upload or telemetry.

---

## 🚑 **Troubleshooting**

| Symptom                  | Likely Cause                       | Resolution                   |
| ------------------------ | ---------------------------------- | ---------------------------- |
| Access Denied errors     | Not run as Administrator           | Relaunch elevated PowerShell |
| Missing Defender Data    | Defender not installed or disabled | Verify AV configuration      |
| BitLocker status unknown | No TPM or unsupported SKU          | Review encryption method     |
| Auditpol parsing errors  | Localized OS (non-English)         | Adjust property name mapping |

---

## 🔍 **Roadmap / Upcoming Improvements**

* ✅ **JSON Output** for SIEM ingestion
* ✅ **HTML Dashboard** for visual summaries (opt-in)
* ✅ **Remediation Mode** with safe defaults and rollback
* ✅ **Baseline Mapping** (CIS/NIST IDs per check)
* ✅ **Exclusion Profile** to honor justifications (e.g., WSUS, Smart Card)
* ✅ **Central Aggregation** script for fleet summaries
* ✅ **Language Localization** support for `auditpol`

> Contributions welcome! Submit pull requests or open issues to suggest new baseline checks or RMM integrations.

---

## 🔗 **License**

Licensed under the **MIT License**. You are free to use, modify, and distribute with attribution.

---

## 👤 **Author**

**Ulises Paiz (Coach40oz / Ghosxt Labs)**
Founder, Ghosxt IT Services — *Managed Security & Infrastructure Engineering*
🌐 [ghosxt.com](https://ghosxt.com)

---

## 🔒 **Repository Info**

| Name                    | Value                                                                                                                                                                                                                                  |      |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- |
| **Repo**                | [Windows-SecurityBaselineAuditor](https://github.com/Coach40oz/Windows-SecurityBaselineAuditor)                                                                                                                                        |      |
| **Script**              | `script.ps1`                                                                                                                                                                                                                           |      |
| **Raw URL (One-Liner)** | `iwr [https://raw.githubusercontent.com/Coach40oz/Windows-SecurityBaselineAuditor/refs/heads/main/script.ps1](https://raw.githubusercontent.com/Coach40oz/Windows-SecurityBaselineAuditor/refs/heads/main/script.ps1) -UseBasicParsing | iex` |

---
