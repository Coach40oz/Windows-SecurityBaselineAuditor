# Windows-SecurityBaselineAuditor
PowerShell-based security auditing script that evaluates Windows systems against common hardening baselines — including **CIS**, **NIST**, and **Microsoft Security** recommendations.  


# Windows Security Baseline Auditor

A PowerShell-based security auditing script that evaluates Windows systems against common hardening baselines — including **CIS**, **NIST**, and **Microsoft Security** recommendations.  
Built for MSP and enterprise environments, the script performs comprehensive checks on account policies, registry configurations, firewall status, services, and security controls to identify gaps and summarize compliance.

---

## 🔍 Overview

This script performs a series of checks across multiple security domains:

| Category | Description |
|-----------|--------------|
| **Account Policies** | Password age, complexity, history, and lockout policies |
| **Local Policies** | Administrator & Guest account status, UAC settings, local rights |
| **Audit Policies** | Credential validation, logon events, user management, object access |
| **Registry Settings** | Firewall profiles, automatic updates, autoplay settings |
| **Services** | Ensures critical services are running and insecure ones are disabled |
| **Network Settings** | IPv6, SMBv1, NetBIOS, and shared resources validation |
| **Advanced Settings** | Defender status, BitLocker encryption, Windows Update checks |

All checks are logged, summarized, and optionally exported to CSV for integration with RMM or SIEM tools.

---

## 🧩 Key Features

- 🔒 **CIS-aligned** checks for both workstations and servers  
- ⚙️ **Local Policy & Registry** inspection without domain dependencies  
- 🧾 **Comprehensive CSV reports** for downstream processing  
- 🧠 **Auto-scoring engine** with pass/fail/warning categories  
- 🧰 **Lightweight, non-destructive** — ideal for RMM execution  
- 💬 **Readable log output** with color-coded summaries  

---

## 🧠 How It Works

1. The script gathers system information (OS, IP, uptime, etc.)  
2. Exports local security policy using `secedit` for granular review  
3. Evaluates registry, services, and firewall configuration  
4. Scores compliance and generates both console and log summaries  
5. Optionally exports a CSV with all failed/warning checks

---

## 🪟 Requirements

| Requirement | Minimum Version |
|--------------|----------------|
| **Windows** | 10 / Server 2016 and newer |
| **PowerShell** | 5.1 or later |
| **Privileges** | Administrator rights |
| **Modules (optional)** | `Defender`, `BitLocker`, `NetAdapter` |

---

## 🏃‍♂️ Usage

### Run Locally

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\SecurityBaselineAuditor.ps1
