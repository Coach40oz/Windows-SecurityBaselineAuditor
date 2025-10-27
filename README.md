🔒 Windows Security Baseline Auditor

A PowerShell script that audits Windows Server and Workstation security posture against simplified best practices inspired by CIS, NIST, and Microsoft baselines.
Outputs colorized console status, timestamped logs, and an exportable CSV of failed/warning checks—ready for RMM deployment at scale.

✨ Highlights

Baseline Coverage: Account policies, local security policy (UAC, built-ins), audit policy, services, firewall, network stack (SMB1/NetBIOS/IPv6), Defender, BitLocker, Windows Update recency.

Clear Results: Pass / Warning / Fail with expected vs actual, severity, and remediation guidance.

RMM-Ready: Zero interactive prompts; logs + CSV stored under C:\Logs\SecurityAudit\….

Self-Contained: Creates its log directory, handles temp exports (secedit/auditpol), and cleans up.

Score at a Glance: Overall Compliance Score based on pass ratio.

✅ Compatibility

OS: Windows Server 2016+; Windows 10/11

PowerShell: Windows PowerShell 5.1 (built-in on supported OSes)

Rights: Run as Administrator (required for security policy export, services, registry reads)

🚀 Quick Start (one-liner)

Runs from GitHub Raw and immediately audits the local machine.

iwr https://raw.githubusercontent.com/Coach40oz/Windows-SecurityBaselineAuditor/refs/heads/main/script.ps1 -UseBasicParsing | iex


Tip (RMM): If your RMM requires an explicit bypass:

powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "iwr https://raw.githubusercontent.com/Coach40oz/Windows-SecurityBaselineAuditor/refs/heads/main/script.ps1 -UseBasicParsing | iex"

🧠 What It Checks (summary)

Account Policies

Password history, min/max age, min length, complexity

Lockout threshold, duration, and reset window

Local Security Policies

Built-in Administrator/Guest account status

Deny access from network for Guest

Local accounts Classic vs Guest-only model

UAC prompts (admins & standard users) and Admin Approval Mode

Audit Policies

Credential Validation, Logon, User Account Management

File System auditing configured where needed

Registry & Host Controls

Remote Registry service disabled

Windows Firewall enabled for Domain/Public/Private profiles

Autoplay/Autorun disabled

Automatic Updates state (policies & fallback)

Services

Expected disabled (e.g., ICS, UPnP, SMB helpers, etc.)

Expected running (Event Log, Firewall, Defender)

Network Settings

SMBv1 disabled

NetBIOS over TCP/IP disabled

IPv6 status (warn if enabled but not required)

Non-default network shares flagged

Advanced

Windows Defender real-time and signature age

BitLocker OS drive protection status

Windows Update last detection recency

📦 Output & Artifacts

Console: Colorized summary with Pass / Warning / Fail counts and Compliance Score.

Logs: C:\Logs\SecurityAudit\SecurityAudit_YYYYMMDD_HHMMSS.log

CSV: C:\Logs\SecurityAudit\SecurityAudit_YYYYMMDD_HHMMSS.csv
Columns: Category, CheckName, Description, Result, ExpectedValue, ActualValue, Severity, Recommendation, Reference

By default, the CSV includes only Warnings/Failures to focus remediation. Flip $IncludeAllResults = $true in the script to export everything.

🛠 How It Works (internals)

Local/Domain Context: Uses secedit to export local security policy and parses key values.

Audit Policy: Uses auditpol /get /category:* /r and inspects inclusion settings.

Services/Firewall/Registry: Native cmdlets + registry queries for deterministic reads.

Defender/BitLocker/Updates: Uses Get-MpComputerStatus, Get-BitLockerVolume, and Windows Update registry.

Scoring: ComplianceScore = Passed / Total * 100 (rounded to 2 decimals).

🧰 RMM Deployment Notes

Run As: System or Admin; must have local admin rights.

Network: No external downloads required; runs offline.

Exit Codes: Writes failures to log/CSV; the script itself is informational. If you want hard failure for CI/RMM, add an exit condition on $Results.Summary.FailedChecks.

Example RMM command line:

powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\script.ps1


Or directly via raw one-liner (above).

🔒 Security Notes

Read-only posture: The script does not change settings; it audits and recommends.

Least Privilege: Some queries require elevation; non-admin runs will show more “Warning/Fail” due to access limits.

Data at Rest: Logs and CSVs are local only (no exfil). Ensure C:\Logs\SecurityAudit fits your data retention policy.

🧯 Troubleshooting

Access Denied / Missing Data

Ensure elevated context (Admin). Some providers (e.g., BitLocker, Defender) need elevation.

Windows Defender Cmdlets Missing

On some Server SKUs, Defender components may be not installed/managed by a third-party AV. Script will warn and recommend verification.

BitLocker Status Unknown

If Get-BitLockerVolume fails, the script falls back to TPM presence as a Warning (not a Fail).

Auditpol CSV Parsing

Locale differences can alter headers; script expects default English column names. If localized, adjust the Subcategory/Inclusion Setting property names accordingly.

🗺️ Roadmap (in progress)

GPO Export Attachment: Bundle relevant secpol deltas or a pre-canned GPO backup for rapid remediation.

HTML/MD Report (optional): Static report artifact with filters and per-host diff (off by default to stay RMM-friendly).

Remediation Mode (opt-in): Toggle to automatically apply recommended fixes with safety-rails + rollback.

CIS Mapping Table: Enrich CSV with precise CIS benchmark versions and machine-readable control IDs.

Exclusions Profile: Allow org-specific justifications (e.g., Smart Card required) to suppress noise in score.

Centralized Upload Hook: Optional connector (e.g., to an SMB/HTTPS drop) for fleet aggregation.

Intune/Defender for Endpoint Signals: Optional enrichment when available.

Localization: Header mapping for non-EN auditpol outputs.

Have a feature you need for MSP scale? Open an Issue with your environment constraints and we’ll prioritize.

📜 License

MIT. See LICENSE.

🤝 Contributing

PRs welcome:

Keep everything RMM-safe (non-interactive, no external deps).

Prefer native cmdlets before external binaries.

Add tests or at least a sample run output for new checks.

Don’t default to remediation—keep audit behavior as default.

🧾 About

Windows Security Baseline Auditor by Ghosxt Labs (Coach40oz).
Purpose-built for MSP fleet hygiene: quick posture read, actionable CSV, no surprises.
If you deploy this with Gorelo, Kaseya, NinjaOne, Atera, or Intune—share notes so we can optimize defaults.
