# ⚠️ DISCLAIMER

## UserFolderMigrator — Legal Notice & Limitation of Liability

**Version:** 7.5.0  
**Last Updated:** 2025

---

### 1. No Warranty

THIS SOFTWARE IS PROVIDED **"AS IS"**, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

The author(s) make no representations or warranties regarding:
- The accuracy, completeness, or reliability of the script
- Its fitness for any particular purpose or environment
- Its compatibility with your specific Windows configuration, Active Directory setup, OneDrive sync state, or third-party software

---

### 2. Limitation of Liability

**IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY:**

- Loss of data, files, or user profiles
- System instability, boot failure, or registry corruption
- Business interruption or productivity loss
- Damage to hardware or storage media
- Loss resulting from unauthorized access to migrated data

**This includes but is not limited to:**
- Data loss caused by interrupted migrations
- Registry changes that cannot be reversed
- Conflicts with Group Policy, OneDrive Known Folder Move (KFM), or enterprise MDM policies
- Failures on encrypted volumes (BitLocker, VeraCrypt, etc.)
- Data loss on NAS/network destinations due to network interruptions

---

### 3. Administrator Privilege Warning

This script **requires and runs with Administrator (SYSTEM-level) privileges**. It performs:

- **Registry writes** to `HKCU`, `HKLM`, and loaded offline hives (`NTUSER.DAT`)
- **File system operations** including moving, deleting, and wiping user data
- **Driver and printer restoration** that modifies system-level components
- **VSS snapshot creation** and deletion
- **Scheduled task registration** under the SYSTEM account
- **WSL distro import/export** that modifies the WSL subsystem

Misuse, incorrect parameters, or running in the wrong environment can cause **irreversible data loss or system misconfiguration**.

---

### 4. You Are Responsible For

Before running this script, you accept full responsibility for:

- ✅ Taking a **complete backup** of all affected user profiles
- ✅ Testing in a **non-production VM** before deploying to real machines
- ✅ Running `-DryRun` first to validate behavior
- ✅ Verifying sufficient **free disk space** at the destination
- ✅ Ensuring **OneDrive sync is paused or disabled** before migration
- ✅ Confirming that **no Group Policy or MDM policy** conflicts with shell folder redirection
- ✅ Verifying **destination encryption** meets your organization's security policy
- ✅ Reading and understanding the **full parameter reference** before use

---

### 5. Not a Substitute for Professional IT Support

This script is a **tool**, not a managed service. In enterprise environments:

- Test with `-PilotUser` before deploying to all users
- Use `-ValidateOnly` to audit readiness before a maintenance window
- Engage qualified IT personnel for large-scale or regulated deployments
- Do not use in environments where compliance (HIPAA, PCI-DSS, SOX, ISO 27001) requires change-controlled procedures without first completing a formal risk assessment

---

### 6. Third-Party Components

This script calls the following system tools. Their respective licenses and terms apply:

| Tool | Source | Purpose |
|---|---|---|
| `robocopy.exe` | Microsoft Windows | File copy engine |
| `cmdkey.exe` | Microsoft Windows | Credential storage |
| `schtasks.exe` | Microsoft Windows | Scheduled task registration |
| `wsl.exe` | Microsoft Windows | WSL distro import/export |
| `sfc.exe` | Microsoft Windows | Optional system file check |
| `sdelete.exe` | Sysinternals (optional) | Secure file wipe |
| `accesschk.exe` | Sysinternals (optional) | ACL audit |

---

### 7. Open Source License

This script is released under the **MIT License**. You are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of this software under the terms of that license.

The MIT License does not grant any warranty or liability protection beyond what is stated in this disclaimer.

---

### 8. Acceptance

**By running this script in any mode (including `-DryRun`), you acknowledge that you have read, understood, and accepted this disclaimer in full.**

If you do not agree with these terms, do not execute the script.

---

*For questions, issues, or contributions, open a GitHub Issue or Pull Request.*
