# 🗂️ UserFolderMigrator

> **Enterprise-grade Windows user shell folder migration, full profile backup/restore, and redirect management — with live progress bars, HTML reporting, multi-user support, and a plugin system.**

![PowerShell](https://img.shields.io/badge/PowerShell-7.0%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-informational?logo=windows)
![Version](https://img.shields.io/badge/Version-7.5.0-success)
![Plugins](https://img.shields.io/badge/Plugins-10%20included-blueviolet)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Requires Admin](https://img.shields.io/badge/Requires-Administrator-red)
![Status](https://img.shields.io/badge/Status-Initial%20Public%20Release-orange)

> **🚧 Initial Public Release** — Core migration scenarios are thoroughly tested and work reliably. Several edge cases (domain environments, exotic storage configurations, cross-architecture restores) have not been explicitly tested. See [Known Untested Edge Cases](#️-known-untested-edge-cases) before deploying in production. [Feedback welcome](#-feedback).

---

## 📋 Table of Contents

- [Overview](#-overview)
- [🎯 Use Cases — Who Is This For?](#-use-cases--who-is-this-for)
- [⚔️ How It Compares to Other Tools](#️-how-it-compares-to-other-tools)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Modes of Operation](#-modes-of-operation)
- [Quick Start Examples](#-quick-start-examples)
- [All Parameters](#-all-parameters)
  - [Mode & Destination](#mode--destination)
  - [Folder Selection](#folder-selection)
  - [Copy & Robocopy Options](#copy--robocopy-options)
  - [Verification & Integrity](#verification--integrity)
  - [VSS Options](#vss-options)
  - [Parallelism & Performance](#parallelism--performance)
  - [Restore Profile Options](#restore-profile-options)
  - [Full Profile Backup Options](#full-profile-backup-options)
  - [Enterprise & Notification](#enterprise--notification)
  - [Safety & Pilot](#safety--pilot)
  - [Network Options](#network-options)
  - [Scheduled Task Registration](#scheduled-task-registration)
  - [Universal Flags](#universal-flags)
- [Output & Reports](#-output--reports)
- [Plugin System](#-plugin-system)
  - [Hook Stages](#available-hook-stages)
  - [Included Plugins](#included-plugins)
  - [DeclareInputs Convention](#the-_declareinputs-convention)
  - [Plugin Development Guide](PLUGIN_DEVELOPMENT.md)
- [Script Signing Enforcement](#-script-signing-enforcement)
- [Offline / Air-Gapped Usage](#-offline--air-gapped-usage)
- [Troubleshooting](#-troubleshooting)
- [Security Considerations](#-security-considerations)
- [⚠️ Known Untested Edge Cases](#️-known-untested-edge-cases)
- [💬 Feedback](#-feedback)
- [License](#-license)

---

## 🔍 Overview

**UserFolderMigrator** is a production-ready PowerShell 7 script designed for IT administrators, power users, and enterprise environments. It handles the complete lifecycle of Windows shell folder management:

| Capability | Description |
|---|---|
| **Shell Folder Migration** | Moves `Desktop`, `Documents`, `Downloads`, `Pictures`, `Music`, `Videos`, and more to a new drive/location, updating registry and optionally cleaning source |
| **Full Profile Backup** | Clones entire `C:\Users\<user>` for disaster recovery, including AppData, Wi-Fi profiles, printers, scheduled tasks, mapped drives, and WSL distros |
| **Profile Restore** | 8-phase restore pipeline: files → registry → ACLs → Wi-Fi → mapped drives → scheduled tasks → printers → WSL distros |
| **Registry Redirect** | Updates shell folder registry keys to point at existing data without copying |
| **Restore Defaults** | Resets all shell folders back to Windows defaults |
| **Repair Transactions** | Fixes partially-completed migrations with resume/checkpoint support |
| **Report Only** | Read-only scan that generates HTML + JSON reports without making changes |

### Key Highlights

- ✅ **Multi-user support** — migrate one user or all local users in a single run
- ✅ **Live per-file progress bars** — real-time robocopy progress in the console
- ✅ **HTML + JSON reports** — color-coded migration summary saved to disk
- ✅ **Checksum verification** — MD5 / SHA1 / SHA256 integrity checks post-copy
- ✅ **VSS integration** — Volume Shadow Copy for locked/in-use files
- ✅ **OneDrive KFM awareness** — detects and optionally removes Known Folder Move policies before migration
- ✅ **Checkpoint / resume** — survive interruptions; pick up where you left off
- ✅ **Plugin system** — extend behavior with `.psm1` hooks at every pipeline stage
- ✅ **Dry-run mode** — simulate any operation without touching the filesystem
- ✅ **Enterprise notifications** — SMTP email (Basic / OAuth2 / Certificate / Secret Vault) and Microsoft Teams webhook
- ✅ **Syslog support** — forward events to a remote syslog server
- ✅ **Unattended/automation-ready** — full `-Unattended` mode for SCCM, Intune, or scheduled tasks
- ✅ **Authenticode signing enforcement** — optional production hardening via environment variable

---

## 🎯 Use Cases — Who Is This For?

| Persona | Scenario | Key Flags |
|---|---|---|
| 🏠 **Home user** | C: drive is full; move Documents, Downloads, Desktop to a second drive or external | `-Mode Migrate -Destination "D:\Data"` |
| 🏠 **Home user** | Reinstalling Windows; need a full profile backup first | `-Mode FullProfileBackup -Destination "E:\Backup"` |
| 💼 **IT admin** | Migrate all users on a shared workstation before a storage upgrade, in one command | `-Mode Migrate -AllUsers` |
| 💼 **IT admin** | Shell folders are already on D: but registry still points to C: after a manual move | `-Mode RedirectAndClean -Destination "D:\Data"` |
| 🔁 **Disaster recovery** | Restore a user's full profile to a replacement machine in one operation | `-Mode RestoreProfile -Source "E:\Backup\User"` |
| 🏢 **MSP / consultant** | Free USMT alternative for SMB clients — no Windows ADK installation required | `-Unattended -NotificationEmail admin@company.com` |
| ⚙️ **Intune / SCCM engineer** | Deploy shell folder migration silently with exit codes for success/failure reporting | `-Unattended -Force` + check `$LASTEXITCODE` |
| 🧪 **Home lab** | Back up entire profile including WSL distros, printers, Wi-Fi before OS reinstall | `-Mode FullProfileBackup -Destination "E:\Lab"` |
| 🧪 **Home lab** | Test a migration safely before committing | `-DryRun` then `-ValidateOnly` then real run |
| 🔌 **Developer / IT engineer** | Extend migration behavior with custom logic at any pipeline stage | Drop a `.psm1` in `plugins\` — see `PLUGIN_DEVELOPMENT.md` |
| 🏢 **Enterprise** | Enforce BitLocker on destination, sign manifests, route logs to SIEM via syslog | `-BitLockerRequired -HmacSecret -EnableSyslog` |
| 🔄 **Ongoing sync** | Keep shell folders mirrored to a NAS after migration | `-CreateSyncTask` registers a daily robocopy scheduled task |

---

## ⚔️ How It Compares to Other Tools

No tool is right for every situation. This comparison is honest about both strengths and weaknesses.

### Tools Compared

| Tool | Type | Cost |
|---|---|---|
| **USMT** (Microsoft) | Enterprise CLI — part of Windows ADK | Free but requires ADK install |
| **Laplink PCmover** | GUI migration wizard | ~$30–60 one-time |
| **EaseUS Todo PCTrans** | GUI migration wizard | ~$60–90/year subscription |
| **Bvckup 2** | Real-time folder sync engine | ~$20 one-time |
| **FolderMove** | Simple shell folder redirect utility | Free |
| **Manual robocopy scripts** | DIY — whatever you write yourself | Free |

### Feature Comparison

| Feature | UFM | USMT | PCmover | EaseUS | Bvckup 2 | FolderMove |
|---|---|---|---|---|---|---|
| Shell folder migration (registry-aware) | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| No external software install required | ✅ | ❌ ADK needed | ❌ installer | ❌ installer | ❌ installer | ✅ |
| Migrate all users in one command | ✅ | ⚠️ complex XML | ❌ | ❌ | ❌ | ❌ |
| OneDrive KFM detection + auto-fix | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Full 8-phase profile restore | ✅ | ⚠️ partial | ⚠️ partial | ⚠️ partial | ❌ | ❌ |
| WSL distro backup + restore | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Printer + driver backup + restore | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| SHA256 checksum verification | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Volume Shadow Copy (VSS) | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Dry run / full simulation mode | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Checkpoint / resume after interruption | ✅ | ✅ | ❌ | ❌ | N/A | ❌ |
| Plugin / extensibility system | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SMTP + Teams webhook notifications | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Syslog / SIEM integration | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Script signing enforcement | ✅ | N/A | N/A | N/A | N/A | N/A |
| Bandwidth throttle | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Unattended / RMM-ready (exit codes) | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Offline / air-gapped operation | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| Guided interactive menu (no parameters) | ✅ | ❌ | ✅ GUI | ✅ GUI | ❌ | ✅ GUI |
| **Cost** | **Free** | **Free** | **$30–60** | **$60–90/yr** | **$20** | **Free** |

### Where UFM Has a Clear Edge

**OneDrive KFM awareness** — no other free tool detects and resolves Known Folder Move policy locks. This is the single most common reason shell folder migrations silently break on modern Windows 10/11.

**End-to-end integrity** — USMT copies files and moves on. UFM copies, verifies SHA256 checksums, test-restores a sample, and saves a signed manifest so you know the data arrived intact.

**8-phase RestoreProfile** — USMT can move files and some registry, but not WSL distros, printers with driver fallback, scheduled task XML, mapped drives, and Wi-Fi profiles all in a single automated pipeline.

**Extensibility** — the plugin system lets teams hook into any stage (pre-flight, per-user, per-folder, post-session) with custom `.psm1` files and zero changes to the main script.

**True unattended mode** — PCmover and EaseUS require a human at the screen. UFM is safe for SCCM, Intune, and RMM deployment with structured exit codes, email/Teams notifications, and pilot-user gating before a full batch.

### Where UFM Has Weaknesses

| Weakness | Impact |
|---|---|
| Requires PowerShell 7 | Machines still on PS 5.1 need pwsh.exe installed first |
| No GUI for main script | Higher barrier for non-technical users — mitigated by `UFM_Interactive.ps1` |
| 11,000+ line single-file script | Harder to audit or contribute to than a modular codebase |
| Windows only | No Linux or macOS equivalent by design |
| No true block-level incremental sync | `-IncrementalBackup` uses robocopy `/XO` (date-based), not delta/block-level like Bvckup 2 |
| Printer restore is architecture-dependent | `.printerExport` restore fails if source and target OS architecture differ (x86 ↔ x64) |
| Several edge cases untested | Domain roaming profiles, Azure AD-joined machines, ReFS volumes — see [Known Untested Edge Cases](#️-known-untested-edge-cases) |

### When to Use Something Else

| Situation | Better Choice |
|---|---|
| Migrating an entire PC (applications + OS settings + files) to a new machine | **PCmover** or **USMT** — they handle application migration; UFM does not |
| You need a real-time continuous sync engine | **Bvckup 2** — purpose-built block-level sync with a proper scheduler |
| Large enterprise domain deployment (>500 users, AD-managed) | **USMT** via MDT/SCCM — battle-tested at that scale with Microsoft support |
| You just need to redirect one folder with a GUI | **FolderMove** — simpler tool for a simpler job |

---

## ⚙️ Requirements

| Requirement | Minimum |
|---|---|
| PowerShell | **7.0 or later** |
| Windows | Windows 10 / Server 2016 or later |
| Privileges | **Run as Administrator** |
| Tools | `robocopy.exe` (built into Windows) |
| Optional | `wsl.exe` (for WSL distro backup/restore) |
| Optional | `sdelete.exe` (for `-SecureWipeSource`) |
| Optional | `accesschk.exe` (for ACL auditing) |

> **Note:** The script will auto-install required PowerShell modules from the PSGallery on first run. Use `-OfflineMode` to skip module downloads in air-gapped environments.

---

## 📦 Installation

```powershell
# 1. Clone or download the script
git clone https://github.com/YourUsername/UserFolderMigrator.git
cd UserFolderMigrator

# 2. (Optional) Create plugin folder
mkdir plugins

# 3. Run as Administrator in PowerShell 7+
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\UserData"
```

> The script requires **PowerShell 7+**. To check your version:
> ```powershell
> $PSVersionTable.PSVersion
> ```

---

## 🚀 Modes of Operation

| Mode | Switch / `-Mode` Value | Description |
|---|---|---|
| **Migrate** | `-Mode Migrate` | Copy shell folders to a new location, update registry, optionally delete source |
| **RedirectAndClean** | `-Mode RedirectAndClean` | Update registry only — no file copy. Data must already exist at destination |
| **RestoreDefaults** | `-Mode RestoreDefaults` | Reset shell folder paths back to Windows defaults (`C:\Users\<user>\...`) |
| **FullProfileBackup** | `-Mode FullProfileBackup` | Full `C:\Users\<user>` clone including supplemental exports (Wi-Fi, printers, tasks, WSL) |
| **RestoreProfile** | `-Mode RestoreProfile` | 8-phase restore from a `FullProfileBackup` archive |
| **RepairTransactions** | `-Mode RepairTransactions` | Resume/fix a partially-completed migration using checkpoint file |
| **Report Only** | `-ReportOnly` | Read-only scan + HTML/JSON report, zero changes |
| **Interactive** | *(no mode flag)* | Guided interactive menu — prompts for all options at runtime |

---

## ⚡ Quick Start Examples

### Migrate current user's folders to D:\Data
```powershell
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Data"
```

### Migrate all local users to a network share
```powershell
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "\\NAS01\Profiles" -AllUsers
```

### Dry run — simulate migration without changes
```powershell
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Data" -DryRun
```

### Migrate only Documents and Desktop
```powershell
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Data" -Folders Documents, Desktop
```

### Full profile backup for disaster recovery
```powershell
.\UserFolderMigrator.ps1 -Mode FullProfileBackup -Destination "E:\Backups"
```

### Restore a profile from backup
```powershell
.\UserFolderMigrator.ps1 -Mode RestoreProfile -Source "E:\Backups\JohnDoe_20250101" -DestinationProfile "C:\Users\JohnDoe"
```

### Redirect registry to existing data (no copy)
```powershell
.\UserFolderMigrator.ps1 -Mode RedirectAndClean -Destination "D:\Data"
```

### Restore all users to Windows defaults with free-space check
```powershell
.\UserFolderMigrator.ps1 -Mode RestoreDefaults -AllUsers
```

### Unattended migration with Teams notification
```powershell
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Data" -AllUsers -Unattended `
    -NotificationTeamsWebhook "https://outlook.office.com/webhook/..."
```

### Register as a weekly scheduled task
```powershell
.\UserFolderMigrator.ps1 -RegisterTask -TaskTrigger Weekly -TaskDay Sunday -TaskTime "22:00"
```

---

## 📐 All Parameters

### Mode & Destination

| Parameter | Type | Description |
|---|---|---|
| `-Mode` | String | Operation mode. One of: `Migrate`, `RedirectAndClean`, `RestoreDefaults`, `FullProfileBackup`, `RestoreProfile`, `RepairTransactions` |
| `-Destination` | String | Target root path for migration or backup (local path or UNC share) |
| `-Source` | String | Source backup root for `-Mode RestoreProfile` |
| `-DestinationProfile` | String | Local profile path to restore into (e.g. `C:\Users\JohnDoe`) |

### Folder Selection

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Folders` | String[] | `All` | Shell folders to include. Valid values: `Desktop`, `Documents`, `Downloads`, `Music`, `Pictures`, `Videos`, `Favorites`, `Contacts`, `Links`, `SavedGames`, `Searches`, `All` |

### Copy & Robocopy Options

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-RobocopyThreads` | Int (0–128) | `0` (auto) | Number of robocopy `/MT` threads. `0` = auto-tuned |
| `-RobocopyRetries` | Int (1–30) | `3` | Number of retries on failed file copy |
| `-RobocopyWait` | Int (1–120) | `5` | Wait time (seconds) between retries |
| `-UseRobocopyZ` | Switch | — | Enable `/Z` restartable mode (slower but resumable per-file) |
| `-BandwidthLimitMbps` | Int (0–10000) | `0` | Throttle copy speed. `0` = unlimited |
| `-Exclude` | String[] | — | Patterns to exclude from copy |
| `-ExcludeFile` | String | — | Path to a text file listing additional exclusion patterns |
| `-DisableAutoExclusions` | Switch | — | Disable built-in smart exclusions (temp files, recycle bin, etc.) |
| `-WanOptimized` | Switch | — | Forces low thread count; auto-activates on links with RTT > 50 ms |
| `-KeepSource` | Switch | — | Do not delete source folders after successful migration |
| `-CreateSymlink` | Switch | — | Create a junction/symlink at the old location pointing to the new one |
| `-CreateSyncTask` | Switch | — | Register a scheduled task to keep source and destination in sync |

### Verification & Integrity

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-DisableChecksumVerify` | Switch | — | Skip post-copy checksum verification |
| `-ChecksumAlgorithm` | String | `SHA256` | Hash algorithm: `MD5`, `SHA1`, or `SHA256` |
| `-SkipTestRestore` | Switch | — | Skip the test-restore sample check after migration |
| `-TestRestoreSamplePct` | Int (1–20) | `10` | Percentage of files to test-restore as a verification sample |
| `-VerifyDestination` | Switch | — | Re-verify all destination files after copy completes |
| `-HmacSecret` | String | — | HMAC secret for manifest integrity signing |

### VSS Options

| Parameter | Type | Description |
|---|---|---|
| `-UseVSS` | Switch | Use Volume Shadow Copy Service to read locked/in-use files |
| `-DisableSmartVSS` | Switch | Disable automatic VSS activation heuristics |

### Parallelism & Performance

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-MaxParallel` | Int (1–32) | `1` | Number of shell folders to migrate in parallel |
| `-DisableAutoPerfTuning` | Switch | — | Disable automatic performance tuning (thread count, buffer size) |

### Restore Profile Options

| Parameter | Type | Description |
|---|---|---|
| `-SkipFileRestore` | Switch | Skip Phase 1 (file copy) during RestoreProfile |
| `-SkipRegistryRestore` | Switch | Skip Phase 2 (registry hive restore) |
| `-SkipAclRestore` | Switch | Skip Phase 3 (ACL/permission restore) |
| `-SkipWifiRestore` | Switch | Skip Phase 4 (Wi-Fi profile restore) |
| `-SkipDriveRestore` | Switch | Skip Phase 5 (mapped drive restore) |
| `-SkipTaskRestore` | Switch | Skip Phase 6 (scheduled task restore) |
| `-SkipPrinterRestore` | Switch | Skip Phase 7 (printer/driver restore) |
| `-SkipWslRestore` | Switch | Skip Phase 8 (WSL distro restore) |
| `-WslInstallRoot` | String | `C:\WSL` | Root directory for imported WSL distros |
| `-AutoEnableSystemProtection` | Switch | Auto-enable System Restore when running unattended |

### Full Profile Backup Options

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-MaxProfileSizeGB` | Int (0–10000) | `0` | Abort backup if profile exceeds this size. `0` = no limit |
| `-IncrementalBackup` | Switch | — | Only copy new/changed files since last backup run |
| `-SkipBackupManifest` | Switch | — | Do not generate the backup manifest JSON |
| `-SkipCloudOnlyCheck` | Switch | — | Skip OneDrive cloud-only file hydration check |
| `-HydrateOneDrive` | Switch | — | Force OneDrive to download all cloud-only files before backup |
| `-RollbackFullProfile` | Switch | — | Restore a full profile backup (alias for `-Mode RestoreProfile`) |
| `-SkipSupplementalExports` | Switch | — | Skip Wi-Fi, printer, task, drive, and WSL exports during backup |
| `-AutoCleanupCreds` | Switch | — | Remove leftover credential cache entries after backup |

### Enterprise & Notification

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-NotificationEmail` | String | — | Email address to send migration result report |
| `-SmtpServer` | String | — | SMTP relay hostname |
| `-SmtpPort` | Int | `0` (auto) | SMTP port (25/465/587 auto-detected if `0`) |
| `-SmtpFrom` | String | — | Sender address for notification emails |
| `-SmtpCredential` | PSCredential | — | SMTP credentials |
| `-SmtpAuthMode` | String | `Basic` | Auth mode: `Basic`, `OAuth2`, `Certificate`, `SecretVault`, `CredentialManager` |
| `-OAuthTenantId` | String | — | Azure AD tenant ID for OAuth2 SMTP auth |
| `-OAuthClientId` | String | — | App registration client ID |
| `-OAuthClientSecret` | String | — | Client secret (use `-OAuthCertThumbprint` for cert-based auth) |
| `-OAuthCertThumbprint` | String | — | Certificate thumbprint for OAuth2 client-cert auth |
| `-SecretVaultName` | String | — | Secret vault name (Microsoft.PowerShell.SecretManagement) |
| `-SecretName` | String | — | Secret name within the vault |
| `-SmtpMaxRetries` | Int (1–10) | `3` | Max SMTP send retries |
| `-SmtpRetryDelayBase` | Int (1–300) | `5` | Base delay (seconds) between SMTP retries (exponential backoff) |
| `-NotificationTeamsWebhook` | String | — | Microsoft Teams Incoming Webhook URL for completion notification |
| `-BitLockerRequired` | Switch | — | Abort if destination volume is not BitLocker-encrypted |
| `-EnableSyslog` | Switch | — | Forward events to a remote syslog server |
| `-SyslogServer` | String | — | Syslog server hostname or IP |
| `-MaxFailures` | Int (0–100) | `0` | Maximum allowed per-file failures before aborting. `0` = unlimited |

### Safety & Pilot

| Parameter | Type | Description |
|---|---|---|
| `-DryRun` | Switch | Simulate everything — no filesystem or registry changes |
| `-ValidateOnly` | Switch | Run pre-flight checks only; do not migrate |
| `-TestCompatibility` | Switch | Check environment compatibility and exit |
| `-PilotUser` | String | Run migration for a single named test user before applying `-AllUsers` |
| `-SkipLockedFileCheck` | Switch | Skip locked-file pre-flight scan |
| `-SkipAccessCheck` | Switch | Skip AccessChk permission audit |
| `-SkipJunctionScan` | Switch | Skip junction/reparse-point scan warning |
| `-SecureWipeSource` | Switch | Use SDelete for cryptographic deletion of source after migration |
| `-QuarantinePath` | String | Move failed/suspicious files here instead of aborting |
| `-QuarantineRetentionDays` | Int (0–3650) | Auto-delete quarantined files after this many days (`0` = keep forever) |
| `-RunSFCCheck` | Switch | Run `sfc /verifyonly` pre-flight (opt-in; takes 5–15 min) |

### Network Options

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-NetworkCredential` | PSCredential | — | Credentials for accessing UNC/network destination |
| `-NetworkTimeout` | Int (10–300) | `30` | Network path connection timeout (seconds) |

### Scheduled Task Registration

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-RegisterTask` | Switch | — | Register a Windows Scheduled Task for this script and exit |
| `-TaskName` | String | `UserFolderMigrator` | Name of the scheduled task |
| `-TaskTrigger` | String | `Weekly` | Trigger type: `Daily`, `Weekly`, `AtLogon` |
| `-TaskTime` | String | `22:00` | Time of day for the task trigger |
| `-TaskDay` | String | `Sunday` | Day of week for weekly trigger |
| `-TaskRunAs` | String | `SYSTEM` | Run task as this account |

### Universal Flags

| Parameter | Type | Description |
|---|---|---|
| `-AllUsers` | Switch | Apply operation to all local user profiles |
| `-TargetUsername` | String | Apply operation to a single specific username |
| `-Force` | Switch | Suppress confirmation prompts |
| `-Unattended` | Switch | Fully non-interactive mode — no prompts, all decisions auto-resolved |
| `-QuietMode` | Switch | Suppress console progress output |
| `-DryRun` | Switch | Simulate without making changes |
| `-ResetState` | Switch | Clear saved checkpoint/resume state before running |
| `-LogPath` | String | Custom path for the log file |
| `-ReportPath` | String | Custom path for the HTML/JSON report output |
| `-DisableHtmlReport` | Switch | Do not generate the HTML report |
| `-NoEventLog` | Switch | Do not write to the Windows Event Log |
| `-DisableRestorePoint` | Switch | Skip creating a System Restore point before migration |
| `-SkipGPOBlock` | Switch | Skip Group Policy pre-flight block check |
| `-SkipKFMBlock` | Switch | Skip OneDrive KFM policy block detection |
| `-ForceOneDrive` | Switch | Proceed even when OneDrive sync is active |
| `-DeployKFMPolicy` | Switch | Deploy OneDrive Known Folder Move ADMX registry keys |
| `-RemoveKFMPolicy` | Switch | Remove KFM policy keys to unlock shell folders before migration |
| `-KFMTenantId` | String | Azure AD Tenant GUID required by `-DeployKFMPolicy` |
| `-EnableCheckpoint` | Switch | Enable checkpoint/resume support |
| `-CheckpointFile` | String | Custom path for the checkpoint file |
| `-DisableResume` | Switch | Ignore existing checkpoint and start fresh |
| `-RollbackFile` | String | Path to a registry backup file for rollback |
| `-OfflineMode` | Switch | Skip PSGallery module installs; use pre-staged modules in `.\UFM_Modules\` |
| `-MaxRepairSizeGB` | Int (0–10000) | Profiles larger than this skip `takeown /r` to avoid multi-hour stalls. `0` = unlimited |
| `-SkipAutoPermissionFix` | Switch | Skip automatic permission repair |
| `-PassThru` | Switch | Return a result object to the pipeline (for scripting/automation) |

---

## 📊 Output & Reports

### Console Output
- Color-coded status messages (`Success` = green, `Warning` = yellow, `Error` = red)
- Live per-file robocopy progress bars during copy operations
- Section headers separating each migration phase

### Log File
- Written to `%TEMP%\UserFolderMigrator_<date>.log` by default
- Override with `-LogPath`

### HTML Report
- Self-contained color-coded HTML summary of all folders, users, and outcomes
- Includes file counts, sizes, duration, checksum results, and error details
- Override output path with `-ReportPath`
- Disable with `-DisableHtmlReport`

### JSON Report
- Machine-readable companion to the HTML report
- Suitable for ingestion by SIEM, monitoring, or automation pipelines

### Windows Event Log
- Events written to the **Application** log under source `UserFolderMigrator`
- Disable with `-NoEventLog`

### PassThru Object
- Use `-PassThru` to receive a structured result object in the pipeline:
```powershell
$result = .\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Data" -PassThru
$result.FailedFolders
```

---

## 🔌 Plugin System

UserFolderMigrator has a first-class plugin architecture. Drop any `UF_*.psm1` file into the `plugins\` subfolder and its hook functions are auto-loaded before the migration runs — **zero changes to the main script required**.

> 📄 **Full plugin development reference:** see [`PLUGIN_DEVELOPMENT.md`](PLUGIN_DEVELOPMENT.md)  
> This covers the complete `$Context` schema per stage, the `_DeclareInputs` convention, return value semantics, `Write-ErrorGuard` usage, conflict detection rules, the fallback shim pattern, manifest signing, and two complete plugin templates (minimal + full-featured).

---

### Available Hook Stages

| Stage Pattern | Fires When | Typical Use |
|---|---|---|
| `PreFlight_*` | Before any checks run | Disk health, AV verification, network stability |
| `PreMigration_*` | After checks pass, before migration loop | VSS rollback points, browser detection, start watchdog |
| `PreUser_*` | Before each user's folders are processed | Pre-create folder structure, set quotas |
| `PreFolder_*` | Before each shell folder is copied | Path conflict detection, queue reordering |
| `PostFolder_*` | After each shell folder is copied | EFS encryption, semantic file validation |
| `PostUser_*` | After all folders for a user complete | Browser profile copy, per-user helpdesk tickets |
| `PostMigration_*` | After all users complete | Diagnostics summary, audit upload, reports |
| `PostSession_*` | At the very end of the script | Stop watchdog, cleanup temp files, telemetry |
| `Rollback_*` | During rollback operations | VSS snapshot restore, registry conflict repair |

> Hook functions ending in `_DeclareInputs` are reserved for the input-collection system and are **never** dispatched as hooks — name them freely without conflict risk.

---

### Included Plugins

Ten production plugins ship with this repository, each following the same reference architecture:

| Plugin | Hook Stage(s) | What It Does |
|---|---|---|
| `UF_PreFlight.psm1` | `PreFlight` | SMART disk health (WMI), path conflict scan, network stability, AV detection |
| `UF_ConflictResolver.psm1` | `PreFolder` | Circular path detection, reserved name check (CON/NUL/COM1…), path length >240, case mismatches |
| `UF_PriorityQueue.psm1` | `PreFolder` | Reorders migration queue: Desktop/Documents first, Videos/Music last |
| `UF_Provisioning.psm1` | `PreUser` | Pre-creates destination folder trees; sets NTFS disk quotas via `fsutil quota` |
| `UF_Encryption.psm1` | `PreMigration` + `PostFolder` | Verifies BitLocker; applies EFS (`cipher /e`) to migrated folders |
| `UF_SemanticValidation.psm1` | `PostFolder` | Validates files by magic-byte detection + minimal read; catches silent corruption SHA256 misses |
| `UF_BrowserProfileMigrator.psm1` | `PreMigration` + `PostUser` + `PostMigration` | Migrates Chrome, Edge, Firefox, Brave, Opera, Vivaldi profiles with cache auto-exclusion |
| `UF_RollbackEnhanced.psm1` | `PreMigration` + `Rollback` | Creates VSS volume snapshots before migration; restores from snapshot on rollback |
| `UF_Troubleshooter.psm1` | `PostMigration` + `Rollback` | Detects stuck transactions, registry pointing to missing paths; auto-remediates if enabled |
| `UF_Watchdog.psm1` | `PreMigration` + `PostSession` | Background runspace that monitors script heartbeat; sends alerts via email/Teams/EventLog/Syslog if hung or crashed |

All plugins use the same architecture pattern — study any of them as a reference when building your own.

---

### The `_DeclareInputs` Convention

Plugins that need runtime parameters implement a `_DeclareInputs` function. The main script calls this before the hook fires and injects the collected values into `$Context`:

```powershell
function PostFolder_MyPlugin_DeclareInputs {
    return @(
        @{
            Key               = 'EnableMyFeature'
            Prompt            = 'Enable MyPlugin feature? (Y/N)'
            Type              = 'YesNo'        # YesNo | String | Int
            Default           = 'N'
            UnattendedDefault = 'N'            # Used when -Unattended is set
            Required          = $false
        }
    )
}
```

Plugins using this pattern: `UF_Provisioning` (QuotaGB), `UF_Encryption` (EnableEncryption, RequireBitLocker), `UF_SemanticValidation` (StopOnCorruption), `UF_Troubleshooter` (AutoRemediation), `UF_BrowserProfileMigrator` (BrowserMigrateCache, BrowserSkipIfRunning, BrowserList).

---

### Minimal Plugin Template

```powershell
#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function PostFolder_MyPlugin {
    param($Context)

    $folderName = [string]$Context.FolderName
    $destPath   = [string]$Context.DestPath
    $dryRun     = [bool]$Context.DryRun

    if (-not $destPath) { return $true }   # Non-fatal skip

    if ($dryRun) {
        Write-Status "  [DRY RUN] MyPlugin: would process $folderName" -Type "Info"
        return $true
    }

    try {
        # Your logic here
        Write-Status "  MyPlugin: $folderName done" -Type "Success"
        return $true     # Continue
    } catch {
        Write-Log "MyPlugin: error — $_" -Level "ERROR"
        return $false    # Abort this folder (not the whole migration)
    }
}

Export-ModuleMember -Function 'PostFolder_MyPlugin'
```

### Plugin Manifest (Signed Mode)

```powershell
.\New-PluginManifest.ps1
```

Creates `UF_Plugins.manifest.json` with SHA-256 hashes for every plugin. Without a manifest the loader runs in open mode with a one-time advisory. With a manifest, any plugin whose hash doesn't match is **blocked** entirely.

---

## 🔏 Script Signing Enforcement

For production deployments, enforce Authenticode signature verification:

```powershell
# Require valid signature (set before running the script)
$env:UFM_ENFORCE_SIGNING = '1'

# Sign the script with your code-signing certificate
Set-AuthenticodeSignature -FilePath '.\UserFolderMigrator.ps1' `
    -Certificate (Get-Item Cert:\CurrentUser\My\<thumbprint>)
```

When `UFM_ENFORCE_SIGNING=1` and the signature is missing or invalid, the script exits with code `126` and prints remediation instructions.

Leave the variable unset (or `=0`) in dev/test environments — no behavioral change.

---

## 🌐 Offline / Air-Gapped Usage

```powershell
# Pre-stage required modules in .\UFM_Modules\ then run:
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Data" -OfflineMode
```

With `-OfflineMode`, the script skips all `Install-Module` calls and loads modules exclusively from `.\UFM_Modules\` relative to the script directory.

---

## 🛠️ Troubleshooting

### Script won't start
- Ensure you are running **PowerShell 7.0+** (`pwsh.exe`), not Windows PowerShell 5.1 (`powershell.exe`)
- Ensure the console session is elevated (**Run as Administrator**)

### Robocopy exits with errors
- Check the log file for specific error codes
- Use `-RobocopyRetries 5` and `-RobocopyWait 15` for flaky network paths
- For high-latency links, add `-WanOptimized`

### OneDrive folders can't be moved
- Run with `-RemoveKFMPolicy` to clear KFM policy locks before migration
- Add `-ForceOneDrive` to bypass the OneDrive sync active warning

### Migration interrupted / incomplete
- Re-run the same command with `-EnableCheckpoint` to resume from the last successful point
- Use `-Mode RepairTransactions` to scan and fix a partially-completed migration

### Permission errors on destination
- Ensure the running account has **Full Control** on the destination path
- Use `-NetworkCredential` for UNC paths requiring alternate credentials
- Remove `-SkipAutoPermissionFix` if you previously disabled auto repair

### Modules fail to install (corporate proxy)
- Pre-stage modules in `.\UFM_Modules\` and run with `-OfflineMode`

### HTML report not opening correctly
- The report is self-contained — open with any modern browser
- If `-DisableHtmlReport` was used, check for the JSON report at the same path

---

## 🔐 Security Considerations

| Topic | Guidance |
|---|---|
| **Run as SYSTEM** | Scheduled task runs as SYSTEM by default. Scope permissions on destination via ACLs |
| **SMTP credentials** | Use `-SmtpAuthMode OAuth2` or `Certificate` instead of `Basic` in production |
| **Plugin trust** | Always generate and commit `UF_Plugins.manifest.json` in production environments |
| **Script signing** | Set `UFM_ENFORCE_SIGNING=1` as a machine-level environment variable in managed fleets |
| **Secure wipe** | Use `-SecureWipeSource` with SDelete for HIPAA/PCI-regulated data |
| **BitLocker** | Pass `-BitLockerRequired` to abort if the destination volume is unencrypted |
| **HMAC signing** | Use `-HmacSecret` to cryptographically sign migration manifests |

---

## ⚠️ Known Untested Edge Cases

This is an **initial public release**. The script performs reliably in normal operation across the scenarios it was built and tested for. The following edge cases have **not been explicitly tested** and may produce unexpected results. Proceed with extra caution — always run `-DryRun` first and have a backup.

### Multi-User & Domain Environments

| Scenario | Risk | Workaround |
|---|---|---|
| Roaming profiles (UNC-based `%USERPROFILE%`) | Registry hive load/unload timing may conflict | Test with `-TargetUsername` on one user first |
| Domain-joined machines with GPO-enforced folder redirection | GPO will re-redirect on next login, overriding migration | Coordinate with AD admin to update GPO before running |
| Mandatory profiles (read-only roaming) | Registry writes will fail silently | Not supported in mandatory profile environments |
| Azure AD-joined (AAD-only, no local SID) | SID resolution for multi-user mode untested | Test with current user only; skip `-AllUsers` |
| Home folders mapped via DFS namespace | UNC path normalisation may produce double-backslash paths | Verify destination paths in dry run output carefully |

### Storage & Volume Edge Cases

| Scenario | Risk | Workaround |
|---|---|---|
| Source and destination on the same physical drive (different partitions) | No known issue, but throughput collapses to sequential | Expect 50–70% slower than cross-drive |
| ReFS destination volume | `cipher /e` (EFS) is unsupported on ReFS — `UF_Encryption` plugin will fail gracefully | Disable `-EnableEncryption` or skip the plugin |
| Destination is a RAM disk | VSS cannot snapshot RAM disks | Do not use `-UseVSS` with RAM disk destinations |
| Folder path contains Unicode characters (non-Latin) | `robocopy` handles UTF-16 paths; `cipher.exe` array argument form used to avoid corruption | Monitor log for skipped files |
| OneDrive Files On-Demand stubs (cloud-only files) | robocopy copies the stub, not the content | Use `-HydrateOneDrive` to force download first |
| Destination is a mounted VHD/VHDX | Not tested; may work fine but unmounting mid-copy would corrupt | Not recommended without checkpoint enabled |
| Storage Spaces or RAID volumes as destination | No known issue; untested at scale (>500 GB) | Run with a small folder subset first |

### Plugin-Specific Edge Cases

| Plugin | Untested Scenario |
|---|---|
| `UF_Encryption` | EFS on folders already partially encrypted by another user's certificate |
| `UF_BrowserProfileMigrator` | Firefox with multiple profiles (non-default profile names) |
| `UF_RollbackEnhanced` | VSS rollback after the source volume has been reformatted |
| `UF_Watchdog` | Behaviour when `Write-ProgressBar` is not defined (non-standard PS host) |
| `UF_Provisioning` | NTFS quota enforcement on volumes where `fsutil quota` requires a service restart |
| `UF_SemanticValidation` | Files >2 GB — magic byte check reads the whole file header only, but `[File]::ReadAllBytes` will OOM on large files if validation mode changes |

### RestoreProfile Edge Cases

| Scenario | Risk |
|---|---|
| Restoring to a **different Windows version** (e.g. Win10 → Win11) | Registry hive structure differences may cause silent key mismatches |
| Printer restore across **different CPU architectures** (x86 ↔ x64) | Driver import will fail; manual install from `Drivers\` fallback required |
| WSL distro restore when **distro name already exists** | `wsl --import` will overwrite — no prompt in `-Unattended` mode |
| Restoring a profile while the **target user is logged in** | NTUSER.DAT hive cannot be loaded for registry restore phase |

### What Is Tested and Works Reliably

- ✅ Standard Migrate mode: single user, local → local (same or different drive)
- ✅ All-users migration on standalone (non-domain) Windows 10/11 machines
- ✅ Full profile backup and file-phase restore
- ✅ Dry run and ValidateOnly across all modes
- ✅ OneDrive KFM detection and removal
- ✅ ConflictResolver circular path detection
- ✅ PriorityQueue folder reordering
- ✅ Watchdog alert on script hang
- ✅ Interactive wrapper (UFM_Interactive.ps1) on Windows 11

> If you encounter a failure in any untested scenario, please [open an issue](../../issues) or use the [feedback form](#-feedback) with your log file (sanitize paths first).

---

## 💬 Feedback

This is an initial public release and community feedback directly shapes what gets fixed, improved, or added next.

### 📋 Structured Feedback Form (Preferred)

Please fill in the Google Form — it takes under 3 minutes and covers what worked, what failed, and what you'd like added:

> **[→ Open Feedback Form](https://forms.gle/YOUR_FORM_ID_HERE)**

The form asks:
- Which mode(s) you used
- Your Windows version and environment type (home / domain / Azure AD)
- Whether it worked, partially worked, or failed
- Which edge cases you hit (if any)
- Which plugins you used
- What you'd most like improved
- Optional: your email if you want a reply

> **Don't have time for the form?** A one-line GitHub Issue is equally welcome.

### 🐛 Bug Reports — GitHub Issues

[Open an Issue](../../issues/new) and include:

- The exact command you ran (sanitize any UNC paths or usernames)
- Your Windows version (`winver`) and PowerShell version (`$PSVersionTable.PSVersion`)
- The exit code the script returned
- The relevant section from the log file (`%TEMP%\UFM_<date>.log`)

### 📧 Email

Prefer email? Reach out directly:

> **your@email.com**  
> Subject line: `[UFM Feedback]` or `[UFM Bug]`

Include the same details as a bug report above. I read every message and reply when time allows.

### 💡 Feature Requests

Open an Issue with the label **enhancement** and describe:
- The scenario you're trying to solve
- What you expected the script to do
- Any workaround you're currently using

---



MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Test with `-DryRun` and `-ValidateOnly` before committing
4. If adding a plugin hook stage, update `Invoke-PluginHooks` and document here
5. Submit a pull request

> For bug reports, include the log file (sanitize any sensitive paths) and the exact command used.
