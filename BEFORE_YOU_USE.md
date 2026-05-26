# 🧪 BEFORE YOU USE — Pre-Flight Warning & Test Checklist

> **READ THIS BEFORE RUNNING ANYTHING.**  
> This checklist exists to prevent the most common causes of data loss and failed migrations. It takes 5 minutes. Skipping it can cost you hours — or your data.

---

## 🚨 Hard Stops — Do NOT Proceed If Any of These Are True

| Check | Why It Matters |
|---|---|
| ❌ You have **no backup** of the user profile | A failed migration mid-copy can leave files split across source and destination with neither intact |
| ❌ **OneDrive sync is running** and KFM is enabled | OneDrive will revert your registry changes silently, making the migration appear to succeed while actually breaking shell paths |
| ❌ You are running **Windows PowerShell 5.1** (`powershell.exe`) | The script requires `pwsh.exe` (PowerShell 7). Running in 5.1 will fail at the `#Requires` block |
| ❌ You are **not running as Administrator** | Registry writes to other users' hives and VSS operations will fail |
| ❌ The destination drive has **less free space** than the total size of folders being migrated | Robocopy will fail mid-copy; partial copies may corrupt the folder state |
| ❌ A **Group Policy** redirects shell folders to a different path | The script will detect this but proceeding may cause a GPO/script conflict on next login |
| ❌ You are migrating a **live, logged-in user's profile** with VSS disabled | Locked files (Outlook PST, browser databases) will be skipped or fail |
| ❌ The destination is **not encrypted** and your policy requires BitLocker | Use `-BitLockerRequired` to enforce this automatically |

---

## ✅ Step-by-Step Pre-Flight Checklist

### Step 1 — Verify PowerShell Version
```powershell
$PSVersionTable.PSVersion
# Must show Major: 7 or higher
# If not: download from https://github.com/PowerShell/PowerShell/releases
```

### Step 2 — Verify You Are Running as Administrator
```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# Must return: True
```

### Step 3 — Unblock the Script
```powershell
# Run once after downloading from GitHub
Unblock-File .\UserFolderMigrator.ps1
Unblock-File .\UFM_Interactive.ps1

# Verify (should return empty output after unblocking):
Get-Item .\UserFolderMigrator.ps1 | Select-Object -ExpandProperty Stream
```

### Step 4 — Check Free Space at Destination
```powershell
# Check how much space your folders will need
Get-ChildItem "$env:USERPROFILE\Documents","$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop" -Recurse -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum |
    Select-Object @{N='SizeGB';E={[Math]::Round($_.Sum/1GB,2)}}

# Check available space on destination
Get-PSDrive D | Select-Object Used,Free   # Replace D with your target drive letter
```

### Step 5 — Pause OneDrive
```powershell
# Pause OneDrive sync before migration (replace path if needed)
& "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe" /pause
# Or: right-click OneDrive tray icon → Pause syncing → 24 hours
```

### Step 6 — Run Compatibility Check
```powershell
.\UserFolderMigrator.ps1 -TestCompatibility
# This exits immediately after checking OS version, PS version,
# robocopy presence, and free space. No files touched.
```

### Step 7 — Run Validate Only (No Changes)
```powershell
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\YourPath" -ValidateOnly
# Runs ALL pre-flight checks (GPO, KFM, OneDrive, BitLocker, paths)
# and exits. Zero files or registry keys touched.
```

### Step 8 — Run a Dry Run
```powershell
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\YourPath" -DryRun
# Simulates the COMPLETE migration including robocopy output.
# No files copied. No registry changes. Read the output carefully.
```

### Step 9 — Check the Dry Run Output
Look for these in the dry run output:

| Symbol | Meaning | Action |
|---|---|---|
| `[DRY RUN]` | Simulated action | Normal — this is what will happen for real |
| `[WARNING]` | Potential issue | Read carefully; may not be a blocker |
| `[BLOCKED]` | OneDrive KFM or GPO lock | Must resolve before proceeding |
| `[ERROR]` | Path or permission problem | Must fix before proceeding |
| `Locked files detected` | Files in use | Close applications or use `-UseVSS` |

### Step 10 — Create a System Restore Point (Manual Safety Net)
```powershell
# Create a restore point before running the real migration
Checkpoint-Computer -Description "Before UFM Migration $(Get-Date -Format 'yyyyMMdd')" -RestorePointType MODIFY_SETTINGS
```

---

## 🧪 Recommended Test Order (First Time Users)

```
1. VM Test  →  2. DryRun on real machine  →  3. ValidateOnly  →  4. PilotUser  →  5. Real run
```

### Test in a VM First
- Clone your machine to a VM (Hyper-V, VMware, VirtualBox)
- Run the full migration there first
- Confirm Explorer shows correct paths
- Confirm new files save to the destination
- Sign out and back in; confirm paths persist

### Then PilotUser Test on Real Machine
```powershell
# Migrate one test user before committing to all users
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Data\%USERNAME%" `
    -PilotUser "testuser" -AllUsers
```

---

## 🔁 Testing the Interactive Wrapper (Beginners)

If you're using `UFM_Interactive.ps1` instead of the main script directly:

```powershell
# Start the interactive wrapper
.\UFM_Interactive.ps1

# At the main menu:
# → Choose mode (e.g., 1 = Migrate)
# → Select "Dry Run" = YES when prompted
# → Choose "Run in current window"
# → Review output before doing the real run
```

The wrapper will never proceed to the real migration without asking you to confirm.

---

## 📋 Post-Migration Verification Checklist

After the real migration completes, verify:

- [ ] Open **File Explorer** → navigate to Documents, Desktop, Downloads
- [ ] Confirm paths show the new location (e.g., `D:\Data\Documents`)
- [ ] **Save a test file** in Documents → confirm it appears at the new path
- [ ] Open **Registry Editor** (`regedit`) → navigate to:  
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`  
  → Confirm `Personal` points to new path
- [ ] Sign out and back in → re-check above
- [ ] Open the **HTML report** generated by the script → confirm all folders show ✅ Success
- [ ] If using OneDrive → resume sync and confirm no KFM conflict warning

---

## 🆘 Emergency Rollback

If something goes wrong after a real migration:

```powershell
# Option 1: Script rollback (uses saved .reg backup)
.\UserFolderMigrator.ps1 -Mode Rollback

# Option 2: Specify the backup file directly
.\UserFolderMigrator.ps1 -Mode Rollback -RollbackFile ".\Backup_YYYYMMDD.reg"

# Option 3: System Restore (if rollback files are missing)
# Win+R → rstrui.exe → pick the restore point created before migration

# Option 4: Manual registry fix (last resort)
# regedit → HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
# Set Personal = %USERPROFILE%\Documents  (or original path)
```

---

## ❓ FAQ

**Q: Can I run this on a live, logged-in machine?**  
A: Yes, but close Outlook, browsers, and any app that locks files in the folders being migrated. Use `-UseVSS` if you cannot close them.

**Q: Do I need to sign out after migration?**  
A: The script broadcasts a shell refresh notification. New Explorer windows show the new paths immediately. A sign-out is recommended for the cleanest experience.

**Q: What if migration is interrupted halfway?**  
A: Re-run with `-EnableCheckpoint` to resume. Or use `-Mode RepairTransactions` to scan and fix the partial state.

**Q: Is it safe to run on a domain-joined machine?**  
A: Check Group Policy first (`gpresult /h gp.html`). If shell folder redirection is GPO-managed, migration will be blocked on next login unless GPO is updated.

**Q: Does this work with OneDrive for Business?**  
A: Yes, but you must disable OneDrive Known Folder Move (KFM) first. Use `-RemoveKFMPolicy` if KFM was applied via Group Policy.
