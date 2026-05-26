# 🔌 Plugin Development Guide

> Reference architecture for building UserFolderMigrator plugins.  
> All 10 included plugins follow this exact specification.

---

## Table of Contents

- [How the Plugin System Works](#how-the-plugin-system-works)
- [File Naming & Placement](#file-naming--placement)
- [Hook Stages Reference](#hook-stages-reference)
- [The $Context Object — Full Schema](#the-context-object--full-schema)
- [Hook Function Anatomy](#hook-function-anatomy)
- [The _DeclareInputs Convention](#the-_declareinputs-convention)
- [Module-Scoped State](#module-scoped-state)
- [Return Values](#return-values)
- [Write-ErrorGuard Pattern](#write-errorguard-pattern)
- [Defensive Fallback Shims](#defensive-fallback-shims)
- [Export-ModuleMember Rules](#export-modulemember-rules)
- [Conflict Detection](#conflict-detection)
- [Plugin Manifest (Signed Mode)](#plugin-manifest-signed-mode)
- [Included Plugins — Annotated Catalog](#included-plugins--annotated-catalog)
- [Complete Minimal Plugin Template](#complete-minimal-plugin-template)
- [Complete Full-Featured Plugin Template](#complete-full-featured-plugin-template)
- [Style Guide](#style-guide)
- [Testing Your Plugin](#testing-your-plugin)

---

## How the Plugin System Works

At startup, the main script scans the `plugins\` subfolder for any `*.psm1` file, verifies it against the manifest (if one exists), checks for function name conflicts with already-loaded commands, and imports it via `Import-Module`. It then dispatches hook functions at each pipeline stage by calling all functions matching the pattern `<Stage>_*`.

```
plugins\
  UF_MyPlugin.psm1          ← loaded automatically
  UF_Plugins.manifest.json  ← optional; enforces SHA-256 integrity
```

Hooks are **non-fatal by default** — a hook that throws only emits a Warning and the main script continues. Returning `$false` from a hook is the correct way to signal a controlled abort.

---

## File Naming & Placement

| Rule | Example |
|---|---|
| File must be a `.psm1` | `UF_MyPlugin.psm1` |
| Drop in `plugins\` subfolder | `<script dir>\plugins\UF_MyPlugin.psm1` |
| Prefix with `UF_` (convention, not enforced) | `UF_BrowserProfileMigrator.psm1` |
| Module name in `Export-ModuleMember` must match basename | File = `UF_Encryption.psm1` |

If `plugins\` does not exist, the loader creates it on first run and falls back to the script's own directory for this run.

---

## Hook Stages Reference

Every hook function is named `<Stage>_<YourName>`. The loader finds all loaded functions matching `<Stage>_*` and calls them in load order.

| Stage | Pattern | Fires When | Typical Use |
|---|---|---|---|
| **PreFlight** | `PreFlight_*` | Before any pre-migration checks run | SMART disk health, network stability, AV verification |
| **PreMigration** | `PreMigration_*` | After checks pass, before the migration loop starts | Create VSS rollback points, detect browsers, start watchdog |
| **PreUser** | `PreUser_*` | Before each user's folders are processed | Pre-create destination folder structure, set quota |
| **PreFolder** | `PreFolder_*` | Before each shell folder is copied | Conflict detection, path validation, reorder queue |
| **PostFolder** | `PostFolder_*` | After each shell folder is copied | EFS encryption, semantic validation, custom checksums |
| **PostUser** | `PostUser_*` | After all folders for a user complete | Browser profile copy, per-user reporting, helpdesk tickets |
| **PostMigration** | `PostMigration_*` | After all users complete | Diagnostics summary, browser report, audit upload |
| **PostSession** | `PostSession_*` | At the very end of the script | Stop watchdog, cleanup temp files, final telemetry |
| **Rollback** | `Rollback_*` | During rollback operations | VSS snapshot restore, registry conflict repair |

> **Note:** Functions ending in `_DeclareInputs` are **never** called as hooks — they are excluded from the hook dispatcher automatically and serve only the input-collection system (see [_DeclareInputs Convention](#the-_declareinputs-convention)).

---

## The $Context Object — Full Schema

Every hook receives a single `$Context` parameter (hashtable). Keys available depend on the stage. Always guard with `$Context.ContainsKey('Key')` before accessing optional keys.

### PreFlight Stage
```powershell
$Context = @{
    Destination  = [string]  # Root destination path
    SourcePath   = [string]  # Current source profile path
    DryRun       = [bool]    # True if -DryRun was passed
    Unattended   = [bool]    # True if -Unattended was passed
}
```

### PreMigration Stage
```powershell
$Context = @{
    DryRun           = [bool]
    Unattended       = [bool]
    RollbackId       = [string]   # GUID identifying this migration session
    SkipRollbackPoint = [bool]    # True if plugin should skip creating a rollback point
    # Plugin-injected keys are available here if set by a PreFlight hook
}
```

### PreUser Stage
```powershell
$Context = @{
    Username          = [string]   # SAM account name of the user being processed
    Destination       = [string]   # Resolved destination root for this user
    BaseDestination   = [string]   # Destination root before %USERNAME% substitution
    Folders           = [string[]] # Folder names selected for migration
    DryRun            = [bool]
    Unattended        = [bool]
    # _DeclareInputs keys are injected here before the hook fires:
    QuotaGB           = [int]      # Example: from UF_Provisioning DeclareInputs
    SkipProvisioning  = [bool]     # Plugin can write this to signal skip
    ProvisioningResult = [object]  # Plugin can write result objects here
}
```

### PreFolder Stage
```powershell
$Context = @{
    Username    = [string]                              # User being migrated
    FolderName  = [string]                              # e.g. 'Documents', 'Desktop'
    SourcePath  = [string]                              # Full resolved source path
    DestPath    = [string]                              # Full resolved destination path
    DryRun      = [bool]
    Unattended  = [bool]
    FoldersList = [System.Collections.Generic.List[string]]  # Mutable ordered list of remaining folders
}
```

> ⚠️ **FoldersList mutability:** If you need to reorder the queue (like `UF_PriorityQueue`), confirm `FoldersList` is an `IList` before calling `.Clear()` or `.Add()`. Convert if it's a plain `[string[]]` array:
> ```powershell
> if ($Context.FoldersList -isnot [System.Collections.IList]) {
>     $mutable = [System.Collections.Generic.List[string]]::new()
>     foreach ($f in $Context.FoldersList) { $mutable.Add($f) }
>     $Context.FoldersList = $mutable
> }
> ```

### PostFolder Stage
```powershell
$Context = @{
    Username         = [string]
    FolderName       = [string]
    SourcePath       = [string]
    DestPath         = [string]
    DestinationPath  = [string]   # Alias for DestPath (some stages use either)
    DryRun           = [bool]
    Unattended       = [bool]
    # _DeclareInputs keys injected before hook fires:
    EnableEncryption = [bool]     # Example: from UF_Encryption DeclareInputs
    RequireBitLocker = [bool]
    StopOnCorruption = [bool]     # Example: from UF_SemanticValidation DeclareInputs
    # Plugin result keys (write these to pass data to PostUser/PostMigration):
    EncryptionResult  = [object]
    ValidationResult  = [object]
    SkipValidation    = [bool]
}
```

### PostUser Stage
```powershell
$Context = @{
    Username         = [string]
    Destination      = [string]
    DestinationPath  = [string]
    DryRun           = [bool]
    Unattended       = [bool]
    # All PostFolder result keys are still accessible here
}
```

### PostMigration Stage
```powershell
$Context = @{
    DestinationPath          = [string]
    DryRun                   = [bool]
    Unattended               = [bool]
    # _DeclareInputs keys:
    AutoRemediation          = [bool]    # Example: from UF_Troubleshooter
    # Plugin result keys:
    ProfilePath              = [string]
    SID                      = [string]
    DiagnosticsResult        = [object]
    RemediationResult        = [object]
    RegistryConflictsResolved = [int]
}
```

### PostSession Stage
```powershell
$Context = @{
    DryRun      = [bool]
    Unattended  = [bool]
    # Final session-level result keys set by earlier stages
}
```

### Rollback Stage
```powershell
$Context = @{
    DryRun                    = [bool]
    Unattended                = [bool]
    Username                  = [string]
    RollbackId                = [string]
    SkipRollbackPoint         = [bool]
    DestinationPath           = [string]
    SID                       = [string]
    RegistryConflictsResolved = [int]
}
```

---

## Hook Function Anatomy

```powershell
function PostFolder_MyPlugin {
    param($Context)                          # Always a single $Context param

    # 1. Extract and cast keys — never assume types from $Context
    $folderName = [string]$Context.FolderName
    $destPath   = [string]$Context.DestPath
    $dryRun     = [bool]$Context.DryRun

    # 2. Guard: skip if required keys are missing
    if (-not $destPath) {
        Write-Log "MyPlugin: missing DestPath in context — skipping" -Level "WARN"
        return $true    # Non-fatal skip
    }

    # 3. Guard: check optional plugin-input keys
    if ($Context.ContainsKey('SkipMyPlugin') -and $Context.SkipMyPlugin) {
        Write-Status "MyPlugin: skipped by context flag" -Type "Info"
        return $true
    }

    # 4. Do your work
    Write-Status "MyPlugin: processing $folderName" -Type "Info"

    if ($dryRun) {
        Write-Status "  [DRY RUN] Would do X to $destPath" -Type "Info"
        return $true
    }

    try {
        # ... actual work ...
        $Context.MyPluginResult = $result    # Write results back to context
        return $true                         # Signal: continue
    } catch {
        Write-Log "MyPlugin: error in $folderName — $_" -Level "ERROR"
        return $false    # Signal: abort this folder (not the whole migration)
    }
}
```

---

## The _DeclareInputs Convention

Plugins that need user-supplied parameters at runtime implement a `_DeclareInputs` function. This is called **before** the hook fires to collect and inject values into `$Context`.

**Naming:** `<Stage>_<PluginName>_DeclareInputs` or `<Stage>_DeclareInputs`

**The function must return an array of hashtables**, each describing one input:

```powershell
function PostFolder_Encryption_DeclareInputs {
    return @(
        @{
            Key               = 'EnableEncryption'   # Key injected into $Context
            Prompt            = 'Enable EFS encryption on migrated folders?'
            Type              = 'YesNo'              # YesNo | String | Int
            Default           = 'N'                  # Shown interactively
            UnattendedDefault = 'N'                  # Used when -Unattended
            Required          = $false               # If $true, abort if not supplied
        },
        @{
            Key               = 'RequireBitLocker'
            Prompt            = 'Require BitLocker on destination drive?'
            Type              = 'YesNo'
            Default           = 'N'
            UnattendedDefault = 'N'
            Required          = $false
        }
    )
}
```

**Valid `Type` values:**

| Type | Input behavior | $Context injection |
|---|---|---|
| `YesNo` | Prompts Y/N; accepts y/n/yes/no | `[bool]` (`$true` for Y) |
| `String` | Free-text prompt | `[string]` |
| `Int` | Numeric prompt; validates integer | `[int]` |

> ⚠️ `_DeclareInputs` functions are **excluded from conflict detection** — the loader's conflict check skips any function whose name ends in `_DeclareInputs`. You can safely export them without worrying about name collisions.

---

## Module-Scoped State

Use `$script:` prefix for any state that must persist across hook calls within the same session. Never use global variables.

```powershell
# Module-level state — declared at module scope (outside any function)
$script:MyPlugin_Results   = [System.Collections.Generic.List[object]]::new()
$script:MyPlugin_StartTime = $null
$script:MyPlugin_Config    = @{}

function PreMigration_MyPlugin {
    param($Context)
    $script:MyPlugin_StartTime = [datetime]::UtcNow
    $script:MyPlugin_Results.Clear()
    return $true
}

function PostMigration_MyPlugin {
    param($Context)
    $elapsed = ([datetime]::UtcNow - $script:MyPlugin_StartTime).TotalSeconds
    Write-Status "MyPlugin: $($script:MyPlugin_Results.Count) items in ${elapsed}s" -Type "Info"
    return $true
}
```

---

## Return Values

| Return | Meaning |
|---|---|
| `$true` | Continue normally |
| `$false` | Abort the **current folder or user** — the main script logs the abort and moves on |
| *(nothing / void)* | Treated as `$true` (non-fatal) |
| `throw` | Caught by the dispatcher; logged as Warning; treated as `$true` (non-fatal) |

To abort the **entire migration** from a hook, call `exit 1` or `exit 99` — but use this only for critical unrecoverable failures (e.g. predicted disk failure in `UF_PreFlight`).

---

## Write-ErrorGuard Pattern

The main script provides `Write-ErrorGuard` for structured error reporting. Call it instead of `Write-Warning` for any condition that has recovery guidance.

```powershell
Write-ErrorGuard `
    -Operation    "MyPlugin" `
    -ErrorType    "Destination path too long (>240 chars)" `
    -Folder       $folderName `
    -Severity     "Warning" `
    -SkipReason   "Robocopy may fail on paths >240 chars" `
    -Recovery     @{ Action = "Shorten the destination path or enable LongPathsEnabled in registry" } `
    -Diagnostics  @{ PathLength = $destPath.Length; Path = $destPath }
```

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `-Operation` | String | Plugin or module name |
| `-ErrorType` | String | Short description of what went wrong |
| `-Folder` | String | Folder name being processed |
| `-Severity` | String | `Warning` or `Error` |
| `-SkipReason` | String | Why this item was skipped (shown in report) |
| `-Recovery` | Hashtable | Suggested remediation steps |
| `-Diagnostics` | Hashtable | Structured diagnostic data attached to the error record |

---

## Defensive Fallback Shims

If your plugin calls `Write-ErrorGuard`, `Write-SectionHeader`, `Write-Status`, or `Write-Log`, include a fallback shim at the top of your module in case the main script has not yet defined them (e.g. during unit testing):

```powershell
if (-not (Get-Command 'Write-ErrorGuard' -ErrorAction SilentlyContinue)) {
    function Write-ErrorGuard {
        param(
            [string]$Operation  = '',
            [string]$ErrorType  = '',
            [string]$Folder     = '',
            [string]$Severity   = 'Warning',
            [string]$SkipReason = '',
            [hashtable]$Recovery    = @{},
            [hashtable]$Diagnostics = @{}
        )
        $msg = "[$Operation] $ErrorType"
        if ($SkipReason) { $msg += " — $SkipReason" }
        switch ($Severity) {
            'Error'   { Write-Error   $msg -ErrorAction Continue }
            default   { Write-Warning $msg }
        }
    }
}
```

This pattern is used by: `UF_ConflictResolver`, `UF_Encryption`, `UF_SemanticValidation`, `UF_RollbackEnhanced`, `UF_Troubleshooter`.

---

## Export-ModuleMember Rules

Every hook function and `_DeclareInputs` function **must** be listed in `Export-ModuleMember`. Internal helpers that are not hooks should be omitted (or prefixed with a module abbreviation to avoid conflicts).

```powershell
# Export only what the plugin system needs
Export-ModuleMember -Function @(
    'PreMigration_MyPlugin',
    'PostFolder_MyPlugin',
    'PostFolder_MyPlugin_DeclareInputs',   # DeclareInputs always exported
    'PostMigration_MyPlugin'
    # Internal helpers like 'MyPlugin_WriteStatus' are NOT listed
)
```

---

## Conflict Detection

Before loading a plugin, the loader scans all functions it exports and checks if any already exist in the current session. A plugin is **skipped** (not blocked) if any of its exports conflict, and a yellow warning is shown.

To avoid conflicts:
- Prefix internal helper functions with a module abbreviation (e.g. `BPM_Write`, `ENC_Validate`)
- Only export hook functions and `_DeclareInputs` functions — keep helpers unexported
- `_DeclareInputs` functions are **exempt** from conflict detection by the loader

---

## Plugin Manifest (Signed Mode)

In production, generate `UF_Plugins.manifest.json` to enforce SHA-256 integrity:

```powershell
.\New-PluginManifest.ps1
```

This creates:
```json
{
  "GeneratedAt": "2025-06-01T12:00:00Z",
  "Plugins": {
    "UF_MyPlugin": "SHA256:3A9F1C..."
  }
}
```

Without a manifest, the loader runs in **open mode** and emits a one-time advisory. With a manifest, any plugin whose hash doesn't match is **blocked** (not just skipped). The hash is checked against `SHA256:<hash>` in the manifest.

---

## Included Plugins — Annotated Catalog

| Plugin File | Hook(s) | What It Does |
|---|---|---|
| `UF_PreFlight.psm1` | `PreFlight_RunFullReport` | SMART disk health via WMI, path conflict pre-scan, network stability check, AV detection |
| `UF_ConflictResolver.psm1` | `PreFolder_ResolveConflicts` | Detects circular paths, reserved names (CON/NUL/COM1…), path length >240, case mismatches. Returns `$false` to abort circular copies |
| `UF_PriorityQueue.psm1` | `PreFolder_ReorderByPriority` | Reorders the folder processing queue: Desktop/Documents/Favorites first (Tier 1), then Downloads/Pictures/Contacts (Tier 2), then Videos/Music/SavedGames (Tier 3) |
| `UF_Provisioning.psm1` | `PreUser_CreateFolderStructure`, `PreUser_DeclareInputs` | Pre-creates destination folder tree per user; optionally sets NTFS disk quotas via `fsutil quota`. DeclareInputs: `QuotaGB` (default 0 = no limit) |
| `UF_Encryption.psm1` | `PreMigration_CheckBitLocker`, `PostFolder_EncryptFiles`, `PostFolder_Encryption_DeclareInputs` | Verifies BitLocker status on source/destination; applies EFS (`cipher /e`) to migrated folders. DeclareInputs: `EnableEncryption`, `RequireBitLocker` |
| `UF_SemanticValidation.psm1` | `PostFolder_SemanticValidate`, `PostFolder_Validation_DeclareInputs` | Validates migrated files by reading magic bytes (PDF/DOCX/JPEG/PNG/etc.) and attempting a minimal read. Catches silent corruption that SHA256 misses. DeclareInputs: `StopOnCorruption` |
| `UF_BrowserProfileMigrator.psm1` | `PreMigration_BrowserProfileMigrator`, `PostUser_BrowserProfileMigrator`, `PostMigration_BrowserProfileMigrator` | Detects and migrates Chrome, Edge, Firefox, Brave, Opera, Vivaldi profiles. Excludes cache/GPU/shader dirs. DeclareInputs (custom): `BrowserMigrateCache`, `BrowserSkipIfRunning`, `BrowserList` |
| `UF_RollbackEnhanced.psm1` | `PreMigration_CreateRollbackPoint`, `Rollback_RestoreFromSnapshot` | Creates VSS snapshots before migration; writes transaction log. On rollback, restores from VSS snapshot by volume. |
| `UF_Troubleshooter.psm1` | `PostMigration_RunDiagnostics`, `Rollback_FixRegistryConflicts`, `PostMigration_Diagnostics_DeclareInputs` | Detects stuck transactions (`.partial` marker files), registry values pointing to missing paths, and orphaned reg backups. DeclareInputs: `AutoRemediation` |
| `UF_Watchdog.psm1` | `PreMigration_StartWatchdog`, `PostSession_StopWatchdog` | Launches a background runspace that monitors the main script heartbeat. Sends alerts via `Send-MigrationNotification`, `Write-EventLogEntry`, `Write-AuditEntry`, and `Send-SyslogMessage` if the script hangs (>120s without heartbeat) or crashes. Patches `Write-ProgressBar` at runtime to inject heartbeat ticks. |

---

## Complete Minimal Plugin Template

```powershell
#Requires -Version 7.0
<#
.SYNOPSIS
    UF.Migration.MyPlugin — brief description.
    Hook points: PostFolder
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fallback shim (required if calling Write-ErrorGuard)
if (-not (Get-Command 'Write-ErrorGuard' -ErrorAction SilentlyContinue)) {
    function Write-ErrorGuard {
        param(
            [string]$Operation='', [string]$ErrorType='', [string]$Folder='',
            [string]$Severity='Warning', [string]$SkipReason='',
            [hashtable]$Recovery=@{}, [hashtable]$Diagnostics=@{}
        )
        $msg = "[$Operation] $ErrorType"
        if ($SkipReason) { $msg += " — $SkipReason" }
        if ($Severity -eq 'Error') { Write-Error $msg -ErrorAction Continue } else { Write-Warning $msg }
    }
}

function PostFolder_MyPlugin {
    param($Context)

    $folderName = [string]$Context.FolderName
    $destPath   = [string]$Context.DestPath
    $dryRun     = [bool]$Context.DryRun

    if (-not $destPath) {
        Write-Log "MyPlugin: missing DestPath — skipping" -Level "WARN"
        return $true
    }

    if ($dryRun) {
        Write-Status "  [DRY RUN] MyPlugin: would process $folderName" -Type "Info"
        return $true
    }

    try {
        # Your logic here
        Write-Status "  MyPlugin: processed $folderName" -Type "Success"
        return $true
    } catch {
        Write-Log "MyPlugin: error — $_" -Level "ERROR"
        return $false
    }
}

Export-ModuleMember -Function 'PostFolder_MyPlugin'
```

---

## Complete Full-Featured Plugin Template

```powershell
#Requires -Version 7.0
<#
.SYNOPSIS
    UF.Migration.MyPlugin — full template with DeclareInputs, state, and multi-stage hooks.
    Hook points: PreMigration, PostFolder, PostMigration

.STYLE GUIDE
    Functions  : PascalCase
    Parameters : PascalCase
    Variables  : camelCase
    Module vars: $script:MyPlugin_<Name>
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Fallback shims ────────────────────────────────────────────────────────────
if (-not (Get-Command 'Write-ErrorGuard' -ErrorAction SilentlyContinue)) {
    function Write-ErrorGuard {
        param(
            [string]$Operation='', [string]$ErrorType='', [string]$Folder='',
            [string]$Severity='Warning', [string]$SkipReason='',
            [hashtable]$Recovery=@{}, [hashtable]$Diagnostics=@{}
        )
        $msg = "[$Operation] $ErrorType"
        if ($SkipReason) { $msg += " — $SkipReason" }
        if ($Severity -eq 'Error') { Write-Error $msg -ErrorAction Continue } else { Write-Warning $msg }
    }
}

# ── Module-scoped state ───────────────────────────────────────────────────────
$script:MyPlugin_Results   = [System.Collections.Generic.List[object]]::new()
$script:MyPlugin_StartTime = $null

# ── DeclareInputs — called before PreMigration hook fires ────────────────────
function PreMigration_MyPlugin_DeclareInputs {
    return @(
        @{
            Key               = 'MyPluginEnabled'
            Prompt            = 'Enable MyPlugin processing? (Y/N)'
            Type              = 'YesNo'
            Default           = 'Y'
            UnattendedDefault = 'Y'
            Required          = $false
        },
        @{
            Key               = 'MyPluginThreshold'
            Prompt            = 'MyPlugin size threshold in MB (0 = no limit)'
            Type              = 'Int'
            Default           = '0'
            UnattendedDefault = '0'
            Required          = $false
        }
    )
}

# ── Hook: PreMigration ────────────────────────────────────────────────────────
function PreMigration_MyPlugin {
    param($Context)

    $script:MyPlugin_StartTime = [datetime]::UtcNow
    $script:MyPlugin_Results.Clear()

    # Read injected DeclareInputs value
    $enabled = if ($Context.ContainsKey('MyPluginEnabled')) { [bool]$Context.MyPluginEnabled } else { $true }
    if (-not $enabled) {
        Write-Status "MyPlugin: disabled via DeclareInputs — skipping all stages" -Type "Info"
        $Context.SkipMyPlugin = $true
        return $true
    }

    Write-Status "MyPlugin: initialized" -Type "Info"
    return $true
}

# ── Hook: PostFolder ──────────────────────────────────────────────────────────
function PostFolder_MyPlugin {
    param($Context)

    if ($Context.ContainsKey('SkipMyPlugin') -and $Context.SkipMyPlugin) { return $true }

    $folderName = [string]$Context.FolderName
    $destPath   = [string]$Context.DestPath
    $dryRun     = [bool]$Context.DryRun

    if (-not $destPath) {
        Write-Log "MyPlugin: missing DestPath in PostFolder context — skipping" -Level "WARN"
        return $true
    }

    if ($dryRun) {
        Write-Status "  [DRY RUN] MyPlugin: would process $folderName at $destPath" -Type "Info"
        return $true
    }

    try {
        $result = [PSCustomObject]@{
            FolderName = $folderName
            Success    = $true
            Detail     = "processed"
        }
        $script:MyPlugin_Results.Add($result)
        $Context.MyPluginResult = $result
        Write-Status "  MyPlugin: $folderName — OK" -Type "Success"
        return $true
    } catch {
        Write-ErrorGuard -Operation "MyPlugin" -ErrorType "PostFolder failed" `
            -Folder $folderName -Severity "Warning" `
            -SkipReason $_.Exception.Message
        return $false
    }
}

# ── Hook: PostMigration ───────────────────────────────────────────────────────
function PostMigration_MyPlugin {
    param($Context)

    if ($Context.ContainsKey('SkipMyPlugin') -and $Context.SkipMyPlugin) { return $true }

    $elapsed = ([datetime]::UtcNow - $script:MyPlugin_StartTime).TotalSeconds
    $success = $script:MyPlugin_Results | Where-Object { $_.Success }
    Write-Status "MyPlugin: $($success.Count)/$($script:MyPlugin_Results.Count) folders processed in $([Math]::Round($elapsed,1))s" -Type "Info"
    return $true
}

# ── Exports ───────────────────────────────────────────────────────────────────
Export-ModuleMember -Function @(
    'PreMigration_MyPlugin_DeclareInputs',
    'PreMigration_MyPlugin',
    'PostFolder_MyPlugin',
    'PostMigration_MyPlugin'
)
```

---

## Style Guide

All included plugins follow this convention:

| Element | Convention | Example |
|---|---|---|
| Hook functions | `<Stage>_<PascalCase>` | `PostFolder_SemanticValidate` |
| Helper functions | `PascalCase` (unexported) | `Get-FileMagicNumber` |
| Private module helpers | `<ABBREV>_PascalCase` (unexported) | `BPM_Write`, `ENC_Validate` |
| Parameters | `PascalCase` | `$Context`, `$FolderName` |
| Local variables | `camelCase` | `$destPath`, `$dryRun` |
| Module-scope state | `$script:<ModuleAbbrev>_<Name>` | `$script:BPM_Results` |
| Result objects | `[PSCustomObject]` with named properties | `@{ Success=$true; Detail="..." }` |
| Error handling | `try/catch` + `Write-ErrorGuard` | See templates above |

---

## Testing Your Plugin

```powershell
# 1. Dry run — safest first test
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Test" -DryRun

# 2. Check plugin loaded (look for "[+] Loaded UF_MyPlugin" in startup output)

# 3. Validate-only — runs pre-flight but no migration
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Test" -ValidateOnly

# 4. Single-folder test
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Test" -Folders Documents -DryRun

# 5. Real single-folder test (non-destructive if -KeepSource)
.\UserFolderMigrator.ps1 -Mode Migrate -Destination "D:\Test" -Folders Documents -KeepSource

# 6. Check the HTML report for your plugin's output
# 7. Check the log file: $env:TEMP\UFM_<date>.log
```

If your plugin fails to load, check:
- `Export-ModuleMember` lists all exported functions
- No function name collides with an existing command (`Get-Command YourFunctionName`)
- The file is valid PowerShell 7 syntax (`pwsh -NoProfile -Command "Import-Module .\plugins\UF_MyPlugin.psm1"`)
- The manifest hash matches if `UF_Plugins.manifest.json` exists
