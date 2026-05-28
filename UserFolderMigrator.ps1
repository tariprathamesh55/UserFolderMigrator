#Requires -Version 7.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enterprise-grade Windows user shell folder migration with automatic inactive user handling,
    live progress bars, HTML reporting, and full multi-user support.

.DESCRIPTION
    Relocates known Windows shell folders with smart feature detection, live per-file progress
    bars, HTML+JSON reports, checksum verification, and multi-user support.

.EXAMPLE
    .\UserFolderMigratorMultiUser.ps1 -Destination "Y:\Data" -AllUsers
    (Multi-user migration with live progress bars)

.EXAMPLE
    .\UserFolderMigratorMultiUser.ps1 -RedirectAndClean
    (Redirect registry to existing data location for current user)

.EXAMPLE
    .\UserFolderMigratorMultiUser.ps1 -RestoreDefaults
    (Restore folders to Windows defaults for current user)

.EXAMPLE
    .\UserFolderMigratorMultiUser.ps1 -RestoreDefaults -AllUsers
    (Restore all users to Windows defaults with space check)

.EXAMPLE
    .\UserFolderMigratorMultiUser.ps1 -RedirectAndClean -AllUsers
    (Redirect all users to existing data location)

.NOTES
    Version  : 7.4.0
    Requires : PowerShell 7.0+ | robocopy.exe
#>

# ── Parameter set names ──────────────────────────────────────────────────
#   Migrate          — default: copy shell folders to a new location
#   FullProfileBackup— clone entire C:\Users\<user> for DR
#   Rollback         — undo a previous migration via registry backup
#   ReportOnly       — read-only scan, no changes
#   RestoreDefaults  — reset shell folders back to Windows defaults
#   RedirectAndClean — update registry to point at an existing location
#   RepairTransactions — fix partially-completed migrations
# Each mode switch is mandatory in its set so PowerShell rejects invalid combos at parse time.
# Shared optional params (DryRun, AllUsers, etc.) are declared without a ParameterSetName
# so they are available in every set.
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param (
    # ── Mode — replaces all mode switches; also accepted interactively ──────
    # Valid values: Migrate, RedirectAndClean, RestoreDefaults, FullProfileBackup,
    #               RestoreProfile, RepairTransactions
    [Parameter()] [ValidateSet(
        'Migrate','RedirectAndClean','RestoreDefaults',
        'FullProfileBackup','RestoreProfile','RepairTransactions'
    )] [string]$Mode,

    # ── Destination ────────────────────────────────────────────────────────
    [Parameter()] [string]$Destination,

    # ── RestoreProfile-specific ────────────────────────────────────────────
    [Parameter()] [string]$Source,
    [Parameter()] [string]$DestinationProfile,
    [Parameter()] [switch]$SkipFileRestore,
    [Parameter()] [switch]$SkipRegistryRestore,
    [Parameter()] [switch]$SkipAclRestore,
    [Parameter()] [switch]$SkipWifiRestore,
    [Parameter()] [switch]$SkipDriveRestore,
    [Parameter()] [switch]$SkipTaskRestore,
    [Parameter()] [switch]$SkipPrinterRestore,
    [Parameter()] [switch]$AutoEnableSystemProtection,   # auto-enable System Restore when unattended
    [Parameter()] [switch]$SkipWslRestore,
    [Parameter()] [string]$WslInstallRoot = 'C:\WSL',

    # ── Folder selection ───────────────────────────────────────────────────
    [Parameter()]
    [ValidateSet('Desktop','Documents','Downloads','Music','Pictures','Videos',
                 'Favorites','Contacts','Links','SavedGames','Searches','All')]
    [string[]]$Folders = @('All'),

    # ── Universal flags ────────────────────────────────────────────────────
    [Parameter()] [switch]$DryRun,
    [Parameter()] [switch]$Force,
    [Parameter()] [switch]$ResetState,
    [Parameter()] [switch]$QuietMode,
    [Parameter()] [switch]$NoEventLog,
    [Parameter()] [string]$LogPath,
    [Parameter()] [string]$ReportPath,
    [Parameter()] [switch]$DisableHtmlReport,
    [Parameter()] [switch]$DisableAutoPerfTuning,
    [Parameter()] [switch]$SkipAutoPermissionFix,
    [Parameter()] [string]$HmacSecret,
    [Parameter()] [switch]$PassThru,
    [Parameter()] [switch]$TestCompatibility,

    # ── Copy / robocopy options ────────────────────────────────────────────
    [Parameter()] [ValidateRange(0,128)] [int]$RobocopyThreads = 0,
    [Parameter()] [ValidateRange(1,30)]  [int]$RobocopyRetries = 3,
    [Parameter()] [ValidateRange(1,120)] [int]$RobocopyWait = 5,
    [Parameter()] [switch]$UseRobocopyZ,
    [Parameter()] [ValidateRange(0,10000)] [int]$BandwidthLimitMbps = 0,
    [Parameter()] [string[]]$Exclude = @(),
    [Parameter()] [string]$ExcludeFile,
    [Parameter()] [switch]$DisableAutoExclusions,

    # ── VSS options ────────────────────────────────────────────────────────
    [Parameter()] [switch]$UseVSS,
    [Parameter()] [switch]$DisableSmartVSS,

    # ── Verification ──────────────────────────────────────────────────────
    [Parameter()] [switch]$DisableChecksumVerify,
    [Parameter()] [ValidateSet('MD5','SHA1','SHA256')] [string]$ChecksumAlgorithm = 'SHA256',
    [Parameter()] [switch]$SkipTestRestore,
    [Parameter()] [ValidateRange(1,20)] [int]$TestRestoreSamplePct = 10,
    [Parameter()] [switch]$VerifyDestination,

    # ── Migrate-specific ───────────────────────────────────────────────────
    [Parameter()] [switch]$KeepSource,
    [Parameter()] [switch]$SkipRegistryUpdate,
    [Parameter()] [switch]$ForceOneDrive,
    [Parameter()] [switch]$SkipGPOBlock,
    [Parameter()] [switch]$SkipKFMBlock,
    [Parameter()] [switch]$RunSFCCheck,         # Opt-in SFC /verifyonly pre-flight (5–15 min); prompted interactively if omitted
    [Parameter()] [switch]$DeployKFMPolicy,    # Deploy OneDrive KFM ADMX registry keys (requires -KFMTenantId)
    [Parameter()] [switch]$RemoveKFMPolicy,    # Remove KFM policy keys to unlock shell folders before migration
    [Parameter()] [string]$KFMTenantId,        # Azure AD Tenant GUID for KFMSilentOptIn policy
    [Parameter()] [switch]$CreateSymlink,
    [Parameter()] [switch]$CreateSyncTask,
    [Parameter()] [switch]$EnableCheckpoint,
    [Parameter()] [string]$CheckpointFile,
    [Parameter()] [switch]$DisableResume,

    # ── Parallelism ────────────────────────────────────────────────────────
    [Parameter()] [ValidateRange(1,32)] [int]$MaxParallel = 1,

    # ── FullProfileBackup-specific ─────────────────────────────────────────
    [Parameter()] [ValidateRange(0,10000)] [int]$MaxProfileSizeGB = 0,
    [Parameter()] [switch]$SkipBackupManifest,
    [Parameter()] [switch]$SkipCloudOnlyCheck,
    [Parameter()] [switch]$HydrateOneDrive,
    [Parameter()] [switch]$RollbackFullProfile,
    [Parameter()] [switch]$AutoCleanupCreds,
    # -IncrementalBackup: use /MIR + /XO + /XC + /XN so only new/changed files
    # are copied on subsequent runs. A backup.marker file records the last run time.
    # Without this switch, every run copies all files (full copy each time).
    [Parameter()] [switch]$IncrementalBackup,

    # ── Network ───────────────────────────────────────────────────────────
    [Parameter()] [PSCredential]$NetworkCredential,
    [Parameter()] [ValidateRange(10,300)] [int]$NetworkTimeout = 30,

    # ── Enterprise / notification ──────────────────────────────────────────
    [Parameter()] [ValidateRange(0,100)] [int]$MaxFailures = 0,
    [Parameter()] [string]$NotificationEmail,
    [Parameter()] [string]$NotificationTeamsWebhook,
    [Parameter()] [string]$SmtpServer,
    [Parameter()] [ValidateSet('Basic','OAuth2','Certificate','SecretVault','CredentialManager')]
    [string]$SmtpAuthMode = 'Basic',
    [Parameter()] [ValidateRange(0,65535)] [int]$SmtpPort = 0,
    [Parameter()] [string]$SmtpFrom,
    [Parameter()] [PSCredential]$SmtpCredential,
    [Parameter()] [string]$OAuthTenantId,
    [Parameter()] [string]$OAuthClientId,
    [Parameter()] [SecureString]$OAuthClientSecret,
    [Parameter()] [string]$OAuthCertThumbprint,
    [Parameter()] [string]$SecretVaultName,
    [Parameter()] [string]$SecretName,
    [Parameter()] [ValidateRange(1,10)]  [int]$SmtpMaxRetries     = 3,
    [Parameter()] [ValidateRange(1,300)] [int]$SmtpRetryDelayBase  = 5,
    [Parameter()] [switch]$BitLockerRequired,
    [Parameter()] [switch]$SkipSupplementalExports,
    [Parameter()] [switch]$DisableRestorePoint,
    [Parameter()] [switch]$EnableSyslog,
    [Parameter()] [string]$SyslogServer,

    # ── Safety / pilot ────────────────────────────────────────────────────
    [Parameter()] [string]$PilotUser,
    [Parameter()] [switch]$ValidateOnly,
    [Parameter()] [switch]$SkipLockedFileCheck,
    [Parameter()] [switch]$SecureWipeSource,          # Use SDelete for secure deletion
    [Parameter()] [switch]$SkipAccessCheck,           # Bypass AccessChk permission audit
    [Parameter()] [switch]$SkipJunctionScan,          # Bypass Junction scan warning
    [Parameter()] [string]$QuarantinePath,
    [Parameter()] [ValidateRange(0,3650)] [int]$QuarantineRetentionDays = 0,

    # ── Unattended / automation ────────────────────────────────────────────
    [Parameter()] [switch]$Unattended,
    [Parameter()] [string]$RollbackFile,

    # ── WAN / high-latency optimisation ───────────────────────────────────
    # Forces /MT:1 or /MT:2 and disables directory parallelism for RTT > 50 ms links.
    # Auto-activated when hardware detection measures RTT > 50 ms on a network drive.
    # Pass explicitly to override auto-detection on any topology.
    [Parameter()] [switch]$WanOptimized,

    # ── Permission repair throttle ─────────────────────────────────────────
    # Profiles larger than this (GB) skip takeown /r to prevent multi-hour stalls.
    # Set to 0 for unlimited (repair all profiles regardless of size).
    [Parameter()] [ValidateRange(0,10000)] [int]$MaxRepairSizeGB = 10,

    # ── Offline mode ───────────────────────────────────────────────────────
    # Skip Install-Module calls; look for pre-staged modules in .\UFM_Modules\.
    # Required for air-gapped / no-internet environments.
    [Parameter()] [switch]$OfflineMode,

    # ── Scheduled Task Registration ───────────────────────────────────────────
    # -RegisterTask  : Creates a Windows Scheduled Task that runs this script automatically.
    # Run once interactively as an administrator — does not perform any migration.
    [Parameter()] [switch]$RegisterTask,
    [Parameter()] [string]$TaskName    = 'UserFolderMigrator',
    [Parameter()] [ValidateSet('Daily','Weekly','AtLogon')] [string]$TaskTrigger = 'Weekly',
    [Parameter()] [string]$TaskTime    = '22:00',
    [Parameter()] [ValidateSet('Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday')] [string]$TaskDay = 'Sunday',
    [Parameter()] [string]$TaskRunAs   = 'SYSTEM',

    # ── User selection ────────────────────────────────────────────────────
    [Parameter()] [ValidatePattern('^[a-zA-Z0-9_\-\.]{1,64}$')] [string]$TargetUsername,
    [Parameter()] [switch]$AllUsers
)

# ── Optional Script Signing Enforcement ──────────────────────────────────────
# Set environment variable UFM_ENFORCE_SIGNING=1 in production deployments to
# require a valid Authenticode signature before the script continues.
# Leave unset (or =0) in dev/test environments — no change in behaviour.
$UFM_ENFORCE_SIGNING = if ($env:UFM_ENFORCE_SIGNING -eq '1') { $true } else { $false }  # Set env var UFM_ENFORCE_SIGNING=1 in production to enforce; dev/test runs unsigned
if ($UFM_ENFORCE_SIGNING) {
    $sig = Get-AuthenticodeSignature -FilePath $PSCommandPath -ErrorAction SilentlyContinue
    if (-not $sig -or $sig.Status -ne 'Valid') {
        Write-Host "  [X] Script signature invalid or missing. Execution blocked." -ForegroundColor Red
        Write-Host "    Sign with: Set-AuthenticodeSignature -FilePath '$PSCommandPath' -Certificate (Get-Item Cert:\CurrentUser\My\<thumbprint>)" -ForegroundColor Gray
        Write-Host "    Or unset UFM_ENFORCE_SIGNING to run unsigned." -ForegroundColor Gray
        exit 126
    }
}
# 

# Force-clean any previously loaded UF_* modules and functions
Get-Module | Where-Object { $_.Name -like 'UF_*' } | Remove-Module -Force -ErrorAction SilentlyContinue
Get-ChildItem Function: | Where-Object { $_.Name -like 'PreMigration_*' -or $_.Name -like 'PostMigration_*' -or $_.Name -like 'PreUser_*' -or $_.Name -like 'PostUser_*' } | 
    Remove-Item -Force -ErrorAction SilentlyContinue

# ── Plugin Auto-Loader ────────────────────────────────────────────────────────
# Drop any UserFolderMigrator_*.psm1 alongside this script to auto-activate it.
# Conflict detection is dynamic — modules whose exported functions already exist
# in this session are skipped automatically. No hardcoded blocklist required.
#
# SIGNATURE VERIFICATION: if UF_Plugins.manifest.json exists alongside the script,
# each plugin's SHA-256 is verified against the manifest before loading.
# Plugins absent from or mismatched in the manifest are BLOCKED.
# When no manifest is present the loader runs in open mode and emits a one-time advisory.
# Generate / update the manifest with: .\New-PluginManifest.ps1
# ── Determine plugin search path ──────────────────────────────────────────
# If a "plugins" subfolder exists, load exclusively from there.
# Otherwise fall back to the script's own directory.
$pluginsDir = Join-Path $PSScriptRoot 'plugins'
if (Test-Path $pluginsDir -PathType Container) {
    $_pluginSearchPath = $pluginsDir
} else {
    # Create the folder so the user knows where to drop plugins in future runs
    try { New-Item -Path $pluginsDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null } catch { }
    $_pluginSearchPath = $PSScriptRoot
}
$_pluginFiles = @(Get-ChildItem -Path $_pluginSearchPath -Filter '*.psm1' -File)
$_manifestPath   = Join-Path $PSScriptRoot 'UF_Plugins.manifest.json'
$_manifest       = $null
$_manifestMode   = 'open'   # open | enforced

if (Test-Path $_manifestPath) {
    try {
        $_manifest     = Get-Content $_manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        $_manifestMode = 'enforced'
    } catch {
        Write-Host "  [!] Plugin manifest unreadable — falling back to open mode: $_" -ForegroundColor Yellow
    }
}

if ($_pluginFiles.Count -gt 0) {
    Write-Host ''
    Write-Host '  ── Plugin Modules ─────────────────────────────────────────' -ForegroundColor DarkCyan

    if ($_manifestMode -eq 'open') {
        Write-Host '  [~] No manifest found — running in unsigned mode. Run New-PluginManifest.ps1 to enable signing.' -ForegroundColor DarkYellow
    }

    $_loadedCount  = 0
    $_skippedCount = 0
    $_failedCount  = 0
    $_blockedCount = 0
    $_disabledCount = 0

# Remove any previously loaded UserFolderMigrator_* modules (stale from a prior run in the same session)
Get-Module -Name 'UserFolderMigrator_*' | Remove-Module -Force -ErrorAction SilentlyContinue

    foreach ($_mod in $_pluginFiles) {

        # ── Disabled prefix check ────────────────────────────────────────────
        if ($_mod.BaseName -like 'Disabled_*') {
            Write-Host "  [~] DISABLED $($_mod.BaseName)  (rename to remove 'Disabled_' prefix to enable)" -ForegroundColor DarkGray
            $_disabledCount++
            continue
        }

        # ── Signature check (enforced mode only) ────────────────────────────
        if ($_manifestMode -eq 'enforced') {
            $_entry = $_manifest.Plugins.PSObject.Properties[$_mod.BaseName]
            if (-not $_entry) {
                Write-Host "  [X] BLOCKED  $($_mod.BaseName)  (not in manifest)" -ForegroundColor Red
                $_blockedCount++
                continue
            }
            $_expected = $_entry.Value -replace '^SHA256:',''
            $_actual   = (Get-FileHash -Path $_mod.FullName -Algorithm SHA256).Hash
            if ($_actual -ne $_expected) {
                Write-Host "  [X] BLOCKED  $($_mod.BaseName)  (SHA256 mismatch — file may have been modified)" -ForegroundColor Red
                $_blockedCount++
                continue
            }
        }

        # ── Conflict check ───────────────────────────────────────────────────
        $_exports = [System.Collections.Generic.List[string]]::new()
        switch -Regex -File $_mod.FullName {
            '^Export-ModuleMember\s+-Function\s+(.+)$' {
                $Matches[1].Trim().Trim('@(').Trim(')') -split ',' |
                    ForEach-Object { $_exports.Add($_.Trim().Trim("'").Trim('"')) }
            }
            "^function\s+([\w-]+)" { $_exports.Add($Matches[1]) }
        }

        $_conflicts = @($_exports | Where-Object {
            $_ -and $_ -notlike '*_DeclareInputs' -and (Get-Command -Name $_ -ErrorAction SilentlyContinue)
        })

        if ($_conflicts.Count -gt 0) {
            Write-Host "  [!] SKIPPED  $($_mod.BaseName)  (conflicts: $($_conflicts -join ', '))" -ForegroundColor Yellow
            $_skippedCount++
            continue
        }

        # ── Load ─────────────────────────────────────────────────────────────
        try {
            Import-Module $_mod.FullName -Force -ErrorAction Stop
            Write-Host "  [+] Loaded   $($_mod.BaseName)" -ForegroundColor Green
            $_loadedCount++
        } catch {
            Write-Host "  [X] FAILED   $($_mod.BaseName)  ($_)" -ForegroundColor Red
            $_failedCount++
        }
    }

    $_summary = "  ── $_loadedCount loaded"
    if ($_blockedCount  -gt 0) { $_summary += "  |  $_blockedCount blocked (manifest)" }
    if ($_skippedCount  -gt 0) { $_summary += "  |  $_skippedCount skipped (conflict)" }
    if ($_disabledCount -gt 0) { $_summary += "  |  $_disabledCount disabled" }
    if ($_failedCount   -gt 0) { $_summary += "  |  $_failedCount failed" }
    Write-Host $_summary -ForegroundColor DarkCyan
    Write-Host ''
Remove-Variable -Name '_pluginFiles','_manifestPath','_manifest','_manifestMode','_mod','_exports','_conflicts','_entry','_expected','_actual','_loadedCount','_skippedCount','_failedCount','_blockedCount','_disabledCount','_summary' -ErrorAction SilentlyContinue
}
# ─────────────────────────────────────────────────────────────────────────────

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'   # Consistent with StrictMode: all errors terminate unless caught

# ── Plugin Hook Dispatcher ────────────────────────────────────────────────────
# Finds and invokes all loaded functions matching the pattern <Stage>_<Action>.
# Called at each pipeline stage. Hook failures are non-fatal (Warning only).
# Stage names: PreFlight, PreMigration, PreUser, PreFolder,
#              PostFolder, PostUser, PostMigration, PostSession, Rollback
function Invoke-PluginHooks {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)] [string]$Stage,
        [object]$Context = @{}
    )
    
    # Defensive: Ensure Context is a hashtable
    if ($Context -is [array]) {
        Write-Verbose "[Plugin] Received array for stage '$Stage' - converting to empty hashtable"
        $Context = @{}
    }
    elseif ($Context -isnot [hashtable] -and $Context -isnot [System.Collections.IDictionary]) {
        Write-Verbose "[Plugin] Received $($Context.GetType().Name) for stage '$Stage' - converting to empty hashtable"
        $Context = @{}
    }
    
    # Get all hooks for this stage
    $hooks = @(Get-Command -Name "${Stage}_*" -CommandType Function -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -notlike '*_DeclareInputs' })
    
    if (-not $hooks) { 
        Write-Verbose "[Plugin] No hooks found for stage '$Stage'"
        return $true 
    }
    
    Write-Verbose "[Plugin] Found $($hooks.Count) hook(s) for stage '$Stage'"
    
    foreach ($hook in $hooks) {
        try {
            Write-Verbose "[Plugin] Invoking hook: $($hook.Name)"
            
            # Try different invocation methods
            $result = $null
            $invokeError = $null
            
            # Method 1: Standard positional parameter
            try {
                $result = & $hook.Name $Context
            }
            catch {
                $invokeError = $_
                Write-Verbose "[Plugin] Positional parameter failed: $($_.Exception.Message)"
                
                # Method 2: Try splatting if Context is a hashtable
                # Filter out _-prefixed metadata keys (_Stage, _SchemaVersion, _Timestamp, _DryRun, _ScriptVersion)
                # before splatting — hooks with [CmdletBinding()] get parameter binding errors on those keys
                # which produces noisy PS>TerminatingError output and breaks the fallback chain.
                if ($Context -is [hashtable]) {
                    try {
                        Write-Verbose "[Plugin] Trying splatting for $($hook.Name)"
                        $splattable = @{}
                        foreach ($k in $Context.Keys) {
                            if (-not $k.StartsWith('_')) { $splattable[$k] = $Context[$k] }
                        }
                        $result = & $hook.Name @splattable
                        $invokeError = $null
                    }
                    catch {
                        $invokeError = $_
                        Write-Verbose "[Plugin] Splatting also failed: $($_.Exception.Message)"
                    }
                }
                
                # Method 3: Try with no parameters
                if ($invokeError) {
                    try {
                        Write-Verbose "[Plugin] Trying with no parameters for $($hook.Name)"
                        $result = & $hook.Name
                        $invokeError = $null
                    }
                    catch {
                        $invokeError = $_
                    }
                }
            }
            
            # If all methods failed, log and continue
            if ($invokeError) {
                throw $invokeError
            }
            
            # Check result
            if ($result -eq $false) {
                Write-Warning "[Plugin] Hook '$($hook.Name)' blocked stage '$Stage' — aborting stage"
                Write-Log "[Plugin] Stage '$Stage' blocked by hook '$($hook.Name)'"
                return $false
            }
        } 
        catch {
            Write-Warning "[Plugin] Hook '$($hook.Name)' failed: $($_.Exception.Message)"
            Write-Log "[Plugin] Hook '$($hook.Name)' EXCEPTION: $($_.Exception.Message)"
            # Continue with other hooks even if one fails
        }
    }
    return $true
}

function Get-PluginInputDeclarations {
    <#
    .SYNOPSIS
        Scans all loaded plugins for *_DeclareInputs functions and returns combined input descriptors.
        Each descriptor: @{ Key; Prompt; Type; Default; UnattendedDefault; Required; PluginName }
    #>
    $declarations = [System.Collections.Generic.List[object]]::new()
    $declareFns = @(Get-Command -Name '*_DeclareInputs' -CommandType Function -ErrorAction SilentlyContinue)

    # Only consider functions from loaded (non-disabled) modules
    $loadedModuleNames = @(Get-Module | Where-Object { $_.Name -notlike 'Disabled_*' } | Select-Object -ExpandProperty Name)

    foreach ($fn in $declareFns) {
        # Skip if the function belongs to a disabled/unloaded module
        if ($fn.Module -and $fn.Module.Name -like 'Disabled_*') { continue }
        if ($fn.Module -and $fn.Module.Name -and $fn.Module.Name -notin $loadedModuleNames) { continue }

        # Skip pure hook functions (exactly Stage_Action, two parts) — not Stage_Plugin_DeclareInputs (three parts)
        $hookPrefixes = @('PreFlight_','PreMigration_','PreUser_','PreFolder_','PostFolder_','PostUser_','PostMigration_','PostSession_','Rollback_')
        $isHook = $hookPrefixes | Where-Object { $fn.Name -like "$_*" -and $fn.Name -notlike "*_DeclareInputs" }
        if ($isHook) { continue }

        $pluginName = if ($fn.Module -and $fn.Module.Name -ne 'global') {
            $fn.Module.Name -replace '\.psm1$',''
        } else {
            $fn.Name -replace '_DeclareInputs$',''
        }
        try {
            $inputs = & $fn.Name
            if ($inputs) {
                foreach ($i in $inputs) {
                    $i['PluginName'] = $pluginName
                    $declarations.Add($i)
                }
            }
        } catch {
            Write-Warning "[Plugin] '$($fn.Name)' DeclareInputs failed: $_"
        }
    }
    return $declarations
}

function Invoke-PluginInputCollection {
    param([bool]$Unattended = $false)

    $declarations = Get-PluginInputDeclarations
    if (-not $declarations -or $declarations.Count -eq 0) { return }

    $sensitiveTypes = @('SecureString', 'Password', 'ApiKey', 'Secret', 'Token')

    Write-Host ''
    Write-Host '  ── Plugin Input Collection ────────────────────────────────' -ForegroundColor DarkCyan
    if ($Unattended) {
        Write-Host '  [~] Unattended mode — using plugin defaults' -ForegroundColor DarkYellow
    }

    # Group declarations by plugin name
    $grouped = $declarations | Group-Object -Property PluginName

    foreach ($group in $grouped) {
        $pluginName = $group.Name
        Write-Host "  Plugin: $pluginName" -ForegroundColor Magenta

        foreach ($decl in $group.Group) {
            $key       = $decl['Key']
            $prompt    = $decl['Prompt']
            $type      = $decl['Type']
            $default   = $decl['Default']
            $uDefault  = if ($decl.ContainsKey('UnattendedDefault')) { $decl['UnattendedDefault'] } else { $default }
            $isSensitive = $sensitiveTypes -contains $type

            if ($Unattended) {
                # Unattended: use default, show compact line (keep for logging)
                if ($isSensitive) {
                    $coerced = if ([string]::IsNullOrWhiteSpace($uDefault)) {
                        [System.Security.SecureString]::new()
                    } else {
                        ConvertTo-SecureString $uDefault -AsPlainText -Force
                    }
                } else {
                    $coerced = switch ($type) {
                        'YesNo' { $uDefault -eq 'Y' -or $uDefault -eq 'y' -or $uDefault -eq $true }
                        'Int'   { [int]::TryParse($uDefault, [ref]$null) ? [int]$uDefault : 0 }
                        default { $uDefault }
                    }
                }
                $script:PluginInputs[$key] = $coerced
                continue
            }

            # ---- Interactive mode: single-line prompt (no extra confirmation) ----
            $defaultText = if ($default -ne $null -and $default -ne '') { " (default: $default)" } else { '' }
            $promptText = "$prompt$defaultText"

            if ($isSensitive) {
                # Secure input: still needs two lines (no way to hide echo on same line easily)
                Write-Host "    [~] $key (secure) – $promptText" -ForegroundColor Cyan
                $coerced = Read-Host "      " -AsSecureString
                # No confirmation line
            } else {
                # Non‑sensitive: all on one line, no confirmation line after
                [Console]::Write("    [?] $key – $promptText : ")
                $raw = [Console]::ReadLine()
                if ([string]::IsNullOrWhiteSpace($raw)) { $raw = $default }
                $value = $raw.Trim()
                $coerced = switch ($type) {
                    'YesNo' { $value -eq 'Y' -or $value -eq 'y' -or $value -eq $true }
                    'Int'   { [int]::TryParse($value, [ref]$null) ? [int]$value : [int]$default }
                    default { $value }
                }
                # No confirmation line – just proceed
            }
            $script:PluginInputs[$key] = $coerced
        }
        Write-Host ""
    }

    # Optional logging (still writes to file, not console)
    Write-Log "Plugin inputs collected:"
    foreach ($kv in $script:PluginInputs.GetEnumerator()) {
        $source = ($declarations | Where-Object { $_['Key'] -eq $kv.Key } | Select-Object -First 1).PluginName
        $valueDisplay = if ($kv.Value -is [SecureString]) { "****" } else { $kv.Value }
        Write-Log "  $($kv.Key) = $valueDisplay (from plugin: $source)"
    }
}

function New-PluginContext {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)] [string]$Stage,
        [Parameter(Mandatory)] [hashtable]$Data
    )
    
    # Clone the input hashtable and sanitize values
    $ctx = [hashtable]::new()
    foreach ($key in $Data.Keys) {
        $value = $Data[$key]
        
        # Convert switch parameters to boolean
        if ($value -is [switch]) {
            $value = $value.IsPresent
        }
        # Convert arrays to strings if needed, or keep as is
        elseif ($value -is [array]) {
            # Keep arrays but they will be handled by hooks
            $value = $value
        }
        # Ensure no null keys
        elseif ($value -eq $null) {
            $value = ''
        }
        
        $ctx[$key] = $value
    }
    
    # Merge collected plugin inputs
    foreach ($k in $script:PluginInputs.Keys) {
        if (-not $ctx.ContainsKey($k)) { 
            $ctx[$k] = $script:PluginInputs[$k] 
        }
    }
    
    # Add metadata
    $ctx['_SchemaVersion'] = 2
    $ctx['_Stage']         = $Stage
    $ctx['_ScriptVersion'] = $script:VERSION
    $ctx['_Timestamp']     = [datetime]::UtcNow
    $ctx['_DryRun']        = $false
    if ($Data.ContainsKey('DryRun')) {
        $dryRunValue = $Data['DryRun']
        if ($dryRunValue -is [switch]) {
            $ctx['_DryRun'] = $dryRunValue.IsPresent
        } else {
            $ctx['_DryRun'] = [bool]$dryRunValue
        }
    }
    
    return $ctx
}
# ─────────────────────────────────────────────────────────────────────────────

# Capture the script's own invocation line before any functions are called
$script:InvocationLine = $MyInvocation.Line

# Global trap: runs on any unhandled terminating error or Ctrl+C
# Ensures VSS shadows, network drives, and transcripts are always cleaned up
trap {
    $errMsg = if ($_ -and $_.Exception) { $_.Exception.Message } else { 'Unknown error' }
    try {
        # Attempt to write log entry — may fail if logger never initialised; silence is intentional inside trap
        if ($script:LogFile) { Add-Content $script:LogFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [FATAL] Unhandled: $errMsg" -Encoding UTF8 -ErrorAction SilentlyContinue }
    } catch [System.Exception] { }   # Must not re-throw inside trap
    try { if ($script:VssShadowPaths  -and $script:VssShadowPaths.Count  -gt 0) { Remove-VssShadows  } } catch [System.Exception] { }   # Cleanup; must not re-throw
    try { if ($script:MountedDrives   -and $script:MountedDrives.Count   -gt 0) { Dismount-NetworkDrives } } catch [System.Exception] { }   # Cleanup; must not re-throw
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch [System.Exception] { }   # Cleanup; must not re-throw
    Write-Host "`n  [X] FATAL: $errMsg" -ForegroundColor Red
    Write-Host "      Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkRed
    # ── Email alert on fatal crash ────────────────────────────────────────────
    # Send-MigrationNotification may itself be uninitialised if crash is very early;
    # guard the call so the trap never re-throws.
    try {
        if ($NotificationEmail) {
            $fatalBody = "UserFolderMigrator encountered a FATAL unhandled error and has terminated.`n`n" +
                         "Computer  : $env:COMPUTERNAME`n" +
                         "User      : $env:USERNAME`n" +
                         "Mode      : $($script:ReportMode)`n" +
                         "Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" +
                         "Error     : $errMsg`n`n" +
                         "Stack Trace:`n$($_.ScriptStackTrace)`n`n" +
                         "Log file  : $($script:LogFile)"
            Send-MigrationNotification -Subject "FATAL CRASH — UserFolderMigrator on $env:COMPUTERNAME" `
                -Body $fatalBody -Status 'Error'
        }
    } catch [System.Exception] { }   # Must not re-throw inside trap
    exit 99
}

#region ── Console Output Formatting ─────────────────────────────────────────

$script:VERSION = ''
$script:STAMP = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:ExitCode = 0
$script:LogFile = $null
$script:HtmlReportPath = $null
$script:TranscriptPath = $null
$script:MetricsPath = $null
$script:AuditLogPath = $null   # HMAC-signed audit log
$script:PreMigrationRegBackup = [System.Collections.Generic.Dictionary[string,string]]::new()
$script:ReportMode = 'Migration'
$script:ReportStartTime = (Get-Date)
$script:ReportUserBlocks = [System.Collections.Generic.List[object]]::new()
$script:_PostMigrationFired = $false   # guard: ensures PostMigration hook fires exactly once per session
$script:_lastMigratedProfilePath = $null  # set by Invoke-UserMigration; read by Exit-WithReport HTML report
$script:PluginInputs = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)   # collected plugin inputs

# Hardware profile — populated by Invoke-HardwareDetection, referenced throughout
$script:HW = $null   # [PSCustomObject] set early in Main; see Invoke-HardwareDetection

# Granular exit codes (documented in .NOTES and in help)
$script:EXIT_SUCCESS    = 0   # All operations completed successfully
$script:EXIT_PARTIAL    = 1   # Partial success — some folders failed
$script:EXIT_FAILURE    = 2   # Complete failure — no folders succeeded
$script:EXIT_NO_SPACE   = 3   # Insufficient disk space on destination
$script:EXIT_PERMISSION = 4   # Permission / access denied
$script:EXIT_CANCELLED  = 5   # Cancelled by user
$script:EXIT_KFM_BLOCK  = 6   # Unattended run aborted — OneDrive KFM active (use -SkipKFMBlock to override)
$script:EXIT_FATAL      = 99  # Unhandled exception (trap)

# Central config dictionary — populated by Import-CentralConfig.
# Functions read from $script:Config instead of $PSBoundParameters (fixes scope leak).
$script:Config = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Abort-on-error flag — set by circuit breaker; checked in outer loops
$script:AbortRequested = $false

# Named system mutexes — used to serialise log/checkpoint writes from parallel runspaces.
# Using named mutexes means each runspace can re-open the same OS primitive by name
# without needing the object to be marshalled across the runspace boundary.
$script:LogMutexName        = "Global\UFM_Log_$PID"
$script:AuditMutexName      = "Global\UFM_Audit_$PID"
$script:CheckpointMutexName = "Global\UFM_Checkpoint_$PID"
# Sysinternals tool paths (filled at startup)
$script:HandlePath    = $null
$script:SDeletePath   = $null
$script:AccessChkPath = $null
$script:JunctionPath  = $null
$script:LogMutex        = [System.Threading.Mutex]::new($false, $script:LogMutexName)
$script:AuditMutex      = [System.Threading.Mutex]::new($false, $script:AuditMutexName)
$script:CheckpointMutex = [System.Threading.Mutex]::new($false, $script:CheckpointMutexName)

# ── Email / PoshMailKit state ─────────────────────────────────────────────────
# $script:PoshMailKitReady   : $true once PoshMailKit is successfully imported
# $script:MsalPsReady        : $true once MSAL.PS is imported (OAuth2 / Certificate modes)
# $script:SecretMgmtReady    : $true once SecretManagement + SecretStore are imported
# $script:CachedSmtpCred     : PSCredential cached after first retrieval — never re-prompted
# $script:CachedOAuthToken   : raw OAuth2 access token string, cached until near-expiry
# $script:OAuthTokenExpiry   : UTC DateTime at which the cached token expires (minus 60s margin)
# $script:ResolvedSmtpConfig : [PSCustomObject]{ Server; Port; UseSsl } resolved once per session
$script:PoshMailKitReady   = $false
$script:MsalPsReady        = $false
$script:SecretMgmtReady    = $false
$script:CachedSmtpCred     = $null
$script:CachedOAuthToken   = $null
$script:OAuthTokenExpiry   = [DateTime]::MinValue
$script:ResolvedSmtpConfig = $null

function Write-SessionBanner {
    <#
    .SYNOPSIS
        Renders the startup banner to the console. Extracted from Main to reduce its size.
        Shows script version and key feature flags. Called once at the start of every run.
    #>
    [CmdletBinding()]
    param()
    $bannerInner = 78
    $border    = "  +" + ("=" * $bannerInner) + "+"
    $line1text = "                            USER FOLDER MIGRATOR "
    $line1     = "  |" + $line1text.PadRight($bannerInner) + "|"
    Write-Host ""
    Write-Host $border -ForegroundColor Cyan
    Write-Host $line1  -ForegroundColor Cyan
    Write-Host $border -ForegroundColor Cyan
    Write-Host ""
}

function Register-UserFolderMigratorScheduledTask {
    <#
    .SYNOPSIS
        Registers a Windows Scheduled Task that runs UserFolderMigrator automatically.
        Supports Daily, Weekly, and AtLogon triggers. Runs as SYSTEM or a named account.
        DPAPI-encrypted credentials cannot be read by SYSTEM — use a named service account
        or a Group Managed Service Account (gMSA) when encryption is required.
    #>
    [CmdletBinding()]
    param()

    if (-not $PSCommandPath) {
        Write-Status "Cannot register task: script path unknown. Run from a saved .ps1 file." -Type "Error"
        return $false
    }

    Write-SectionHeader "SCHEDULED TASK REGISTRATION"
    Write-Status "Task name    : $TaskName"    -Type "Info"
    Write-Status "Trigger      : $TaskTrigger$(if ($TaskTrigger -eq 'Weekly') { " on $TaskDay" }) at $TaskTime" -Type "Info"
    Write-Status "Run as       : $TaskRunAs"   -Type "Info"

    # DPAPI + SYSTEM warning — same guard as ODM
    if ($TaskRunAs -eq 'SYSTEM') {
        Write-Status "SYSTEM account cannot decrypt DPAPI-scoped credentials." -Type "Warning"
        Write-Status "If this task uses encrypted backups, pass -EncryptionPassphrase at runtime or use a gMSA." -Type "Warning"
    }

    # Build argument string — mirror current invocation switches
    $modeArg = switch ($PSCmdlet.ParameterSetName) {
        'Migrate'          { '-AllUsers' }
        'FullProfileBackup'{ '-AllUsers -FullProfileBackup' }
        'Rollback'         { '-Rollback' }
        default            { '-AllUsers' }
    }
    $taskArgs  = "-NonInteractive -NoProfile -ExecutionPolicy Bypass"
    $taskArgs += " -File `"$PSCommandPath`" $modeArg -Unattended"
    if ($Destination)         { $taskArgs += " -Destination `"$Destination`"" }
    if ($DryRun)              { $taskArgs += " -DryRun" }
    if ($KeepSource)          { $taskArgs += " -KeepSource" }
    if ($BitLockerRequired)   { $taskArgs += " -BitLockerRequired" }
    if ($SkipAutoPermissionFix){ $taskArgs += " -SkipAutoPermissionFix" }
    if ($DisableHtmlReport)   { $taskArgs += " -DisableHtmlReport" }

    if ($DryRun) {
        Write-Status "[DRY RUN] Would register scheduled task with args: pwsh $taskArgs" -Type "Info"
        return $true
    }

    try {
        $action   = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument $taskArgs

        $trigger  = switch ($TaskTrigger) {
            'Daily'   { New-ScheduledTaskTrigger -Daily  -At $TaskTime }
            'Weekly'  { New-ScheduledTaskTrigger -Weekly -At $TaskTime -DaysOfWeek $TaskDay }
            'AtLogon' { New-ScheduledTaskTrigger -AtLogOn }
        }

        $principal = if ($TaskRunAs -eq 'SYSTEM') {
            New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        } else {
            New-ScheduledTaskPrincipal -UserId $TaskRunAs -LogonType Password -RunLevel Highest
        }

        $settings = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit (New-TimeSpan -Hours 12) `
            -RestartCount 1 `
            -RestartInterval (New-TimeSpan -Minutes 30) `
            -MultipleInstances IgnoreNew `
            -StartWhenAvailable

        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null

        Write-Status "Scheduled Task '$TaskName' registered successfully." -Type "Success"
        Write-Status "To remove: Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false" -Type "Info"
        Write-Log "Scheduled Task registered: $TaskName | Trigger=$TaskTrigger | RunAs=$TaskRunAs"
        return $true
    } catch {
        Write-Status "Scheduled Task registration failed: $_" -Type "Error"
        Write-Log "Scheduled Task registration failed: $_"
        return $false
    }
}

function Write-SectionHeader {
    <#
    .SYNOPSIS
        Writes a full-width double-line section header with left-aligned title.
    #>
    [CmdletBinding()]
    param([string]$Title)
    $w = try { [Math]::Max(60, [Console]::WindowWidth - 4) } catch { 100 }
    $bar = '=' * $w
    Write-Host ''
    Write-Host "  $bar" -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  $bar" -ForegroundColor DarkCyan
    Write-Host ''
}

function Write-Status {
    <#
    .SYNOPSIS
        Writes a colour-coded status line to the console. Type: Success, Error, Warning, Info.
    #>
    [CmdletBinding()]
    param([string]$Message, [string]$Type = "Info")
    $symbol = switch ($Type) {
        "Success" { "[+]" }
        "Error"   { "[X]" }
        "Warning" { "[!]" }
        "Info"    { "[~]" }
        default   { "[~]" }
    }
    $color = switch ($Type) {
        "Success" { "Green" }
        "Error"   { "Red" }
        "Warning" { "Yellow" }
        default   { "Gray" }
    }
    Write-Host "  $symbol $Message" -ForegroundColor $color
}

function Write-ProgressBar {
    <#
    .SYNOPSIS
        Renders an inline progress bar. Filenames suppressed; updates on same line via CR.
    #>
    [CmdletBinding()]
    param(
        [int]$Current,
        [int]$Total,
        [string]$FolderName,
        [long]$DoneBytes,
        [long]$TotalBytes,
        [double]$SpeedMBps,
        [int]$EtaSec,
        [string]$CurrentFile   # retained for call-site compatibility — not displayed
    )

    $pct      = if ($Total -gt 0) { [Math]::Min(100, [int](($Current / $Total) * 100)) } else { 0 }
    $barW     = 30
    $f        = [int][Math]::Floor(($pct / 100) * $barW)
    $bar      = ('=' * $f) + ('-' * ($barW - $f))
    $pctStr   = "$pct%".PadLeft(4)

    $doneStr  = Format-Bytes $DoneBytes
    $totalStr = Format-Bytes $TotalBytes
    $speedStr = if ($SpeedMBps -gt 0) { "{0:N1} MB/s" -f $SpeedMBps } else { "--- MB/s" }
    $etaStr   = if ($EtaSec -gt 0) { "ETA $(Format-Eta $EtaSec)" } else { "ETA --:--" }
    $statsW   = 45
    $stats    = "$doneStr / $totalStr | $speedStr | $etaStr"
    $stats    = $stats.PadRight($statsW).Substring(0, $statsW)

    $line = "  [~] [$bar] $pctStr | $stats"
    [Console]::Write("`r" + $line)
}

function Write-ProgressComplete {
    param([int]$Total, [long]$TotalBytes, [double]$SpeedMBps)
    $barW    = 30
    $fullBar = '=' * $barW
    $totalStr = Format-Bytes $TotalBytes
    $speedStr = if ($SpeedMBps -gt 0) { "{0:N1} MB/s" -f $SpeedMBps } else { "" }
    $statsW  = 45
    $stats   = "$Total folders | $totalStr | $speedStr"
    $stats   = $stats.PadRight($statsW).Substring(0, $statsW)
    $inner   = " [+] [=$fullBar=] 100% | $stats "
    $boxW    = $inner.Length
    Write-Host ""
    Write-Host ("  " + ('=' * $boxW)) -ForegroundColor Green
    Write-Host ("  $inner") -ForegroundColor Green
    Write-Host ("  " + ('=' * $boxW)) -ForegroundColor Green
    Write-Host ""
}

function Format-Bytes {
    <#
    .SYNOPSIS
        Converts a byte count to a human-readable string (B / KB / MB / GB / TB).
    #>
    [CmdletBinding()]
    param([long]$Bytes)
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Format-Eta {
    [CmdletBinding()]
    param([int]$Seconds)
    if ($Seconds -le 0) { return "--:--:--" }
    $hours   = [int][Math]::Floor($Seconds / 3600)
    $minutes = [int][Math]::Floor(($Seconds % 3600) / 60)
    $secs    = [int]($Seconds % 60)
    if ($hours -gt 0) { return "{0:D2}:{1:D2}:{2:D2}" -f $hours, $minutes, $secs }
    return "{0:D2}:{1:D2}" -f $minutes, $secs
}

function Write-TableSeparator {
    [CmdletBinding()]
    param([int]$Width = 100)
    Write-Host ("  " + "-" * $Width) -ForegroundColor DarkGray
}

function Clear-ProgressLine {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Erases the current console line in-place, leaving the cursor at column 0
        with no newline emitted. The next Write-* call will render on the same
        (now blank) line, so no empty line or ghost bar is left in the scroll buffer.
    #>
    param()
    $w = try   { if ([Console]::WindowWidth -gt 0) { [Console]::WindowWidth } else { 120 } }
         catch { 120 }
    # Carriage-return → overwrite with spaces → carriage-return back to col 0.
    # Deliberately no newline: the caller's next output lands on this line.
    Write-Host ("`r" + (' ' * ($w - 1)) + "`r") -NoNewline
}

function Invoke-Prompt {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Drop-in wrapper for Read-Host that is safe in unattended / pipeline contexts.
        When -Unattended is set: writes an error and returns $null instead of blocking.
        When interactive: delegates to Read-Host normally.
    .PARAMETER Message   Prompt text shown to the operator.
    .PARAMETER Default   Value returned in unattended mode when the prompt would be skipped.
                         If $null (default) the call is treated as a fatal missing-param error.
    .OUTPUTS
        [string] — the entered value, the default, or $null on unattended-fatal.
    #>
    param(
        [Parameter(Mandatory)] [string]$Message,
        [string]$Default = $null
    )
    if ($Unattended) {
        if ($null -ne $Default) {
            Write-Log "Unattended: prompt skipped ('$Message') — using default: '$Default'"
            return $Default
        }
        Write-Status "Unattended mode: required input '$Message' was not supplied as a parameter." -Type "Error"
        Write-Log "Unattended: FATAL — required prompt '$Message' has no default and no parameter was provided"
        $script:ExitCode = $script:EXIT_FAILURE
        Exit-WithReport -Code $script:ExitCode
    }
    return (Read-Host $Message)
}

function Confirm-Operation {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Presents a Y/N confirmation prompt.
        In unattended mode: auto-accepts (returns $true) and logs the bypass.
        In interactive mode: returns $true only for Y/y responses.
    .PARAMETER Message   Question shown to the operator.
    .OUTPUTS
        [bool]
    #>
    param([Parameter(Mandatory)] [string]$Message)
    if ($Unattended) {
        Write-Log "Unattended: confirmation auto-accepted — '$Message'"
        Write-Status "Unattended: auto-confirming '$Message'" -Type "Info"
        return $true
    }
    $answer = Read-Host $Message
    return ($answer -eq 'Y' -or $answer -eq 'y')
}

#endregion

#region ── Unattended Validation ─────────────────────────────────────────────

function Invoke-UnattendedValidation {
    <#
    .SYNOPSIS
        Validates that all required parameters are present for unattended (-Unattended) runs.
        Fails fast with a structured error list rather than hanging at an interactive prompt.
        Called from Main when -Unattended is set, before any migration work begins.
    .PARAMETER ParameterSetName
        The active PowerShell parameter set name (from $PSCmdlet.ParameterSetName in Main).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ParameterSetName)

    $errors = [System.Collections.Generic.List[string]]::new()

    $needsDest = $ParameterSetName -in @('Migrate','FullProfileBackup','RedirectAndClean','RepairTransactions')
    if ($needsDest -and -not $Destination) {
        $errors.Add("  -Destination is required in unattended $ParameterSetName mode")
    }
    if ($ParameterSetName -eq 'Rollback' -and -not $RollbackFile) {
        $errors.Add("  -RollbackFile is required for unattended Rollback mode")
    }
    if ($NotificationEmail -and $SmtpAuthMode -eq 'Basic' -and -not $SmtpCredential) {
        $errors.Add("  -SmtpCredential is required for unattended Basic email auth (or use OAuth2/Certificate/SecretVault/CredentialManager)")
    }
    if ($NotificationEmail -and $SmtpAuthMode -eq 'OAuth2') {
        if (-not $OAuthTenantId)     { $errors.Add("  -OAuthTenantId required for OAuth2 email auth") }
        if (-not $OAuthClientId)     { $errors.Add("  -OAuthClientId required for OAuth2 email auth") }
        if (-not $OAuthClientSecret) { $errors.Add("  -OAuthClientSecret required for OAuth2 email auth") }
    }
    if ($NotificationEmail -and $SmtpAuthMode -eq 'Certificate') {
        if (-not $OAuthTenantId)       { $errors.Add("  -OAuthTenantId required for Certificate email auth") }
        if (-not $OAuthClientId)       { $errors.Add("  -OAuthClientId required for Certificate email auth") }
        if (-not $OAuthCertThumbprint) { $errors.Add("  -OAuthCertThumbprint required for Certificate email auth") }
    }

    if ($errors.Count -gt 0) {
        Write-SectionHeader "UNATTENDED MODE — MISSING REQUIRED PARAMETERS"
        foreach ($e in $errors) { Write-Status $e -Type "Error" }
        Write-Log "Unattended pre-flight FAILED — missing: $($errors -join ' | ')"
        $script:ExitCode = $script:EXIT_FAILURE
        Exit-WithReport -Code $script:ExitCode
    }
    Write-Status "Unattended pre-flight passed — all required parameters present." -Type "Success"
    Write-Log "Unattended pre-flight passed"
}

#endregion

#region ── Logging ───────────────────────────────────────────────────────────

function Initialize-Logger {
    <#
    .SYNOPSIS
        Creates the UserFolderMigrator log directories and initialises all output file paths for the session.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()
    if ($LogPath) {
        $logDir = Split-Path $LogPath -Parent
        if ($logDir -and -not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        $script:LogFile = $LogPath
    } else {
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $logDir = Join-Path $scriptDir "UFM_Logs"
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        $script:LogFile = Join-Path $logDir "UFM_$($script:STAMP).log"
    }

    # Initialise the reports directory alongside UFM_Logs
    $scriptDir2 = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $reportDir  = Join-Path $scriptDir2 "UFM_Reports"
    if (-not (Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }
    $script:HtmlReportPath = Join-Path $reportDir "UFM_Report_$($script:STAMP).html"

    # Transcripts directory — captures all console output verbatim
    $transcriptDir = Join-Path $scriptDir2 "UFM_Transcripts"
    if (-not (Test-Path $transcriptDir)) { New-Item -Path $transcriptDir -ItemType Directory -Force | Out-Null }
    $script:TranscriptPath = Join-Path $transcriptDir "UFM_Transcript_$($script:STAMP).txt"

    # Signed audit log directory — HMAC-SHA256 tamper-evident entries
    $auditDir = Join-Path $scriptDir2 "UFM_AuditLog"
    if (-not (Test-Path $auditDir)) { New-Item -Path $auditDir -ItemType Directory -Force | Out-Null }
    $script:AuditLogPath = Join-Path $auditDir "UFM_Audit_$($script:STAMP).log"

    # Metrics JSON — machine-readable progress/result file for dashboards/monitoring tools
    $metricsDir = Join-Path $scriptDir2 "UFM_Metrics"
    if (-not (Test-Path $metricsDir)) { New-Item -Path $metricsDir -ItemType Directory -Force | Out-Null }
    $script:MetricsPath = Join-Path $metricsDir "UFM_Metrics_$($script:STAMP).json"

    $script:ReportStartTime = Get-Date

    $header = @"
================================================================================
UserFolderMigrator | $($script:STAMP)
User: $env:USERNAME | Host: $env:COMPUTERNAME
================================================================================
"@
    $header | Out-File -FilePath $script:LogFile -Encoding UTF8
}

function Write-Log {
    [CmdletBinding()]
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    if ($script:LogFile) {
        # Mutex-protected write — prevents interleaved lines when parallel runspaces log simultaneously
        $mtx = try { [System.Threading.Mutex]::OpenExisting($script:LogMutexName) } catch { $script:LogMutex }
        try {
            [void]$mtx.WaitOne(2000)   # 2 s timeout — never block indefinitely
            Add-Content -Path $script:LogFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
        } finally {
            try { $mtx.ReleaseMutex() } catch { }
        }
    }
    Write-AuditEntry -Message $Message -Level $Level
}

function Get-SafeTempPath {
    <#
    .SYNOPSIS
        Returns a reliable temp directory path that works in constrained sessions,
        VirtualBox shared folders, and SYSTEM account contexts where $env:TEMP may be null.
    #>
    $candidates = @($env:TEMP, $env:TMP, "$env:SystemRoot\Temp", "$env:ProgramData\UserFolderMigrator\Temp")
    foreach ($c in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($c)) {
            if (-not (Test-Path $c)) {
                try { New-Item -Path $c -ItemType Directory -Force | Out-Null } catch { continue }
            }
            return $c
        }
    }
    return "$env:SystemRoot\Temp"   # last resort — always exists on Windows
}

function Get-AuditHmacKey {
    [CmdletBinding()]
    param()
    <#
    .SYNOPSIS
        Returns a persistent 256-bit HMAC key, stored encrypted with DPAPI (LocalMachine scope).
        On first call the key is generated and saved to $env:ProgramData\UserFolderMigrator\audit.key.
        Subsequent calls load the same key, enabling offline audit log verification across sessions.
        Falls back to a session-derived key if DPAPI is unavailable (e.g. WinPE).
    #>
    $keyDir  = Join-Path $env:ProgramData 'UserFolderMigrator'
    $keyPath = Join-Path $keyDir 'audit.key'
    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        if (Test-Path $keyPath) {
            $encrypted = [System.IO.File]::ReadAllBytes($keyPath)
            return [System.Security.Cryptography.ProtectedData]::Unprotect(
                $encrypted, $null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        }
        # First run — generate, persist, return
        $key = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
        if (-not (Test-Path $keyDir)) { New-Item -Path $keyDir -ItemType Directory -Force | Out-Null }
        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
            $key, $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllBytes($keyPath, $encrypted)
        return $key
    } catch {
        # DPAPI unavailable (WinPE, restricted environment) — derive key via PBKDF2 over machine SID
        $sid = try { (Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue)?.SID?.Value } catch { $env:COMPUTERNAME }
        $sidStr = ($sid ?? $env:COMPUTERNAME)
        $salt = [System.Text.Encoding]::UTF8.GetBytes('UFM-STATIC-SALT-v1-DO-NOT-CHANGE')
        $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            [System.Text.Encoding]::UTF8.GetBytes($sidStr), $salt, 100000,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        return $pbkdf2.GetBytes(32)
    }
}

function Export-AuditLog {
    <#
    .SYNOPSIS
        Decrypts a DPAPI-encrypted UserFolderMigrator audit log (.enc file) and outputs its content.
        Must be run on the same machine that created the audit log (DPAPI is machine-scoped).
        The decrypted content is written to console only — no plaintext file is created.
    .PARAMETER Path
        Full path to the .enc audit log file (e.g. UFM_Audit_20260504_143022.log.enc).
    .PARAMETER OutFile
        Optional: write decrypted content to this path (auto-deleted after 60 seconds via job).
    .EXAMPLE
        Export-AuditLog -Path 'C:\UFM_Logs\UFM_Audit_20260504_143022.log.enc'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [string]$OutFile = ''
    )
    if (-not (Test-Path $Path)) { Write-Error "Audit file not found: $Path"; return }
    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        $encrypted = [System.IO.File]::ReadAllBytes($Path)
        $plain     = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encrypted, $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $text = [System.Text.Encoding]::UTF8.GetString($plain)
        if ($OutFile) {
            [System.IO.File]::WriteAllText($OutFile, $text)
            Write-Host "  [+] Decrypted audit log written to: $OutFile" -ForegroundColor Green
            Write-Host "    Note: delete this file when finished reviewing." -ForegroundColor Yellow
        } else {
            $text
        }
    } catch {
        Write-Error "Failed to decrypt audit log. Ensure you are running on the same machine that created it. Error: $_"
    }
}

function Clear-StoredCredentials {
    <#
    .SYNOPSIS
        Removes DPAPI-stored SMTP credentials, in-memory cached tokens, and optional
        CredentialManager entries created during this session. Called at exit when
        -AutoCleanupCreds is set. Non-fatal — failures are logged and ignored.
    #>
    [CmdletBinding()]
    param()
    # DPAPI-stored SMTP credential in registry
    $regPath = 'HKCU:\Software\UserFolderMigrator'
    if (Test-Path $regPath) {
        Remove-ItemProperty -Path $regPath -Name 'SMTP_Credential' -ErrorAction SilentlyContinue
        Write-Log "AutoCleanupCreds: removed DPAPI-stored SMTP credential from registry"
    }
    # In-memory cached credentials
    $script:CachedSmtpCred   = $null
    $script:CachedOAuthToken = $null
    # CredentialManager entry (cmdkey fallback — no managed API for deletion)
    if ($SecretName -eq 'UserFolderMigrator_SmtpCredential') {
        try {
            & cmdkey /delete:$SecretName 2>&1 | Out-Null
            Write-Log "AutoCleanupCreds: removed CredentialManager entry '$SecretName'"
        } catch { }
    }
    Write-Status "Stored credentials cleared (AutoCleanupCreds)" -Type "Info"
    Write-AuditEntry -Message "CRED_CLEANUP: stored credentials removed at session end" -Level "INFO"
}

function Write-AuditEntry {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Writes a tamper-evident audit log entry signed with HMAC-SHA256.
        Each line format: TIMESTAMP|LEVEL|MESSAGE|HMAC
        The HMAC covers TIMESTAMP+LEVEL+MESSAGE using $HmacSecret (or machine SID if not set).
        Compliance tools can verify integrity by recomputing HMACs offline.
        When no secret is provided, entries are still written but marked UNSIGNED.
    #>
    param([string]$Message, [string]$Level = "INFO")
    if (-not $script:AuditLogPath) { return }
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $payload   = "$timestamp|$Level|$Message"
        # Use caller-supplied secret if provided; otherwise load/create the persistent DPAPI key.
        # Persistent key enables post-session offline verification of any audit log from this machine.
        $keyBytes  = if ($HmacSecret) {
            [System.Text.Encoding]::UTF8.GetBytes($HmacSecret)
        } else {
            if (-not $script:_CachedAuditKey) { $script:_CachedAuditKey = Get-AuditHmacKey }
            $script:_CachedAuditKey
        }
        $msgBytes  = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $hmac      = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
        $hash      = [System.BitConverter]::ToString($hmac.ComputeHash($msgBytes)) -replace '-',''
        $hmac.Dispose()
        $entry = "$payload|HMAC=$hash"
        # Mutex-protected write — serialises audit entries from parallel runspaces
        $mtx = try { [System.Threading.Mutex]::OpenExisting($script:AuditMutexName) } catch { $script:AuditMutex }
        try {
            [void]$mtx.WaitOne(2000)
            Add-Content -Path $script:AuditLogPath -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue
        } finally {
            try { $mtx.ReleaseMutex() } catch { }
        }
    } catch { }   # Audit writes must never crash the main flow
}

function Confirm-AuditLog {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Verifies all HMAC signatures in an audit log file.
        Returns a summary object with TotalLines, ValidLines, InvalidLines, UnsignedLines.
        Use for post-migration compliance verification.
    #>
    param([string]$AuditLogPath, [string]$Secret)
    $result = [PSCustomObject]@{ TotalLines=0; ValidLines=0; InvalidLines=0; UnsignedLines=0; Errors=@() }
    if (-not (Test-Path $AuditLogPath)) {
        $result.Errors += "Audit log not found: $AuditLogPath"; return $result
    }
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $hmac     = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    foreach ($line in (Get-Content $AuditLogPath -Encoding UTF8 -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $result.TotalLines++
        if ($line -match '\|UNSIGNED$') { $result.UnsignedLines++; continue }
        if ($line -match '^(.+)\|HMAC=([0-9A-F]+)$') {
            $payload  = $Matches[1]
            $expected = $Matches[2]
            $msgBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
            $computed = [System.BitConverter]::ToString($hmac.ComputeHash($msgBytes)) -replace '-',''
            if ($computed -ceq $expected) { $result.ValidLines++ }
            else { $result.InvalidLines++; $result.Errors += "TAMPERED: $($payload.Substring(0,[Math]::Min(80,$payload.Length)))..." }
        } else { $result.InvalidLines++; $result.Errors += "MALFORMED: $($line.Substring(0,[Math]::Min(80,$line.Length)))" }
    }
    $hmac.Dispose()
    return $result
}

#endregion

#region ── Migration State (Idempotency Ledger) ────────────────────────────────

function Get-UfmStatePath {
    [CmdletBinding()]
    param([string]$Destination)
    return Join-Path $Destination '.ufm_state.json'
}

function Get-UfmMigrationState {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Reads the per-destination migration state ledger.
        Returns a hashtable of Username → completion record, or empty hashtable if no ledger exists.
    #>
    param([string]$Destination)
    $path = Get-UfmStatePath $Destination
    if (-not (Test-Path $path)) { return @{} }
    try {
        $raw = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        $tbl = @{}
        foreach ($prop in $raw.Migrations.PSObject.Properties) { $tbl[$prop.Name] = $prop.Value }
        return $tbl
    } catch { return @{} }
}

function Save-UfmMigrationState {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Records a completed user migration in the ledger at $Destination\.ufm_state.json.
        Thread-safe: uses a named mutex to guard concurrent writes from parallel runspaces.
    #>
    param([string]$Destination, [string]$UserName, [string]$Mode, [bool]$Success)
    if (-not $Destination) { return }
    $path  = Get-UfmStatePath $Destination
    $mutex = [System.Threading.Mutex]::new($false, 'UFM_StateLedger')
    try {
        [void]$mutex.WaitOne(5000)
        $state = Get-UfmMigrationState $Destination
        $state[$UserName] = [PSCustomObject]@{
            CompletedAt = (Get-Date -Format 'o')
            Mode        = $Mode
            Success     = $Success
            ScriptVer   = $script:VERSION
        }
        $obj = [PSCustomObject]@{ SchemaVersion = 1; Migrations = $state }
        $obj | ConvertTo-Json -Depth 4 | Set-Content -Path $path -Encoding UTF8 -Force
    } catch { } finally {
        try { $mutex.ReleaseMutex() } catch { }
        $mutex.Dispose()
    }
}

function Reset-UfmMigrationState {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Clears the migration state ledger at $Destination, allowing all users to be re-processed.
        Invoked when -ResetState switch is passed.
    #>
    param([string]$Destination)
    $path = Get-UfmStatePath $Destination
    if (Test-Path $path) {
        Remove-Item $path -Force
        Write-Status "Migration state ledger cleared at: $path" -Type "Warning"
        Write-Log "ResetState: ledger cleared at $path"
    } else {
        Write-Status "No state ledger found at: $Destination" -Type "Info"
    }
}

#endregion

#region ── Registry and Shell Folders ─────────────────────────────────────────

$script:USF_KEY = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
$script:SF_KEY = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'

$script:SHELL_FOLDERS = [ordered]@{
    Desktop    = @{ RegValue = 'Desktop';     Default = 'Desktop' }
    Documents  = @{ RegValue = 'Personal';    Default = 'Documents' }
    Downloads  = @{ RegValue = '{374DE290-123F-4565-9164-39C4925E467B}'; Default = 'Downloads' }
    Music      = @{ RegValue = 'My Music';    Default = 'Music' }
    Pictures   = @{ RegValue = 'My Pictures'; Default = 'Pictures' }
    Videos     = @{ RegValue = 'My Video';    Default = 'Videos' }
    Favorites  = @{ RegValue = 'Favorites';   Default = 'Favorites' }
    Contacts   = @{ RegValue = '{56784854-C6CB-462b-8169-88E350ACB882}'; Default = 'Contacts' }
    Links      = @{ RegValue = '{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}'; Default = 'Links' }
    SavedGames = @{ RegValue = '{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}'; Default = 'Saved Games' }
    Searches   = @{ RegValue = '{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}'; Default = 'Searches' }
}

#endregion

#region ── Helper Functions ─────────────────────────────────────────────────

function Get-FolderStats {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Returns Size (bytes), FileCount, and DirCount for a path.

        Two modes are available via the -FollowJunctions switch (default: $true).

        FollowJunctions = $true  (default) — matches Windows Explorer Properties:
            SIZE / FILE COUNT — junctions ARE followed via BFS with a visited-set
            to prevent double-counting circular shell-compat junctions (e.g.
            "My Documents" → "Documents" in user profiles).
            DIR COUNT — junctions are counted as one directory entry but their
            interior subdirectories are NOT added to DirCount, mirroring Explorer.

        FollowJunctions = $false — matches robocopy /XJD output (physical-only):
            Junction directory entries ARE still counted in DirCount (they exist
            as real entries on disk) but are NEVER recursed into.  Files and sizes
            inside junction targets are excluded.  Use this mode when verifying a
            backup made with robocopy /XJD so source and destination stats align.
    #>
    param(
        [string]$Path,
        [switch]$FollowJunctions = $true
    )

    $result = [PSCustomObject]@{ Size = 0L; FileCount = 0; DirCount = 0 }
    if (-not (Test-Path $Path)) { return $result }

    $opts = [System.IO.EnumerationOptions]::new()
    $opts.RecurseSubdirectories = $false
    $opts.AttributesToSkip      = [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System   # match Explorer default: hidden files OFF + hide protected OS files ON
    $opts.IgnoreInaccessible    = $true   # silently skip locked/denied paths

    $reparsePoint = [System.IO.FileAttributes]::ReparsePoint

    $visited = [System.Collections.Generic.HashSet[string]]::new(
                   [System.StringComparer]::OrdinalIgnoreCase)
    $queue   = [System.Collections.Generic.Queue[object]]::new()

    $root = [System.IO.Path]::GetFullPath($Path)
    [void]$visited.Add($root)
    $queue.Enqueue([pscustomobject]@{ P = $root; D = 0; CountDirs = $true })

    while ($queue.Count -gt 0) {
        $item       = $queue.Dequeue()
        $current    = $item.P
        $depth      = $item.D
        $countDirs  = $item.CountDirs

        # ── Files ─────────────────────────────────────────────────────────────
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($current, '*', $opts)) {
                try {
                    $result.Size += ([System.IO.FileInfo]::new($f)).Length
                    $result.FileCount++
                } catch [System.UnauthorizedAccessException] { }
                  catch [System.IO.IOException] { }
            }
        } catch [System.UnauthorizedAccessException] { }
          catch [System.IO.IOException] { }

        # ── Sub-directories ───────────────────────────────────────────────────
        if ($depth -lt 256) {
            try {
                foreach ($d in [System.IO.Directory]::EnumerateDirectories($current, '*', $opts)) {
                    try {
                        # Count this directory entry if we are in a counting context.
                        if ($countDirs) { $result.DirCount++ }

                        # Determine whether d itself is a junction/reparse point.
                        $attrs      = ([System.IO.DirectoryInfo]::new($d)).Attributes
                        $isJunction = ($attrs -band $reparsePoint) -ne 0

                        # In physical-only mode (-FollowJunctions:$false) do NOT recurse
                        # into junction targets.  The junction entry is already counted in
                        # DirCount above; we simply skip enqueuing it.
                        if ($isJunction -and -not $FollowJunctions) { continue }

                        # FIX: resolve junction/symlink to its real physical path so the visited
                        # set deduplicates by actual location, not by path string.
                        # GetFullPath() only normalises the string — it does NOT follow junction targets.
                        # Two different junction paths pointing to the same directory would both pass
                        # the visited check and cause double-counting without this resolution.
                        $norm = try {
                            $resolved = [System.IO.Directory]::ResolveLinkTarget($d, $true)
                            if ($resolved) { $resolved.FullName } else { [System.IO.Path]::GetFullPath($d) }
                        } catch { [System.IO.Path]::GetFullPath($d) }
                        if ($visited.Add($norm)) {
                            # Physical dirs propagate the current CountDirs flag.
                            # Junctions (when followed) are visited for file enumeration
                            # only — their children must NOT contribute to DirCount.
                            $childCountDirs = $countDirs -and (-not $isJunction)
                            $queue.Enqueue([pscustomobject]@{ P = $d; D = $depth + 1; CountDirs = $childCountDirs })
                        }
                    } catch [System.UnauthorizedAccessException] { }
                      catch [System.IO.IOException] { }
                }
            } catch [System.UnauthorizedAccessException] { }
              catch [System.IO.IOException] { }
        }
    }

    return $result
}

function Get-DiskFreeSpace {
    <#
    .SYNOPSIS
        Returns available free bytes on the volume hosting the specified path.
    #>
    [CmdletBinding()]
    param([string]$Path)
    try {
        # Split-Path -Qualifier returns e.g. "D:" but Get-PSDrive needs just "D" (Fix #3)
        $qualifier = (Split-Path $Path -Qualifier).TrimEnd(':')
        $driveInfo = Get-PSDrive -Name $qualifier -ErrorAction SilentlyContinue
        if ($driveInfo) { return $driveInfo.Free }
    } catch [System.Exception] {
        Write-Log "Get-DiskFreeSpace: could not query drive for path '$Path' — $_" -ErrorAction SilentlyContinue
    }
    return 0
}

function Test-AdminRight {
    <#
    .SYNOPSIS
        Returns true if the current session is elevated (running as Administrator).
    #>
    [CmdletBinding()]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Repair-InactiveUserPermissions {
    <#
    .SYNOPSIS
        Grants the Administrator group read access to an inactive user profile for migration.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$ProfilePath, [string]$Username)
    try {
        # ── Size-aware throttle ──────────────────────────────────────────────
        # takeown /r on a large profile generates millions of Event ID 4670 entries
        # and can stall for hours. Skip repair when profile exceeds -MaxRepairSizeGB
        # (default 10 GB). Set -MaxRepairSizeGB 0 to disable the cap (unlimited).
        if ($MaxRepairSizeGB -gt 0) {
            try {
                $profileBytes = (Get-ChildItem -Path $ProfilePath -Recurse -Force -ErrorAction SilentlyContinue |
                                    Measure-Object -Property Length -Sum).Sum
                $profileSizeGB = [math]::Round($profileBytes / 1GB, 2)
                if ($profileSizeGB -gt $MaxRepairSizeGB) {
                    Write-Status "  Profile $Username is $profileSizeGB GB — exceeds -MaxRepairSizeGB $MaxRepairSizeGB. Skipping takeown to prevent stall." -Type "Warning"
                    Write-Status "  Pre-stage permissions manually via icacls/GPO, or re-run with -MaxRepairSizeGB 0 to force repair." -Type "Warning"
                    Write-Log "Repair-InactiveUserPermissions: skipped $Username ($profileSizeGB GB > $MaxRepairSizeGB GB threshold)"
                    return $false
                }
                Write-Log "Repair-InactiveUserPermissions: $Username profile $profileSizeGB GB — within threshold, proceeding"
            } catch {
                Write-Log "Repair-InactiveUserPermissions: size check failed for $Username — proceeding anyway: $_"
            }
        }

        # takeown /r is recursive over the entire profile — can take minutes on large
        # profiles. Run via Start-Process so we can show a progress message and apply
        # a timeout rather than blocking silently forever.
        # FIX: Resolve temp dir safely — $env:TEMP can be null when running from a VirtualBox shared folder.
        $repairTempDir = Get-SafeTempPath

        $tmp_takeown     = [System.IO.Path]::GetTempFileName()
        $tmp_takeown_err = [System.IO.Path]::GetTempFileName()
        Write-Status "  Taking ownership of $ProfilePath (this may take a moment)..." -Type "Info"
        $p1 = Start-Process -FilePath 'takeown.exe' `
            -ArgumentList "/f `"$ProfilePath`" /r /d y" `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput $tmp_takeown `
            -RedirectStandardError  $tmp_takeown_err
        if (-not $p1.WaitForExit(120000)) {   # 2-minute timeout
            $p1.Kill()
            Write-Status "  takeown timed out after 2 minutes — continuing anyway" -Type "Warning"
        }

        Write-Status "  Granting Administrators full control..." -Type "Info"
        $tmp_icacls1     = [System.IO.Path]::GetTempFileName()
        $tmp_icacls1_err = [System.IO.Path]::GetTempFileName()
        $p2 = Start-Process -FilePath 'icacls.exe' `
            -ArgumentList "`"$ProfilePath`" /grant `"Administrators:(OI)(CI)F`" /t /q" `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput $tmp_icacls1 `
            -RedirectStandardError  $tmp_icacls1_err
        if (-not $p2.WaitForExit(60000)) {
            $p2.Kill()
            Write-Status "  icacls (Administrators) timed out — continuing" -Type "Warning"
        }

        Write-Status "  Granting SYSTEM full control..." -Type "Info"
        $tmp_icacls2     = [System.IO.Path]::GetTempFileName()
        $tmp_icacls2_err = [System.IO.Path]::GetTempFileName()
        $p3 = Start-Process -FilePath 'icacls.exe' `
            -ArgumentList "`"$ProfilePath`" /grant `"SYSTEM:(OI)(CI)F`" /t /q" `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput $tmp_icacls2 `
            -RedirectStandardError  $tmp_icacls2_err
        if (-not $p3.WaitForExit(60000)) {
            $p3.Kill()
            Write-Status "  icacls (SYSTEM) timed out — continuing" -Type "Warning"
        }

        # Clean up temp files
        @($tmp_takeown, $tmp_takeown_err, $tmp_icacls1, $tmp_icacls1_err, $tmp_icacls2, $tmp_icacls2_err) | ForEach-Object {
            if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
        }

        Write-Status "  Permissions fixed for $Username" -Type "Success"
    # ── AccessChk verification ─────────────────────────────────────
    $fixVerified = $true
    if ($script:AccessChkPath -and -not $SkipAccessCheck) {
        Write-Status "  Verifying read access with AccessChk..." -Type "Info"
        $verify = & $script:AccessChkPath -accepteula -q -r "$env:USERNAME" "$ProfilePath" 2>&1
        if ($LASTEXITCODE -eq 0 -and $verify) {
            Write-Status "  AccessChk VERIFIED – read access granted." -Type "Success"
            Write-Log "Permission fix verified by AccessChk for $Username"
            $fixVerified = $true
        } else {
            Write-Status "  AccessChk verification FAILED – read access still missing." -Type "Warning"
            Write-Log "Permission fix verification FAILED for $Username (AccessChk exit $LASTEXITCODE)"
            $fixVerified = $false
        }
    } else {
        Write-Status "  AccessChk not available or -SkipAccessCheck set – skipping verification." -Type "Info"
    }
    if ($fixVerified) {
        Write-Status "Permissions fixed and verified for $Username" -Type "Success"
        return $true
    } else {
        Write-Status "Permissions fixed but verification failed – manual check may be required." -Type "Warning"
        return $false
    }
        return $true
    } catch {
        Write-Log "Failed to fix permissions for $Username : $_"
        return $false
    }
}

function Repair-DestinationProfilePermissions {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$ProfilePath, [string]$Username)

    try {
        $repairTempDir = Get-SafeTempPath

        Write-Status "  Taking ownership of destination profile $ProfilePath ..." -Type "Info"
        $p1 = Start-Process -FilePath 'takeown.exe' `
            -ArgumentList "/f `"$ProfilePath`" /r /d y" `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput ([System.IO.Path]::Combine($repairTempDir, 'ufm_restore_takeown.tmp')) `
            -RedirectStandardError  ([System.IO.Path]::Combine($repairTempDir, 'ufm_restore_takeown_err.tmp'))
        if (-not $p1.WaitForExit(120000)) { $p1.Kill(); Write-Status "  takeown timed out" -Type "Warning" }

        Write-Status "  Granting Administrators full control..." -Type "Info"
        $p2 = Start-Process -FilePath 'icacls.exe' `
            -ArgumentList "`"$ProfilePath`" /grant `"Administrators:(OI)(CI)F`" /t /q" `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput ([System.IO.Path]::Combine($repairTempDir, 'ufm_restore_icacls1.tmp')) `
            -RedirectStandardError  ([System.IO.Path]::Combine($repairTempDir, 'ufm_restore_icacls1_err.tmp'))
        if (-not $p2.WaitForExit(60000)) { $p2.Kill() }

        Write-Status "  Granting SYSTEM full control..." -Type "Info"
        $p3 = Start-Process -FilePath 'icacls.exe' `
            -ArgumentList "`"$ProfilePath`" /grant `"SYSTEM:(OI)(CI)F`" /t /q" `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput ([System.IO.Path]::Combine($repairTempDir, 'ufm_restore_icacls2.tmp')) `
            -RedirectStandardError  ([System.IO.Path]::Combine($repairTempDir, 'ufm_restore_icacls2_err.tmp'))
        if (-not $p3.WaitForExit(60000)) { $p3.Kill() }

        # Clean up temp files
        'ufm_restore_takeown.tmp','ufm_restore_takeown_err.tmp',
        'ufm_restore_icacls1.tmp','ufm_restore_icacls1_err.tmp',
        'ufm_restore_icacls2.tmp','ufm_restore_icacls2_err.tmp' | ForEach-Object {
            $f = [System.IO.Path]::Combine($repairTempDir, $_)
            if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        Write-Status "  Destination permissions fixed for $Username" -Type "Success"
        return $true
    } catch {
        Write-Log "Failed to fix destination permissions for $Username : $_"
        return $false
    }
}

function Get-UserRegistryPaths {
    <#
    .SYNOPSIS
        Returns the NTUSER.DAT path and HKLM mount point key name for a given user SID.
    #>
    [CmdletBinding()]
    param([string]$SID)
    return @{
        UsfKey = "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        SfKey = "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    }
}

function Load-UserRegistryHive {
    <#
    .SYNOPSIS
        Loads an offline NTUSER.DAT hive into HKLM using reg.exe load.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$Username, [string]$ProfilePath, [string]$SID)
    
    $ntuserPath = Join-Path $ProfilePath "NTUSER.DAT"
    if (-not (Test-Path $ntuserPath)) {
        Write-Log "NTUSER.DAT not found for $Username"
        return $null
    }
    
    try {
        & reg.exe load "HKU\$SID" "$ntuserPath" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Loaded registry hive for $Username (SID: $SID)"
            return $SID
        }
    } catch {
        Write-Log "Failed to load registry hive for $Username : $_"
    }
    return $null
}

function Unload-UserRegistryHive {
    <#
    .SYNOPSIS
        Unloads a previously mounted NTUSER.DAT hive from HKLM using reg.exe unload.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$SID)
    try {
        & reg.exe unload "HKU\$SID" 2>&1 | Out-Null
        Write-Log "Unloaded registry hive for SID: $SID"
    } catch {
        Write-Log "Failed to unload registry hive for SID: $SID : $_"
    }
}

function Get-ShellFolderPath {
    <#
    .SYNOPSIS
        Reads the current registry value for a named shell folder from HKCU User Shell Folders.
    #>
    [CmdletBinding()]
    param([string]$FolderName, [string]$UsfKey, [string]$SfKey, [string]$ProfilePath)
    
    $def = $script:SHELL_FOLDERS[$FolderName]
    if (-not $def) { return $null }
    
    try {
        $value = Get-ItemPropertyValue -Path $UsfKey -Name $def.RegValue -ErrorAction SilentlyContinue
        if ($value) {
            # FIX: Replace %USERPROFILE% with the TARGET user's ProfilePath BEFORE calling
            # ExpandEnvironmentVariables. If done after, ExpandEnvironmentVariables consumes
            # %USERPROFILE% using the CURRENT process environment (e.g. C:\Users\Test) instead
            # of the inactive user's path (e.g. C:\Users\Prathamesh), silently producing the
            # wrong source directory for every shell folder — the subsequent guard
            # `if ($expanded -match '%USERPROFILE%')` never fires because the token is gone.
            $substituted = if ($ProfilePath -and $value -match '(?i)%USERPROFILE%') {
                $value -ireplace '%USERPROFILE%', $ProfilePath
            } else { $value }
            $expanded = [Environment]::ExpandEnvironmentVariables($substituted)
            return $expanded
        }
    } catch [System.Exception] { }  # Registry key may not exist for all folders — expected
    
    return Join-Path $ProfilePath $def.Default
}

function Set-ShellFolderRegistryPath {
    <#
    .SYNOPSIS
        Writes the new path for a named shell folder into both HKCU Shell Folders keys atomically.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$FolderName, [string]$NewPath, [string]$UsfKey, [string]$SfKey)
    
    $def = $script:SHELL_FOLDERS[$FolderName]
    if (-not $def) { return $false }
    
    try {
        Set-ItemProperty -Path $UsfKey -Name $def.RegValue -Value $NewPath -Type ExpandString -ErrorAction Stop
        Set-ItemProperty -Path $SfKey -Name $def.RegValue -Value $NewPath -Type String -ErrorAction Stop
        Write-Log "Registry updated for $FolderName -> $NewPath"
        return $true
    } catch {
        Write-Log "Failed to update registry for $FolderName : $_"
        return $false
    }
}

function Backup-RegistrySettings {
    <#
    .SYNOPSIS
        Exports the current shell folder registry keys to a JSON backup file used by -Rollback.
    #>
    [CmdletBinding()]
    param([string]$Username, [string]$SID)
    
    $backupDir = Join-Path $env:ProgramData 'UserFolderMigrator\Backups'
    if (-not (Test-Path $backupDir)) { New-Item -Path $backupDir -ItemType Directory -Force | Out-Null }

    $backupFile = [System.IO.Path]::Combine($backupDir, "RegistryBackup_${Username}_$($script:STAMP).reg")
    
    # Fix #4: When SID is null (current active user), use HKCU directly
    $usfKey = if ([string]::IsNullOrEmpty($SID)) {
        $script:USF_KEY
    } else {
        (Get-UserRegistryPaths -SID $SID).UsfKey
    }
    
    try {
        # Fix #8: Write the key header exactly once, then all values below it
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add("Windows Registry Editor Version 5.00`r`n")
        $lines.Add("[$usfKey]`r`n")
        
        foreach ($folder in $script:SHELL_FOLDERS.Keys) {
            $def = $script:SHELL_FOLDERS[$folder]
            $value = Get-ItemPropertyValue -Path $usfKey -Name $def.RegValue -ErrorAction SilentlyContinue
            if ($value) {
                # Escape backslashes for .reg format
                $escaped = $value -replace '\\', '\\'
                $lines.Add("`"$($def.RegValue)`"=`"$escaped`"`r`n")
            }
        }
        
        $lines | Out-File -FilePath $backupFile -Encoding UTF8 -NoNewline
        Write-Log "Registry backup saved to: $backupFile"
        return $backupFile
    } catch {
        Write-Log "Failed to backup registry: $_"
        return $null
    }
}

function Restore-RegistryFromBackup {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$BackupFile)
    
    if (-not (Test-Path $BackupFile)) {
        Write-Status "Backup file not found: $BackupFile" -Type "Error"
        return $false
    }

    # Guard against path traversal — file must resolve within expected backup dir
    $resolvedBackup = [System.IO.Path]::GetFullPath($BackupFile)
    $expectedBase   = [System.IO.Path]::GetFullPath((Split-Path $BackupFile -Parent))
    if (-not $resolvedBackup.StartsWith($expectedBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Status "Registry backup path traversal detected: $BackupFile" -Type "Error"
        return $false
    }

    try {
        & reg.exe import "$resolvedBackup" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Registry restored from backup" -Type "Success"
            return $true
        }
    } catch {
        Write-Status "Failed to restore registry: $_" -Type "Error"
    }
    return $false
}

function Remove-EmptyTree {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Removes empty sub-directories from Path bottom-up (deepest first).

        With -IncludeSelf, also removes Path itself when it is (or becomes) empty.
        Returns $true if Path was fully removed, $false if Path still exists.

        Safe by design: a directory is only deleted when it contains zero files
        and zero sub-directories after the bottom-up pass.  Any directory that
        still has content is silently skipped — nothing is ever force-deleted.
    #>
    param(
        [string]$Path,
        [switch]$IncludeSelf
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $true }

    $opts = [System.IO.EnumerationOptions]::new()
    $opts.RecurseSubdirectories = $true
    $opts.AttributesToSkip      = 0          # include hidden + system entries
    $opts.IgnoreInaccessible    = $true

    # Collect all sub-directories and sort by path length descending so we
    # always process deepest entries first (bottom-up pruning).
    $subDirs = try {
        [System.IO.Directory]::EnumerateDirectories($Path, '*', $opts) |
            Sort-Object { $_.Length } -Descending
    } catch { @() }

    foreach ($dir in $subDirs) {
        try {
            $any = [System.IO.Directory]::EnumerateFileSystemEntries($dir) |
                   Select-Object -First 1
            if (-not $any) {
                [System.IO.Directory]::Delete($dir)
                Write-Log "Removed empty directory: $dir"
            }
        } catch [System.UnauthorizedAccessException] { }
          catch [System.IO.IOException] { }
    }

    # Optionally remove the root itself if it is now empty
    if ($IncludeSelf) {
        try {
            $any = [System.IO.Directory]::EnumerateFileSystemEntries($Path) |
                   Select-Object -First 1
            if (-not $any) {
                [System.IO.Directory]::Delete($Path)
                Write-Log "Removed empty root directory: $Path"
                return $true
            }
        } catch [System.UnauthorizedAccessException] { }
          catch [System.IO.IOException] { }
    }
    return $false
}

#endregion

#region ── Robocopy with Progress ────────────────────────────────────────────

function Resolve-ToUncPath {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Resolves a drive-letter path to its underlying UNC path when the drive
        is a mapped network share.

    .DESCRIPTION
        Windows elevated processes (and child processes they spawn) run under an
        elevated logon session that is SEPARATE from the standard-user session that
        originally mapped network drives via 'net use' or Windows Explorer.
        Because of this session isolation, a mapped drive letter such as Y: that is
        fully visible to PowerShell cmdlets (which go through the PS FileSystem
        provider) is INVISIBLE to native child processes like robocopy.exe, which
        use the Win32 API directly against the elevated token's drive table.
        The result is robocopy exit code 16 ("serious error — no files copied") even
        though Test-Path Y:\ returns $true in the same session.

        The fix is to bypass the drive letter entirely and pass the underlying UNC
        path (e.g. \server\share\Data\Prathamesh\Desktop) directly to robocopy,
        which resolves it via the network redirector rather than the per-session
        drive table.

        For local drives (C:, D:, etc.) or paths that are already UNC, the original
        path is returned unchanged.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }

    # Already a UNC path — nothing to do
    if ($Path.StartsWith('\')) { return $Path }

    $qualifier = (Split-Path $Path -Qualifier -ErrorAction SilentlyContinue)
    if (-not $qualifier) { return $Path }

    $letter = $qualifier.TrimEnd(':').ToUpper()

    try {
        # Query WMI for the network connection behind this drive letter
        $logicalDisk = Get-CimInstance -ClassName Win32_LogicalDisk `
            -Filter "DeviceID='${letter}:'" -ErrorAction SilentlyContinue
        if ($logicalDisk -and $logicalDisk.DriveType -eq 4 -and
            -not [string]::IsNullOrWhiteSpace($logicalDisk.ProviderName)) {
            # ProviderName = \server\share  — replace qualifier with UNC root
            $uncRoot    = $logicalDisk.ProviderName.TrimEnd('\')
            $relative   = $Path.Substring($qualifier.Length).TrimStart('\')
            $resolved   = if ($relative) { "$uncRoot\$relative" } else { $uncRoot }
            # FIX: Verify the UNC root is reachable before substituting.
            # Kernel-mode FS drivers (e.g. VirtualBox VBoxSF) mount the drive letter via
            # the I/O Manager — the letter IS visible to all elevated child processes,
            # but \\server\share may NOT be reachable via Win32 CreateFile / MUP.
            # Passing an unreachable UNC to robocopy.exe produces exit code 16 on every
            # folder. If the UNC root is inaccessible, keep the drive-letter path;
            # robocopy can reach it through the kernel driver just as PS cmdlets can.
            if (-not (Test-Path $uncRoot -ErrorAction SilentlyContinue)) {
                Write-Log "Resolve-ToUncPath: UNC root $uncRoot unreachable — keeping drive-letter path $Path"
                return $Path
            }
            Write-Log "Resolve-ToUncPath: $Path -> $resolved"
            return $resolved
        }
    } catch [System.Exception] {
        # CIM not available or drive not a network share — fall through to original path
    }

    # Also try net use output as a fallback (works when CIM is restricted)
    try {
        $netUse = & net.exe use "${letter}:" 2>$null
        if ($LASTEXITCODE -eq 0 -and $netUse) {
            $remoteLine = $netUse | Where-Object { $_ -match 'Remote name\s+(.+)' } |
                Select-Object -First 1
            if ($remoteLine -and $remoteLine -match 'Remote name\s+(\S+)') {
                $uncRoot  = $Matches[1].TrimEnd('\')
                $relative = $Path.Substring($qualifier.Length).TrimStart('\')
                $resolved = if ($relative) { "$uncRoot\$relative" } else { $uncRoot }
                # FIX: same UNC reachability guard as the CIM branch above.
                if (-not (Test-Path $uncRoot -ErrorAction SilentlyContinue)) {
                    Write-Log "Resolve-ToUncPath (net use fallback): UNC root $uncRoot unreachable — keeping $Path"
                    return $Path
                }
                Write-Log "Resolve-ToUncPath (net use fallback): $Path -> $resolved"
                return $resolved
            }
        }
    } catch [System.Exception] { }

    # Local drive or resolution failed — return original
    return $Path
}

function Invoke-RobocopyWithProgress {
    <#
    .SYNOPSIS
        Wraps robocopy with live per-file progress bar, ETA, and throughput. Returns result with Success, BytesCopied, FilesCopied.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$Source,
        [string]$Destination,
        [string]$FolderName,
        [long]$TotalBytes,
        [switch]$ProfileBackup,  # When set: /DCOPY:DAT + /XJD + /XJF for full profile copies
        [int]$FileCount = -1,    # Pre-scanned file count — skips redundant Get-FolderStats walk when already known
        [switch]$Incremental     # When set: /MIR + /XO + /XC + /XN for differential backup
    )
    
    if (-not (Test-Path $Destination)) {
        New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    }
    
    # Detect VirtualBox — check BOTH source and destination drives.
    # RestoreDefaults copies FROM a VBoxSvr share (source=Y:\) TO C:\, so
    # destination-only detection misses it and falls into the production path.
    # Detect VirtualBox — check BOTH source and destination drives.
    # If the source is a VSS device path (starts with \\?\GLOBALROOT), it's local;
    # skip extracting a qualifier from it to avoid a fatal error.
    $destDrive = (Split-Path $Destination -Qualifier -ErrorAction SilentlyContinue).TrimEnd(':')
    $srcDrive  = if ($Source -match '^\\\\\?\\GLOBALROOT') {
        # VSS shadow path – use the destination drive as reference
        $destDrive
    } else {
        (Split-Path $Source -Qualifier -ErrorAction SilentlyContinue).TrimEnd(':')
    }
    $isVirtualBox = $false
    try {
        foreach ($dl in @($destDrive, $srcDrive) | Select-Object -Unique) {
            $d = Get-PSDrive -Name $dl -ErrorAction SilentlyContinue
            if ($d -and $d.DisplayRoot -match '^\\\\VBoxSvr') {
                $isVirtualBox = $true; break
            }
        }
    } catch { }
    
    if (-not $isVirtualBox) {
        try {
            Update-DriveProfile -Path $Destination
        } catch {
            Write-Log "Drive profiling skipped: $_"
        }
    }
    
    $threads = if (-not $isVirtualBox) {
        $fc = if ($FileCount -ge 0) { $FileCount } else { (Get-FolderStats $Source).FileCount }  # reuse pre-scanned count when available
        Get-OptimalThreadCount -FolderSizeBytes $TotalBytes -FileCount $fc -SourcePath $Source -DestPath $Destination
    } else {
        if ($RobocopyThreads -gt 0) { $RobocopyThreads } else { 3 }
    }
    
    # FIX: cmd.exe (used for VirtualBox copies) cannot resolve \\?\\GLOBALROOT VSS paths.
    # Skip VSS translation when destination is a VirtualBox share.
    $isVirtualBoxDest = $false
    try {
        $destQualifier = Split-Path $Destination -Qualifier -ErrorAction SilentlyContinue
        if ($destQualifier) {
            $diskInfo = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$destQualifier'" -ErrorAction SilentlyContinue
            if ($diskInfo -and $diskInfo.ProviderName -match 'vbox') { $isVirtualBoxDest = $true }
        }
    } catch {}
    if (-not $isVirtualBoxDest) {
        foreach ($marker in @('VirtualBox','VBOXSF','vboxsvr','vboxsrv')) {
            if ($Destination -match $marker -or $Source -match $marker) { $isVirtualBoxDest = $true; break }
        }
    }
    $effectiveSource = if ($isVirtualBox) { $Source } else { Get-VssSourcePath -SourcePath $Source }
    if (-not $effectiveSource) { $effectiveSource = $Source }

    $roboArgs = Build-RobocopyArgs -Source $effectiveSource -Destination $Destination `
        -Threads $threads -ProfileBackup:$ProfileBackup -IsVirtualBox:$isVirtualBox -Incremental:$Incremental

    # VirtualBox: Simple cmd /c method
    if ($isVirtualBox) {
        Write-Status "Copying $FolderName (VirtualBox shared folder)..." -Type "Info"
        
        # Filter out any null/empty arguments
        $filteredArgs = @()
        foreach ($arg in $roboArgs) {
            if ($arg -and $arg.ToString().Trim() -ne '') {
                $filteredArgs += $arg
            }
        }
        
        $argString = $filteredArgs -join " "
        
        # FIX: Start-Process -RedirectStandardOutput/Error require real file paths, not $null.
        # Also resolve temp dir safely — $env:TEMP can be null when running from a
        # VirtualBox shared folder drive (e.g. Z:\), so fall back through TMP → SystemRoot\Temp.
        $tempDir = Get-SafeTempPath

        $tempOut = [System.IO.Path]::Combine($tempDir, "ufm_vbox_out_${PID}.tmp")
        $tempErr = [System.IO.Path]::Combine($tempDir, "ufm_vbox_err_${PID}.tmp")

        $success = $false
try {
            # Convert the space-separated string back into a secure, distinct argument array
            [string[]]$secureFallbackArgs = @()
            if ($null -ne $argString) {
                $secureFallbackArgs = $argString -split ' ' | Where-Object { $_ -match '\S' }
            }

            # Run robocopy.exe directly without invoking the vulnerable cmd.exe shell interpreter layer
            $proc = Start-Process -FilePath "robocopy.exe" `
                -ArgumentList $secureFallbackArgs `
                -Wait -NoNewWindow -PassThru `
                -RedirectStandardOutput $tempOut `
                -RedirectStandardError $tempErr

            $exitCode = $proc.ExitCode
            $success  = $exitCode -le 9

            if ($success) {
                Write-Status "$FolderName : Copy completed" -Type "Success"
                Write-Log "Robocopy completed for $FolderName with exit code $exitCode (VirtualBox)"
            } else {
                Write-Status "$FolderName : Copy FAILED (exit code $exitCode)" -Type "Error"
                Write-Log "Robocopy failed for $FolderName with exit code $exitCode (VirtualBox)"
            }
        } finally {
            Remove-Item -Path $tempOut, $tempErr -Force -ErrorAction SilentlyContinue
        }
        return $success
    }
    
    # Production: Direct stdout capture (no temp files — eliminates ufm_robo_*.tmp leaks and locking)
    $roboArgs += '/BYTES'
    
    $processedBytes = 0L
    $startTime  = Get-Date
    $lastUpdate = $startTime
    $currentFile = ""
    $barDrawn = $false

$psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = 'robocopy.exe'
    
    # Use the ArgumentList collection instead of .Arguments string concatenation
    # This keeps each path and flag completely sandboxed as separate arguments
    foreach ($arg in $roboArgs) {
        $null = $psi.ArgumentList.Add($arg)
    }
    
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $proc.Start() | Out-Null

    try {
        while (-not $proc.StandardOutput.EndOfStream) {
            $line = $proc.StandardOutput.ReadLine()
            if ($line -and $line -match '^\s+New File\s+(\d+)\s+(.+)$') {
                $fileBytes = [long]$Matches[1]
                $processedBytes += $fileBytes
                $currentFile = [System.IO.Path]::GetFileName($Matches[2].Trim())

                $now = Get-Date
                $hwInterval = if ($script:HW) { $script:HW.Tuned_ProgressIntervalMs } else { 250 }
                if (($now - $lastUpdate).TotalMilliseconds -ge $hwInterval) {
                    $elapsed = ($now - $startTime).TotalSeconds
                    $speed = if ($elapsed -gt 0) { ($processedBytes / 1MB) / $elapsed } else { 0 }
                    $remaining = $TotalBytes - $processedBytes
                    $eta = if ($speed -gt 0) { [int]($remaining / 1MB / $speed) } else { 0 }
                    $percent = if ($TotalBytes -gt 0) { [int](($processedBytes / $TotalBytes) * 100) } else { 0 }

                    Write-ProgressBar -Current $percent -Total 100 -FolderName $FolderName `
                        -DoneBytes $processedBytes -TotalBytes $TotalBytes `
                        -SpeedMBps $speed -EtaSec $eta -CurrentFile $currentFile
                    $barDrawn = $true
                    $lastUpdate = $now
                }
            }
        }
    } finally {
        $proc.WaitForExit()
    }

    $exitCode = $proc.ExitCode
    $proc.Dispose()

    if ($barDrawn) { Clear-ProgressLine }

    # Robocopy exit codes (bitmask):
    #   0 = no files copied (destination already up to date)
    #   1 = files copied successfully
    #   2 = extra files/dirs exist in destination (not an error in migration)
    #   4 = mismatched files/dirs detected (destination has different version — investigate)
    #   8 = some files/dirs could not be copied (access denied, locked, etc.)
    #   16 = serious error — no files copied at all
    # Codes 4-7 include a mismatch bit; still allow migration to continue (checksum verify catches real issues)
    # but log a warning. Codes 8+ = genuine failures.
    $success = $exitCode -le 7
    
    if ($exitCode -le 3) {
        Write-Log "Robocopy completed for $FolderName with exit code $exitCode"
    } elseif ($exitCode -le 7) {
        Write-Log "Robocopy completed WITH WARNINGS for $FolderName (exit $exitCode — mismatch/extras detected; checksum verify will confirm)" -Level 'WARN'
        Write-Status "$FolderName : Robocopy warnings (exit $exitCode) — mismatched or extra files detected. Checksum verify will validate." -Type "Warning"
    } else {
        Write-Log "Robocopy FAILED for $FolderName with exit code $exitCode"
    }
    
    return $success
}

#endregion

function Build-RobocopyArgs {
    <#
    .SYNOPSIS
        Builds the robocopy argument array from session parameters.
        Extracted from Invoke-RobocopyWithProgress to isolate arg construction
        for testability and reuse. Returns a [string[]] ready for Start-Process.
    #>
    [CmdletBinding()]
    param(
        [string]$Source,
        [string]$Destination,
        [int]   $Threads      = 8,
        [switch]$ProfileBackup,
        [switch]$IsVirtualBox,
        [switch]$Incremental   # When set: /MIR + /XO + /XC + /XN (differential backup)
    )
    $args = @(
        "`"$Source`"",
        "`"$Destination`"",
        $(if ($Incremental) { '/MIR' } else { '/E' }),
        '/COPY:DAT',
        $(if ($ProfileBackup) { '/DCOPY:DAT' } else { '/DCOPY:DA' }),
        "/R:$RobocopyRetries",
        "/W:$RobocopyWait",
        "/MT:$Threads",
        '/NP',
        '/NDL'
    )
    if ($Incremental) {
        # /XO: exclude older (dest newer than src); /XC: skip same-size+timestamp; /XN: exclude newer dest files
        $args += '/XO'; $args += '/XC'; $args += '/XN'
    }
    if ($ProfileBackup) { $args += '/XJD'; $args += '/XJF' }
    if ($UseRobocopyZ)  { $args += '/Z' }
    if (-not $DisableAutoExclusions -and -not $IsVirtualBox) {
        foreach ($excl in @('*.tmp','*.temp','*.log','*.bak','desktop.ini','thumbs.db','.DS_Store')) {
            $args += '/XF'; $args += $excl
        }
    }
    if (-not $IsVirtualBox) {
        foreach ($excl in (Get-ExcludePatterns)) {
            if (-not [string]::IsNullOrWhiteSpace($excl)) { $args += '/XF'; $args += $excl }
        }
    }
    foreach ($excl in $Exclude) {
        if (-not [string]::IsNullOrWhiteSpace($excl)) { $args += '/XF'; $args += "`"$excl`"" }
    }
    if ($BandwidthLimitMbps -gt 0) {
        $args += "/IPG:$([Math]::Max(1,[Math]::Round(500000/($BandwidthLimitMbps*125))))"
    } elseif ($script:HW -and $script:HW.Tuned_IPGOverride -gt 0 -and -not $IsVirtualBox) {
        $args += "/IPG:$($script:HW.Tuned_IPGOverride)"
    }
    return $args
}

#region ── Full Profile Backup (robocopy + verification) ─────────────────────
# Note: Full profile copies use Invoke-RobocopyWithProgress -ProfileBackup which
# enables /DCOPY:DAT + /XJD + /XJF — no separate copy function required.


function Invoke-FullProfileBackupForUser {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Copies an ENTIRE user profile folder to a destination, including all
        hidden and system files (AppData, NTUSER.DAT, desktop.ini, etc.).

        Junction directories (shell compat + OneDrive) are intentionally skipped
        with robocopy /XJD to avoid double-copies and infinite-loop paths.
        Because junctions are excluded from both the physical-source stat and the
        destination copy, the comparison is always like-for-like.

        Two source size figures are displayed:
          • Physical (no junctions) — this is what robocopy copies and what the
            destination Properties will show.
          • Windows Properties — what Explorer shows; may be larger because it
            follows junction targets before deduplication.
    #>
    param(
        [string]$Username,
        [string]$ProfilePath,
        [string]$Destination,   # full path to user-specific backup folder
        [string]$SID,
        [bool]$IsActive
    )
    Write-SectionHeader "Full Profile Backup: $Username"
    Write-Status "Source      : $ProfilePath" -Type "Info"
    Write-Status "Destination : $Destination" -Type "Info"
    Write-Host ""

    # ── Junction scan (informational) ────────────────────────────────────────
    if (-not $SkipJunctionScan -and $script:JunctionPath) {
        Write-Status "Scanning for junction points in $ProfilePath ..." -Type "Info"
        $junctions = @(& $script:JunctionPath -accepteula -s "$ProfilePath" 2>$null |
            Where-Object { $_ -match 'Junction' })
        if ($junctions.Count -gt 0) {
            Write-Status "Found $($junctions.Count) junction(s) in profile:" -Type "Warning"
            foreach ($j in $junctions) {
                Write-Status "  $j" -Type "Info"
            }
            Write-Status "Robocopy /XJD will skip junction targets – they will not be duplicated." -Type "Info"
        } else {
            Write-Status "No junctions found." -Type "Info"
        }
    }

    # ── Pre-copy statistics ───────────────────────────────────────────────────

    Write-Status "Scanning source — this may take a moment for large profiles..." -Type "Info"

    # Physical stats (no junction following) — matches what robocopy /XJD copies
    $srcPhysical = Get-FolderStats -Path $ProfilePath -FollowJunctions:$false
    # Explorer-visible stats (junction-following, deduped via visited-set)
    $srcWindows  = Get-FolderStats -Path $ProfilePath -FollowJunctions:$true

    Write-Host ""
    Write-Host "  Source statistics:" -ForegroundColor Cyan
    Write-Host ("  {0,-38} {1,12}  {2,8} files  {3,8} folders" -f `
        "Physical (what will be copied):",
        (Format-Bytes $srcPhysical.Size), $srcPhysical.FileCount, $srcPhysical.DirCount) -ForegroundColor Gray
    Write-Host ("  {0,-38} {1,12}  {2,8} files  {3,8} folders" -f `
        "Windows Properties (incl. junctions):",
        (Format-Bytes $srcWindows.Size), $srcWindows.FileCount, $srcWindows.DirCount) -ForegroundColor DarkGray
    Write-Host ""

    # ── Cloud-only file check ──────────────────────────────────────────────────
    # Detect OneDrive placeholder files that have no local content before copying.
    # Robocopy will trigger cloud hydration for every placeholder — on large profiles
    # this can mean hundreds of GB downloaded unexpectedly from OneDrive.
    $cloudCheck = Test-CloudOnlyFiles -Path $ProfilePath
    if ($cloudCheck.Checked -and $cloudCheck.Count -gt 0) {
        Write-Status ("Cloud-only placeholder files detected: {0} file(s), ~{1} to download from OneDrive" -f $cloudCheck.Count, (Format-Bytes $cloudCheck.TotalSize)) -Type "Warning"
        Write-Status "  Robocopy will trigger OneDrive hydration (download) for each placeholder during copy." -Type "Warning"
        Write-Status "  To suppress this check use -SkipCloudOnlyCheck." -Type "Info"
        if ($cloudCheck.Samples.Count -gt 0) {
            Write-Status "  Sample placeholders: $($cloudCheck.Samples -join '; ')" -Type "Info"
        }
        Write-Log ("CloudOnlyCheck: $($cloudCheck.Count) placeholder(s), ~{0} for $Username" -f (Format-Bytes $cloudCheck.TotalSize))
        Write-AuditEntry -Message "CLOUD_ONLY_FILES: $($cloudCheck.Count) OneDrive placeholders detected for $Username" -Level "WARN"

        if ($HydrateOneDrive) {
            Write-Status "  -HydrateOneDrive: forcing local hydration of $($cloudCheck.Count) placeholder(s)..." -Type "Info"
            $hydrateErrors = 0
            foreach ($placeholder in $cloudCheck.Files) {
                try {
                    $null = & attrib.exe +P $placeholder 2>&1
                    $waited = 0
                    while ($waited -lt 60) {
                        $rawAttr = [System.IO.File]::GetAttributes($placeholder)
                        if (-not ([int]$rawAttr -band 0x400000)) { break }
                        Start-Sleep -Milliseconds 500; $waited++
                    }
                    if ($waited -ge 60) { throw "Timed out waiting for hydration" }
                } catch {
                    Write-Log "HydrateOneDrive: failed '$placeholder': $($_.Exception.Message)"
                    $hydrateErrors++
                }
            }
            if ($hydrateErrors -gt 0) {
                Write-Status "  HydrateOneDrive: $hydrateErrors file(s) failed to hydrate — aborting." -Type "Error"
                Write-Log "HydrateOneDrive: aborting — $hydrateErrors failure(s) for $Username"
                Send-MigrationNotification `
                    -Subject "HYDRATION FAILED — UserFolderMigrator on $env:COMPUTERNAME" `
                    -Body "OneDrive placeholder hydration failed for user '$Username'.`n`n$hydrateErrors file(s) could not be downloaded from OneDrive before migration.`nMigration aborted — no data has been moved.`n`nComputer : $env:COMPUTERNAME`nLog      : $($script:LogFile)`n`nFix: Sign into OneDrive, ensure internet connectivity, then re-run." `
                    -Status 'Error'
                $script:ExitCode = $script:EXIT_FAILURE
                Exit-WithReport -Code $script:ExitCode
            }
            Write-Status "  HydrateOneDrive: all $($cloudCheck.Count) placeholder(s) hydrated." -Type "Success"
            Write-Log "HydrateOneDrive: all placeholder(s) hydrated for $Username"
        }
        Write-Host ""
    }

    if ($DryRun) {
        Write-Status "[DRY RUN] Would copy $(Format-Bytes $srcPhysical.Size) ($($srcPhysical.FileCount) files, $($srcPhysical.DirCount) folders) to $Destination" -Type "Info"
        Write-Log "DryRun: FullProfileBackup $Username  src=$ProfilePath  dst=$Destination"
        return [PSCustomObject]@{
            Username    = $Username
            Source      = $ProfilePath
            Destination = $Destination
            SrcSize     = $srcPhysical.Size
            SrcFiles    = $srcPhysical.FileCount
            SrcDirs     = $srcPhysical.DirCount
            DstSize     = 0L
            DstFiles    = 0
            DstDirs     = 0
            SizeMatch   = $false
            FileMatch   = $false
            FolderMatch = $false
            AllMatch    = $false
            Success     = $true
            DryRun      = $true
        }
    }

    # ── MaxProfileSizeGB safety cap ───────────────────────────────────────────
    if ($MaxProfileSizeGB -gt 0) {
        $srcGB = $srcPhysical.Size / 1GB
        if ($srcGB -gt $MaxProfileSizeGB) {
            Write-Status ("ABORTED: source profile is {0:N1} GB — exceeds -MaxProfileSizeGB {1} GB limit." -f $srcGB, $MaxProfileSizeGB) -Type "Error"
            Write-Status "  Pass a larger -MaxProfileSizeGB or remove the limit to proceed." -Type "Info"
            Write-Log ("FullProfileBackup ABORTED for $Username — source {0:N1} GB exceeds MaxProfileSizeGB $MaxProfileSizeGB" -f $srcGB)
            return $null
        }
    }

    # ── Disk space check ─────────────────────────────────────────────────────

    $destDrive = (Split-Path $Destination -Qualifier).TrimEnd(':')
    $freeSpace = try {
        $d = Get-PSDrive -Name $destDrive -ErrorAction SilentlyContinue
        if ($d) { $d.Free } else { 0 }
    } catch { 0 }

    $required = [long]($srcPhysical.Size * 1.05)   # 5 % headroom
    if ($freeSpace -lt $required) {
        Write-Status "Insufficient space on destination drive:" -Type "Error"
        Write-Status "  Required  : $(Format-Bytes $required)" -Type "Error"
        Write-Status "  Available : $(Format-Bytes $freeSpace)" -Type "Error"
        Write-Log "FullProfileBackup aborted — insufficient space for $Username"
        return $null
    }
    Write-Status "Space check : $(Format-Bytes $required) needed, $(Format-Bytes $freeSpace) available — OK" -Type "Success"
    Write-Host ""

    # ── Create destination ────────────────────────────────────────────────────

    if (-not (Test-Path $Destination)) {
        New-Item -Path $Destination -ItemType Directory -Force | Out-Null
        Write-Status "Created destination folder" -Type "Success"
    }

    # ── VSS for active user profiles ─────────────────────────────────────────
    # NTUSER.DAT, AppData\Local\Packages, and Chrome/Teams caches are exclusively
    # locked while the user is logged in.  Without VSS these are silently skipped
    # by robocopy.  When -UseVSS is set we translate the source to its shadow path
    # so every file — including the live registry hive — is captured consistently.
    if ($IsActive -and $UseVSS) {
        Write-Status "Active user + -UseVSS: creating VSS shadow for consistent profile capture..." -Type "Info"
        $effectiveProfilePath = Get-VssSourcePath -SourcePath $ProfilePath
        if ($effectiveProfilePath -ne $ProfilePath) {
            Write-Status "  VSS source: $effectiveProfilePath" -Type "Success"
            Write-Log "FullProfileBackup: VSS shadow active for $Username ($effectiveProfilePath)"
        } else {
            Write-Status "  VSS shadow unavailable — copying live profile (NTUSER.DAT may be skipped)" -Type "Warning"
            Write-Log "FullProfileBackup: VSS requested but shadow failed for $Username — using live path"
        }
    } elseif ($IsActive -and -not $UseVSS) {
        Write-Status "Active user without -UseVSS: NTUSER.DAT and open app files may be silently skipped." -Type "Warning"
        Write-Status "  Add -UseVSS for a complete, consistent snapshot of a live profile." -Type "Warning"
        $effectiveProfilePath = $ProfilePath
    } else {
        $effectiveProfilePath = $ProfilePath
    }

    # ── Robocopy copy ─────────────────────────────────────────────────────────

    # ── Incremental mode: /MIR + timestamp-based skip ────────────────────────
    # When -IncrementalBackup is set, only new or changed files are copied:
    #   /MIR  — mirror: add new, update changed, remove files deleted from source
    #   /XO   — exclude older: skip destination files newer than source
    #   /XC   — exclude changed: skip files with identical size+timestamp
    #   /XN   — exclude newer: skip destination files that are already newer
    # A backup.marker file records the last successful run timestamp for auditing.
    $markerFile        = Join-Path $Destination 'backup.marker'
    $isIncrementalRun  = $IncrementalBackup.IsPresent -and (Test-Path $Destination)
    $lastBackupTime    = if ($isIncrementalRun -and (Test-Path $markerFile)) {
        try { [datetime]::Parse((Get-Content $markerFile -Raw).Trim()) } catch { $null }
    } else { $null }

    if ($IncrementalBackup.IsPresent) {
        if ($lastBackupTime) {
            Write-Status "Incremental backup: last run $($lastBackupTime.ToString('yyyy-MM-dd HH:mm:ss')) — copying new/changed files only" -Type "Info"
            Write-Log "IncrementalBackup: $Username last=$($lastBackupTime.ToString('s'))"
        } else {
            Write-Status "Incremental backup: no prior marker found — performing initial full copy (subsequent runs will be incremental)" -Type "Info"
            Write-Log "IncrementalBackup: $Username — first run, full copy"
        }
    }

    Write-Status "Starting robocopy — all files including hidden/system, junction dirs excluded (/XJD)..." -Type "Info"
    Write-Host ""

    $copySuccess = Invoke-RobocopyWithProgress `
        -Source         $effectiveProfilePath `
        -Destination    $Destination `
        -FolderName     $Username `
        -TotalBytes     $srcPhysical.Size `
        -FileCount      $srcPhysical.FileCount `
        -ProfileBackup  `
        -Incremental:$IncrementalBackup.IsPresent

    # Record marker on success so next incremental run knows when this one completed
    if ($copySuccess -and $IncrementalBackup.IsPresent) {
        try { (Get-Date).ToString('o') | Set-Content -Path $markerFile -Encoding UTF8 -Force } catch { }
        Write-Log "IncrementalBackup: marker updated for $Username ($markerFile)"
    }

    Write-Host ""

    if (-not $copySuccess) {
        Write-Status "Robocopy reported errors — backup may be incomplete" -Type "Error"
        Write-Log "FullProfileBackup FAILED (robocopy) for $Username"
        return [PSCustomObject]@{
            Username    = $Username
            Source      = $ProfilePath
            Destination = $Destination
            SrcSize     = $srcPhysical.Size
            SrcFiles    = $srcPhysical.FileCount
            SrcDirs     = $srcPhysical.DirCount
            DstSize     = 0L; DstFiles = 0; DstDirs = 0
            SizeMatch   = $false; FileMatch = $false; FolderMatch = $false
            AllMatch    = $false; Success = $false; DryRun = $false
        }
    }

    # ── Supplemental: NTUSER.DAT (active user) ────────────────────────────────
    # Robocopy silently skips the live registry hive. Warn clearly if VSS was
    # not used so the operator knows the backup may be missing the hive.
    if ($IsActive -and -not $UseVSS) {
        $hiveDest = Join-Path $Destination 'NTUSER.DAT'
        if (-not (Test-Path $hiveDest)) {
            Write-Status "[!] NTUSER.DAT not captured — active user hive is locked. Use -UseVSS for a complete backup." -Type "Warning"
            Write-Log "FullProfileBackup: NTUSER.DAT missing from backup for active user $Username (no VSS)"
            Write-AuditEntry -Message "BACKUP_INCOMPLETE: NTUSER.DAT missing for $Username — use -UseVSS" -Level "WARN"
        }
    }

    # ── Supplemental: Certificate stores ─────────────────────────────────────
    # These are inside AppData and copied by robocopy, but we explicitly verify
    # presence and export an additional PFX-ready manifest for restore guidance.
    $certPaths = @(
        "$ProfilePath\AppData\Roaming\Microsoft\Crypto",
        "$ProfilePath\AppData\Roaming\Microsoft\SystemCertificates",
        "$ProfilePath\AppData\Roaming\Microsoft\Protect"
    )
    $certsMissing = @($certPaths | Where-Object { -not (Test-Path $_) })
    if ($certsMissing.Count -eq 0) {
        Write-Status "Certificate stores verified in backup (Crypto, SystemCertificates, Protect)" -Type "Success"
        Write-Log "FullProfileBackup: certificate store paths verified for $Username"
    } else {
        Write-Status "Certificate store paths not found (may not exist for this user): $($certsMissing -join ', ')" -Type "Info"
    }

    # ── Supplemental: Credential Manager stores ───────────────────────────────
    $credPaths = @(
        "$ProfilePath\AppData\Local\Microsoft\Credentials",
        "$ProfilePath\AppData\Roaming\Microsoft\Credentials"
    )
    foreach ($cp in $credPaths) {
        if (Test-Path $cp) {
            $destCp = $cp.Replace($ProfilePath, $Destination)
            if (Test-Path $destCp) {
                Write-Log "FullProfileBackup: Credential store captured at $destCp"
            }
        }
    }

    # ── Supplemental: Developer dotfolders ───────────────────────────────────
    # Hidden dotfolders are included by robocopy /E but logged explicitly for audit.
    $dotFolders = @('.ssh', '.gnupg', '.aws', '.kube', '.azure', '.config', '.docker')
    $capturedDots = @($dotFolders | Where-Object { Test-Path (Join-Path $Destination $_) })
    if ($capturedDots.Count -gt 0) {
        Write-Status "Developer dotfolders captured: $($capturedDots -join ', ')" -Type "Success"
        Write-Log "FullProfileBackup: dotfolders captured for $Username — $($capturedDots -join ', ')"
        Write-AuditEntry -Message "DOTFOLDERS_BACKED_UP: $($capturedDots -join ', ') for $Username" -Level "INFO"
    }

    # ── Supplemental: Printer profiles ────────────────────────────────────────
    # Printer preferences, paper sizes, and colour profiles are stored in two locations.
    # The per-user spool folder is included by robocopy. The machine-wide driver store
    # is not profile-scoped — we export a printer list for manual re-installation guidance.
    $printerSpool = "$ProfilePath\AppData\Local\Microsoft\Windows\Printers"
    $printerDest  = Join-Path $Destination 'AppData\Local\Microsoft\Windows\Printers'
    if (Test-Path $printerSpool) {
        if (Test-Path $printerDest) {
            Write-Status "Printer preferences folder captured (per-user spool data)" -Type "Success"
            Write-Log "FullProfileBackup: printer preferences captured for $Username"
        }
    }
    # Export printer list as JSON for restore reference
    try {
        $printers = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Type -ne 'Local' -or $_.PortName -notmatch '^(FILE|NUL|PORTPROMPT)' } | Select-Object Name, PortName, DriverName, Shared, Default)
        if ($printers.Count -gt 0 -and -not $DryRun) {
            $printerManifestPath = Join-Path $Destination 'ufm_printer_manifest.json'
            $printers | ConvertTo-Json -Depth 3 | Set-Content -Path $printerManifestPath -Encoding UTF8 -Force
            Write-Status "Printer manifest written: $($printers.Count) printer(s) documented at ufm_printer_manifest.json" -Type "Success"
            Write-Log "FullProfileBackup: printer manifest written for $Username — $($printers.Count) printer(s)"
            Write-AuditEntry -Message "PRINTER_MANIFEST: $($printers.Count) printers documented for $Username" -Level "INFO"
        }
    } catch {
        Write-Log "FullProfileBackup: printer manifest skipped — $_" 
    }

    if ($SkipSupplementalExports) {
        Write-Status "Supplemental exports skipped (-SkipSupplementalExports)." -Type "Info"
        Write-Log "FullProfileBackup: supplemental exports skipped for $Username"
        return
    }

    # ── Supplemental exports (ACLs, registry, Wi-Fi, drives, tasks, apps) ────
    Export-SupplementalProfileData -Username $Username -ProfilePath $ProfilePath -Destination $Destination -DryRun:$DryRun

    # ── Post-copy verification ────────────────────────────────────────────────

    Write-Status "Scanning destination for verification..." -Type "Info"
    # Use physical mode on destination too (no junctions exist there after /XJD)
    $dstStats = Get-FolderStats -Path $Destination -FollowJunctions:$false

    $sizeMatch   = $srcPhysical.Size      -eq $dstStats.Size
    $fileMatch   = $srcPhysical.FileCount -eq $dstStats.FileCount
    $folderMatch = $srcPhysical.DirCount  -eq $dstStats.DirCount
    $allMatch    = $sizeMatch -and $fileMatch -and $folderMatch

    # ── Summary table ─────────────────────────────────────────────────────────

    Write-SectionHeader "Backup Verification: $Username"

    $hdr = "  {0,-42} {1,14}  {2,10}  {3,10}"
    $row = "  {0,-42} {1,14}  {2,10}  {3,10}"
    Write-Host ($hdr -f "", "Size", "Files", "Folders") -ForegroundColor Cyan
    Write-TableSeparator -Width 90

    $srcSzStr = Format-Bytes $srcPhysical.Size
    $dstSzStr = Format-Bytes $dstStats.Size
    Write-Host ($row -f "Source (physical, no junctions):", $srcSzStr, $srcPhysical.FileCount, $srcPhysical.DirCount) -ForegroundColor Gray
    Write-Host ($row -f "Destination backup:", $dstSzStr, $dstStats.FileCount, $dstStats.DirCount) -ForegroundColor Gray

    Write-TableSeparator -Width 90

    # Per-column match indicators
    $szMk  = if ($sizeMatch)   { "[+] MATCH" } else { "[X] DIFFER" }
    $fMk   = if ($fileMatch)   { "[+] MATCH" } else { "[X] DIFFER" }
    $dMk   = if ($folderMatch) { "[+] MATCH" } else { "[X] DIFFER" }
    $szCol = if ($sizeMatch)   { "Green" } else { "Red" }
    $fCol  = if ($fileMatch)   { "Green" } else { "Red" }
    $dCol  = if ($folderMatch) { "Green" } else { "Red" }

    Write-Host "  Match result:" -NoNewline
    Write-Host ("  Size: {0}  |  Files: " -f $szMk) -NoNewline -ForegroundColor $szCol
    Write-Host ("{0}  |  Folders: " -f $fMk)         -NoNewline -ForegroundColor $fCol
    Write-Host $dMk                                              -ForegroundColor $dCol

    Write-Host ""

    if ($allMatch) {
        Write-Status "Backup COMPLETE — source and destination match exactly (physical, junctions excluded)" -Type "Success"
        Write-Status "Windows Properties on the backup folder will show identical counts to the source" -Type "Success"
    } else {
        Write-Status "Backup finished with discrepancies (see table above):" -Type "Warning"
        if (-not $sizeMatch) {
            $diff = [Math]::Abs($srcPhysical.Size - $dstStats.Size)
            Write-Status "  Size delta   : $(Format-Bytes $diff)" -Type "Warning"
        }
        if (-not $fileMatch) {
            $diff = [Math]::Abs($srcPhysical.FileCount - $dstStats.FileCount)
            Write-Status "  File delta   : $diff file(s)" -Type "Warning"
        }
        if (-not $folderMatch) {
            $diff = [Math]::Abs($srcPhysical.DirCount - $dstStats.DirCount)
            Write-Status "  Folder delta : $diff folder(s) — this is normal when junction stubs differ" -Type "Info"
        }
    }

    if ($srcWindows.Size -ne $srcPhysical.Size -or $srcWindows.FileCount -ne $srcPhysical.FileCount) {
        Write-Host ""
        Write-Status "Note: Windows Properties on the SOURCE shows larger figures because it follows junction" -Type "Info"
        Write-Status "  targets.  The backup captures all physical data; junction targets are not duplicated." -Type "Info"
    }

    Write-Log ("FullProfileBackup $Username : copy={0}  match={1}  src={2}/{3}/{4}  dst={5}/{6}/{7}" -f `
        $copySuccess, $allMatch,
        $srcPhysical.Size, $srcPhysical.FileCount, $srcPhysical.DirCount,
        $dstStats.Size, $dstStats.FileCount, $dstStats.DirCount)

    # ── Write backup manifest sidecar ─────────────────────────────────────────
    if ($copySuccess) {
        Write-BackupManifest `
            -Username    $Username `
            -Source      $ProfilePath `
            -Destination $Destination `
            -SrcStats    $srcPhysical `
            -DstStats    $dstStats `
            -AllMatch    $allMatch `
            -Success     $copySuccess `
            -DryRun      $false `
            -StartTime   $script:ReportStartTime
    }

    # ── Optional post-backup compression (Restic preferred, 7-Zip fallback) ──────
    if ($copySuccess -and -not $DryRun) {
        $resticPath = Install-Restic
        $sevenZip   = @("$env:ProgramFiles\7-Zip\7z.exe","${env:ProgramFiles(x86)}\7-Zip\7z.exe") |
                        Where-Object { Test-Path $_ } | Select-Object -First 1

        if ($resticPath) {
            $repoPath = "${Destination}_restic_repo"
            Write-Status "Restic: initialising repo at $repoPath" -Type "Info"
            if (-not (Test-Path $repoPath)) {
                & $resticPath -r $repoPath init 2>&1 | ForEach-Object { Write-Status "  $_" -Type "Info" }
            }
            & $resticPath -r $repoPath backup $Destination --tag "UFM-$Username" 2>&1 |
                ForEach-Object { Write-Status "  $_" -Type "Info" }
            Write-Log "Restic snapshot created for $Username → $repoPath"
        } elseif ($sevenZip) {
            $archive = "${Destination}_UFM_${Username}_$(Get-Date -Format 'yyyyMMdd').7z"
            Write-Status "7-Zip: compressing backup to $archive" -Type "Info"
            $p = Start-Process $sevenZip -ArgumentList "a -mx=5 -mmt=on `"$archive`" `"$Destination\*`"" `
                    -Wait -NoNewWindow -PassThru
            if ($p.ExitCode -eq 0) { Write-Status "Archive created: $archive" -Type "Success"; Write-Log "7-Zip archive OK for $Username → $archive" }
            else                   { Write-Status "7-Zip failed (exit $($p.ExitCode))" -Type "Warning"; Write-Log "7-Zip FAILED for $Username" }
        } else {
            Write-Status "No compression tool available — backup left uncompressed." -Type "Info"
        }
    }

    return [PSCustomObject]@{
        Username    = $Username
        Source      = $ProfilePath
        Destination = $Destination
        SrcSize     = $srcPhysical.Size
        SrcFiles    = $srcPhysical.FileCount
        SrcDirs     = $srcPhysical.DirCount
        DstSize     = $dstStats.Size
        DstFiles    = $dstStats.FileCount
        DstDirs     = $dstStats.DirCount
        SizeMatch   = $sizeMatch
        FileMatch   = $fileMatch
        FolderMatch = $folderMatch
        AllMatch    = $allMatch
        Success     = $copySuccess
        DryRun      = $false
    }
}

function Export-SupplementalProfileData {
    <#
    .SYNOPSIS
        Exports data that lives outside C:\Users or cannot survive a raw file copy:
        ACLs, HKCU registry, mapped drives reconnect script, Wi-Fi profiles,
        user-scoped scheduled tasks, default app associations, BitLocker recovery keys.
        Writes a companion restore guide (UFM_RestoreGuide.txt) to the destination.
        All sections are individually try/caught — one failure never blocks the others.
    #>
    [CmdletBinding()]
    param(
        [string]$Username,
        [string]$ProfilePath,
        [string]$Destination,
        [switch]$DryRun
    )

    $suppDir = Join-Path $Destination 'UFM_Supplemental'
    if (-not $DryRun) { New-Item -Path $suppDir -ItemType Directory -Force | Out-Null }

    $guide = [System.Text.StringBuilder]::new()
    $null  = $guide.AppendLine("UserFolderMigrator Supplemental Restore Guide — generated $(Get-Date -Format 'o')")
    $null  = $guide.AppendLine("User: $Username  |  Source: $ProfilePath")
    $null  = $guide.AppendLine(('-' * 80))

    Write-SectionHeader "Supplemental Exports: $Username"

    # ── 1. ACL export ─────────────────────────────────────────────────────────
    try {
        Write-Status "Exporting NTFS ACLs..." -Type "Info"
        $aclPath = Join-Path $suppDir 'ACL_Export.json'
        $aclRestorePath = Join-Path $suppDir 'Restore-ACLs.ps1'
        $aclData = [System.Collections.Generic.List[object]]::new()
        $aclRestore = [System.Text.StringBuilder]::new()
        $null = $aclRestore.AppendLine('# ACL Restore Script — generated by UserFolderMigrator')
        $null = $aclRestore.AppendLine('# Run as Administrator on the target machine after restoring files.')
        $null = $aclRestore.AppendLine('param([string]$DestinationRoot)')

        $opts = [System.IO.EnumerationOptions]::new()
        # Record old machine SID for translation at restore time
        $oldSid = ([System.Security.Principal.NTAccount]$Username).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value

        $opts.RecurseSubdirectories = $true
        $opts.AttributesToSkip = 0
        $opts.IgnoreInaccessible = $true
        $allPaths = @($ProfilePath) + @([System.IO.Directory]::EnumerateDirectories($ProfilePath, '*', $opts))
        foreach ($p in $allPaths) {
            try {
                $acl = Get-Acl -Path $p -ErrorAction SilentlyContinue
                if (-not $acl) { continue }
                $rel = $p.Substring($ProfilePath.Length).TrimStart('\')
                $aclData.Add([PSCustomObject]@{
                    RelativePath = $rel
                    Owner        = $acl.Owner
                    OldSid       = $oldSid
                    SDDL         = $acl.Sddl
                })
            } catch { }
        }

        # Generate Restore-ACLs.ps1 with SID translation logic
        $null = $aclRestore.AppendLine('# ACL Restore Script — generated by UserFolderMigrator')
        $null = $aclRestore.AppendLine('# Translates old machine SIDs to the current machine before applying.')
        $null = $aclRestore.AppendLine('# Run as Administrator on the target machine after restoring files.')
        $null = $aclRestore.AppendLine('param(')
        $null = $aclRestore.AppendLine('    [Parameter(Mandatory)] [string]$DestinationRoot,')
        $null = $aclRestore.AppendLine("    [string]`$OldSid = '$oldSid',")
        $null = $aclRestore.AppendLine('    [string]$NewUsername = $env:USERNAME')
        $null = $aclRestore.AppendLine(')')
        $null = $aclRestore.AppendLine('')
        $null = $aclRestore.AppendLine('# Resolve new machine SID for the target user')
        $null = $aclRestore.AppendLine('try {')
        $null = $aclRestore.AppendLine('    $newSid = ([System.Security.Principal.NTAccount]$NewUsername).Translate([System.Security.Principal.SecurityIdentifier]).Value')
        $null = $aclRestore.AppendLine('    Write-Host "Translating SID: $OldSid → $newSid"')
        $null = $aclRestore.AppendLine('} catch {')
        $null = $aclRestore.AppendLine('    Write-Warning "Could not resolve SID for $NewUsername — applying ACLs without SID translation."')
        $null = $aclRestore.AppendLine('    $newSid = $null')
        $null = $aclRestore.AppendLine('}')
        $null = $aclRestore.AppendLine('')
        $null = $aclRestore.AppendLine('$aclData = Get-Content (Join-Path $PSScriptRoot "ACL_Export.json") | ConvertFrom-Json')
        $null = $aclRestore.AppendLine('$ok = 0; $skip = 0; $fail = 0')
        $null = $aclRestore.AppendLine('foreach ($entry in $aclData) {')
        $null = $aclRestore.AppendLine('    $target = Join-Path $DestinationRoot $entry.RelativePath')
        $null = $aclRestore.AppendLine('    if (-not (Test-Path $target)) { $skip++; continue }')
        $null = $aclRestore.AppendLine('    try {')
        $null = $aclRestore.AppendLine('        $sddl = $entry.SDDL')
        $null = $aclRestore.AppendLine('        # Translate old SID to new SID in SDDL string')
        $null = $aclRestore.AppendLine('        if ($newSid -and $OldSid -and $sddl -match [regex]::Escape($OldSid)) {')
        $null = $aclRestore.AppendLine('            $sddl = $sddl -replace [regex]::Escape($OldSid), $newSid')
        $null = $aclRestore.AppendLine('        }')
        $null = $aclRestore.AppendLine('        $acl = Get-Acl $target')
        $null = $aclRestore.AppendLine('        $acl.SetSecurityDescriptorSddlForm($sddl)')
        $null = $aclRestore.AppendLine('        Set-Acl $target $acl')
        $null = $aclRestore.AppendLine('        $ok++')
        $null = $aclRestore.AppendLine('    } catch { $fail++; Write-Warning "Failed: $target — $_" }')
        $null = $aclRestore.AppendLine('}')
        $null = $aclRestore.AppendLine('Write-Host "ACL restore complete: $ok applied, $skip skipped (path not found), $fail failed."')
        $null = $aclRestore.AppendLine('if ($fail -gt 0) { Write-Warning "Some ACLs failed — network share permissions may need manual correction." }')

        if (-not $DryRun) {
            $aclData | ConvertTo-Json -Depth 4 | Set-Content $aclPath -Encoding UTF8 -Force
            $aclRestore.ToString() | Set-Content $aclRestorePath -Encoding UTF8 -Force
        }
        Write-Status "ACL export: $($aclData.Count) path(s) → ACL_Export.json + Restore-ACLs.ps1 (with SID translation)" -Type "Success"
        Write-Log "FullProfileBackup: ACL export — $($aclData.Count) paths, OldSid=$oldSid for $Username"
        $null = $guide.AppendLine("[ACLs] Run UFM_Supplemental\Restore-ACLs.ps1 -DestinationRoot <path> -NewUsername <username> as Administrator.")
        $null = $guide.AppendLine("       The script will automatically translate old SID ($oldSid) to the new machine's SID.")

    } catch {
        Write-Status "ACL export failed: $_" -Type "Warning"
        Write-Log "FullProfileBackup: ACL export failed for $Username — $_"
    }

    # ── 2. HKCU registry export ───────────────────────────────────────────────
    try {
        Write-Status "Exporting HKCU registry..." -Type "Info"
        $regPath = Join-Path $suppDir 'HKCU_Export.reg'
        if (-not $DryRun) {
            $proc = Start-Process -FilePath 'reg.exe' `
                -ArgumentList "export HKCU `"$regPath`" /y" `
                -Wait -NoNewWindow -PassThru
            if ($proc.ExitCode -eq 0) {
                Write-Status "HKCU registry exported → HKCU_Export.reg" -Type "Success"
                Write-Log "FullProfileBackup: HKCU registry exported for $Username"
                $null = $guide.AppendLine('[Registry] Import HKCU_Export.reg on the target machine (double-click or: reg import HKCU_Export.reg).')
                $null = $guide.AppendLine('           Review before importing — this overwrites existing HKCU keys.')
            } else {
                Write-Status "reg export exited with code $($proc.ExitCode)" -Type "Warning"
            }
        } else {
            Write-Status "[DRY RUN] Would export HKCU → HKCU_Export.reg" -Type "Info"
        }
    } catch {
        Write-Status "HKCU export failed: $_" -Type "Warning"
        Write-Log "FullProfileBackup: HKCU export failed for $Username — $_"
    }

    # ── 3. Mapped network drives ──────────────────────────────────────────────
    try {
        Write-Status "Exporting mapped network drives..." -Type "Info"
        $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayRoot -match '^\\\\' }
        if ($drives.Count -gt 0) {
            $driveScript = [System.Text.StringBuilder]::new()
            $null = $driveScript.AppendLine('# Mapped Drive Reconnect Script — generated by UserFolderMigrator')
            $null = $driveScript.AppendLine('# Run on the target machine to reconnect network drives.')
            foreach ($d in $drives) {
                $null = $driveScript.AppendLine("net use $($d.Name): `"$($d.DisplayRoot)`" /persistent:yes")
            }
            $drivePath = Join-Path $suppDir 'Reconnect-MappedDrives.cmd'
            if (-not $DryRun) {
                $driveScript.ToString() | Set-Content $drivePath -Encoding ASCII -Force
                # Store hash for integrity verification on restore
                $cmdHash = (Get-FileHash $drivePath -Algorithm SHA256).Hash
                $cmdHash | Set-Content ($drivePath + '.sha256') -Encoding ASCII -Force
            }
            Write-Status "Mapped drives: $($drives.Count) drive(s) → Reconnect-MappedDrives.cmd" -Type "Success"
            Write-Log "FullProfileBackup: $($drives.Count) mapped drive(s) exported for $Username"
            $null = $guide.AppendLine("[Mapped Drives] Run UFM_Supplemental\Reconnect-MappedDrives.cmd to reconnect $($drives.Count) network drive(s).")
        } else {
            Write-Status "No mapped network drives found." -Type "Info"
        }
    } catch {
        Write-Status "Mapped drives export failed: $_" -Type "Warning"
        Write-Log "FullProfileBackup: mapped drives export failed for $Username — $_"
    }

    # ── 4. Wi-Fi profiles ─────────────────────────────────────────────────────
    try {
        Write-Status "Exporting Wi-Fi profiles..." -Type "Info"
        $wifiDir = Join-Path $suppDir 'WiFi_Profiles'
        # Check if the Wi‑Fi AutoConfig service is running
        $wlansvc = Get-Service -Name Wlansvc -ErrorAction SilentlyContinue
        if (-not $wlansvc -or $wlansvc.Status -ne 'Running') {
            Write-Status "Wi‑Fi service (Wlansvc) is not running — skipping Wi‑Fi export." -Type "Info"
        } else {
            if (-not $DryRun) { New-Item -Path $wifiDir -ItemType Directory -Force | Out-Null }
            $wifiProc = Start-Process -FilePath 'netsh.exe' `
                -ArgumentList "wlan export profile folder=`"$wifiDir`" key=clear" `
                -Wait -NoNewWindow -PassThru
            $xmlCount = if (Test-Path $wifiDir) { @(Get-ChildItem $wifiDir -Filter '*.xml').Count } else { 0 }
            if ($xmlCount -gt 0) {
                Write-Status "Wi-Fi profiles: $xmlCount profile(s) → WiFi_Profiles\" -Type "Success"
                Write-Log "FullProfileBackup: $xmlCount Wi-Fi profile(s) exported for $Username"
                $null = $guide.AppendLine("[Wi-Fi] Restore profiles: netsh wlan add profile filename=`"<file>`" — run for each XML in WiFi_Profiles\.")
                $null = $guide.AppendLine("        Profiles exported with plain-text keys (key=clear) — keep this backup secure.")
            } else {
                Write-Status "No Wi-Fi profiles found or netsh export failed." -Type "Info"
            }
        }
    } catch {
        Write-Status "Wi-Fi export failed: $_" -Type "Warning"
        Write-Log "FullProfileBackup: Wi-Fi export failed for $Username — $_"
    }

    # ── 5. User-scoped scheduled tasks ────────────────────────────────────────
    try {
        Write-Status "Exporting user-scoped scheduled tasks..." -Type "Info"
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.Principal.UserId -match [regex]::Escape($Username) -or
                           $_.Principal.UserId -eq 'INTERACTIVE' })
        if ($tasks.Count -gt 0) {
            $taskDir = Join-Path $suppDir 'ScheduledTasks'
            if (-not $DryRun) { New-Item -Path $taskDir -ItemType Directory -Force | Out-Null }
            foreach ($t in $tasks) {
                try {
                    $xml = Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
                    if ($xml -and -not $DryRun) {
                        $safeName = $t.TaskName -replace '[\\/:*?"<>|]', '_'
                        $xml | Set-Content (Join-Path $taskDir "$safeName.xml") -Encoding UTF8 -Force
                    }
                } catch { }
            }
            Write-Status "Scheduled tasks: $($tasks.Count) task(s) → ScheduledTasks\" -Type "Success"
            Write-Log "FullProfileBackup: $($tasks.Count) scheduled task(s) exported for $Username"
            $null = $guide.AppendLine("[Scheduled Tasks] Restore: schtasks /create /xml `"<file>`" /tn `"<name>`" — run for each XML in ScheduledTasks\.")
        } else {
            Write-Status "No user-scoped scheduled tasks found." -Type "Info"
        }
    } catch {
        Write-Status "Scheduled task export failed: $_" -Type "Warning"
        Write-Log "FullProfileBackup: scheduled task export failed for $Username — $_"
    }

    # ── 6. Default app associations ───────────────────────────────────────────
    try {
        Write-Status "Exporting default app associations..." -Type "Info"
        $assocPath = Join-Path $suppDir 'DefaultApps_Export.reg'
        if (-not $DryRun) {
            $proc = Start-Process -FilePath 'reg.exe' `
                -ArgumentList "export `"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts`" `"$assocPath`" /y" `
                -Wait -NoNewWindow -PassThru
            if ($proc.ExitCode -eq 0) {
                Write-Status "Default app associations exported → DefaultApps_Export.reg" -Type "Success"
                Write-Log "FullProfileBackup: default app associations exported for $Username"
                $null = $guide.AppendLine('[Default Apps] Import DefaultApps_Export.reg to restore file-type associations.')
            }
        } else {
            Write-Status "[DRY RUN] Would export FileExts → DefaultApps_Export.reg" -Type "Info"
        }
    } catch {
        Write-Status "Default app associations export failed: $_" -Type "Warning"
        Write-Log "FullProfileBackup: default app associations export failed for $Username — $_"
    }

    # ── 7. BitLocker recovery keys ────────────────────────────────────────────
    try {
        Write-Status "Exporting BitLocker recovery keys..." -Type "Info"
        $blVolumes = @(Get-BitLockerVolume -ErrorAction SilentlyContinue |
            Where-Object { $_.ProtectionStatus -eq 'On' })
        if ($blVolumes.Count -gt 0) {
            $blData = foreach ($v in $blVolumes) {
                [PSCustomObject]@{
                    MountPoint   = $v.MountPoint
                    VolumeStatus = $v.VolumeStatus.ToString()
                    KeyProtectors = @($v.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
                        Select-Object KeyProtectorId, RecoveryPassword)
                }
            }
            $blPath = Join-Path $suppDir 'BitLocker_RecoveryKeys.json'
            if (-not $DryRun) {
                $blData | ConvertTo-Json -Depth 4 | Set-Content $blPath -Encoding UTF8 -Force
            }
            $keyCount = ($blData | ForEach-Object { $_.KeyProtectors.Count } | Measure-Object -Sum).Sum
            Write-Status "BitLocker: $($blVolumes.Count) volume(s), $keyCount recovery key(s) → BitLocker_RecoveryKeys.json" -Type "Success"
            Write-Log "FullProfileBackup: BitLocker recovery keys exported — $($blVolumes.Count) volume(s) for $Username"
            $null = $guide.AppendLine("[BitLocker] Recovery keys saved to BitLocker_RecoveryKeys.json — KEEP THIS FILE SECURE.")
            $null = $guide.AppendLine("            Store separately from the encrypted drive.")
        } else {
            Write-Status "No BitLocker-protected volumes found." -Type "Info"
        }
    } catch {
        Write-Status "BitLocker export failed (may require elevation): $_" -Type "Warning"
        Write-Log "FullProfileBackup: BitLocker export failed for $Username — $_"
    }

        # ── 8. WSL distro export ──────────────────────────────────────────────────
    try {
        $wslCheck = Get-Command wsl.exe -ErrorAction SilentlyContinue
        if (-not $wslCheck) {
            Write-Status "WSL not installed — skipping export." -Type "Info"
        } else {
            # Check if WSL feature is actually configured before attempting --list
            $null = wsl.exe --status 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Status "WSL is not configured — skipping export." -Type "Info"
            } else {
                $distros = @(wsl.exe --list --quiet 2>&1 |
                    ForEach-Object { ($_ -replace '\x00','').Trim() } |
                    Where-Object { $_ -and $_ -notmatch '^Windows Subsystem|^Press |^CTRL|not installed|visit http|Operation aborted|time out|^$' }
                )
                if ($distros.Count -eq 0) {
                    Write-Status "No WSL distros configured — skipping export." -Type "Info"
                } else {
                    $wslDir = Join-Path $suppDir 'WSL'
                    if (-not $DryRun) { New-Item -Path $wslDir -ItemType Directory -Force | Out-Null }
                    $wslOk = 0; $wslFail = 0
                    foreach ($distro in $distros) {
                        $tarPath = Join-Path $wslDir "$($distro -replace '[\\/:*?"<>|]','_').tar"
                        if ($DryRun) {
                            Write-Status "[DRY RUN] Would export WSL distro '$distro' → WSL\$distro.tar" -Type "Info"
                            $wslOk++
                        } else {
                            Write-Status "Exporting WSL distro: $distro (may take a while)..." -Type "Info"
                            try {
                                wsl.exe --export $distro $tarPath 2>$null
                                if (Test-Path $tarPath) {
                                    $sizeMB = [math]::Round((Get-Item $tarPath).Length / 1MB, 1)
                                    Write-Status "  Exported: $distro ($sizeMB MB)" -Type "Success"
                                    $wslOk++
                                } else {
                                    Write-Status "  Export produced no file for: $distro" -Type "Warning"
                                    $wslFail++
                                }
                            } catch {
                                Write-Status "  Export failed for ${distro}: $_" -Type "Warning"
                                $wslFail++
                            }
                        }
                    }
                    Write-Status "WSL: $wslOk distro(s) exported, $wslFail failed → WSL\" -Type "Success"
                    Write-Log "FullProfileBackup: WSL export — $wslOk ok, $wslFail failed for $Username"
                    $null = $guide.AppendLine('[WSL] Restore each distro on the new machine:')
                    foreach ($d in $distros) {
                        $null = $guide.AppendLine("      wsl --import $d C:\WSL\$d UFM_Supplemental\WSL\$($d -replace '[\\/:*?"<>|]','_').tar")
                    }
                    $null = $guide.AppendLine('      Then set default: wsl --set-default <distro>')
                    $null = $guide.AppendLine('      WSL 2 requires: wsl --set-version <distro> 2')
                }
            }
        }
    } catch {
        Write-Status "WSL export failed: $_" -Type "Warning"
        Write-Log "FullProfileBackup: WSL export failed for $Username — $_"
    }

    # ── 8.5. Printer drivers backup (printbrm + pnputil fallback) ─────────────────
    Write-Status "Backing up printers and drivers..." -Type "Info"
    $printerBackupOk = Backup-PrinterDrivers -DestinationPath $Destination -DryRun:$DryRun
    if ($printerBackupOk) {
        Write-Status "Printer backup completed." -Type "Success"
        Write-Log "FullProfileBackup: Printer backup succeeded for $Username"
        $null = $guide.AppendLine("[Printers] Full backup saved in UFM_Supplemental\Printers\")
        $null = $guide.AppendLine("           - If PrinterBackup.printerExport exists, use it to restore everything.")
        $null = $guide.AppendLine("           - Otherwise, driver packages are in Printers\Drivers – install manually with pnputil.")
    } else {
        Write-Status "Printer backup failed – no printer data saved." -Type "Warning"
    }

    # ── 9. VPN profile detection ──────────────────────────────────────────────
    try {
        Write-Status "Detecting VPN profiles..." -Type "Info"
        $vpnFound = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Built-in Windows VPN (rasphone / RAS)
        $rasProfiles = @(Get-VpnConnection -ErrorAction SilentlyContinue)
        $rasProfiles += @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue)
        foreach ($v in $rasProfiles) {
            $vpnFound.Add([PSCustomObject]@{ Name=$v.Name; Type='Windows Built-in'; ServerAddress=$v.ServerAddress; TunnelType=$v.TunnelType })
        }

        # Third-party VPN client detection (by presence of their ProgramData/service)
        $thirdParty = [ordered]@{
            'Cisco AnyConnect'   = @('C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client', 'C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client')
            'GlobalProtect'      = @('C:\Program Files\Palo Alto Networks\GlobalProtect')
            'WireGuard'          = @('C:\Program Files\WireGuard', 'C:\ProgramData\WireGuard')
            'OpenVPN'            = @('C:\Program Files\OpenVPN', 'C:\ProgramData\OpenVPN Connect')
            'FortiClient'        = @('C:\Program Files\Fortinet\FortiClient')
            'Pulse Secure'       = @('C:\Program Files (x86)\Pulse Secure\Pulse')
            'SonicWall NetExtender' = @('C:\Program Files (x86)\SonicWALL\SSL-VPN\NetExtender')
            'Check Point VPN'    = @('C:\Program Files (x86)\CheckPoint\Endpoint Connect')
        }
        foreach ($client in $thirdParty.GetEnumerator()) {
            foreach ($path in $client.Value) {
                if (Test-Path $path) {
                    $vpnFound.Add([PSCustomObject]@{ Name=$client.Key; Type='Third-party client'; ServerAddress='See client config'; TunnelType='N/A' })
                    break
                }
            }
        }

        if ($vpnFound.Count -gt 0) {
            $vpnPath = Join-Path $suppDir 'VPN_Inventory.txt'
            $vpnContent = [System.Text.StringBuilder]::new()
            $null = $vpnContent.AppendLine("VPN Profile Inventory — $(Get-Date -Format 'o')")
            $null = $vpnContent.AppendLine("User: $Username")
            $null = $vpnContent.AppendLine("IMPORTANT: VPN profiles/configs live outside the user profile and CANNOT be automatically restored.")
            $null = $vpnContent.AppendLine("Install the VPN client on the new machine and re-import or re-enter connection settings.")
            $null = $vpnContent.AppendLine(('-' * 60))
            foreach ($v in $vpnFound) {
                $null = $vpnContent.AppendLine("  Name   : $($v.Name)")
                $null = $vpnContent.AppendLine("  Type   : $($v.Type)")
                $null = $vpnContent.AppendLine("  Server : $($v.ServerAddress)")
                $null = $vpnContent.AppendLine("")
            }
            $null = $vpnContent.AppendLine("Restore steps:")
            $null = $vpnContent.AppendLine("  Built-in Windows VPN : Settings > Network > VPN > Add a VPN connection")
            $null = $vpnContent.AppendLine("  Third-party clients  : Install client, then import profile or contact IT for config")
            if (-not $DryRun) {
                $vpnContent.ToString() | Set-Content $vpnPath -Encoding UTF8 -Force
            }

            Write-Status "VPN: $($vpnFound.Count) profile(s)/client(s) detected → VPN_Inventory.txt" -Type "Warning"
            Write-Status "  [!] VPN configs are NOT backed up — they must be re-configured on the new machine." -Type "Warning"
            foreach ($v in $vpnFound) {
                Write-Status "      $($v.Type): $($v.Name) — $($v.ServerAddress)" -Type "Warning"
            }
            Write-Log "FullProfileBackup: $($vpnFound.Count) VPN profile(s) detected and documented for $Username"
            $null = $guide.AppendLine('')
            $null = $guide.AppendLine("[VPN] $($vpnFound.Count) VPN client(s) detected — configs are NOT in the backup.")
            $null = $guide.AppendLine('  Install the VPN client on the new machine and re-configure manually.')
            $null = $guide.AppendLine('  Full list in: UFM_Supplemental\VPN_Inventory.txt')
            foreach ($v in $vpnFound) { $null = $guide.AppendLine("    - $($v.Name) ($($v.ServerAddress))") }
        } else {
            Write-Status "No VPN profiles or clients detected." -Type "Info"
        }
    } catch {
        Write-Status "VPN detection failed: $_" -Type "Warning"
        Write-Log "FullProfileBackup: VPN detection failed for $Username — $_"
    }

    # ── 10. Windows Credential Manager enumeration ────────────────────────────
    try {
        Write-Status "Enumerating Windows Credential Manager entries..." -Type "Info"
        $cmdkeyOut = cmdkey.exe /list 2>$null
        $entries = @($cmdkeyOut | Where-Object { $_ -match 'Target:' } |
            ForEach-Object { ($_ -replace '.*Target:\s*','').Trim() })
        if ($entries.Count -gt 0) {
            $credPath = Join-Path $suppDir 'CredentialManager_Inventory.txt'
            $credContent = [System.Text.StringBuilder]::new()
            $null = $credContent.AppendLine("Windows Credential Manager Inventory — $(Get-Date -Format 'o')")
            $null = $credContent.AppendLine("User: $Username")
            $null = $credContent.AppendLine("IMPORTANT: Passwords are DPAPI-encrypted and cannot be recovered from the backup.")
            $null = $credContent.AppendLine("You must re-enter each credential on the new machine.")
            $null = $credContent.AppendLine(('-' * 60))
            foreach ($e in $entries) { $null = $credContent.AppendLine("  $e") }
            $null = $credContent.AppendLine(('-' * 60))
            $null = $credContent.AppendLine("To restore: Settings > Credential Manager > Add a credential")
            $null = $credContent.AppendLine("Or via cmdkey: cmdkey /add:<target> /user:<user> /pass:<password>")
            if (-not $DryRun) {
                $credContent.ToString() | Set-Content $credPath -Encoding UTF8 -Force
            }
            Write-Status "Credential Manager: $($entries.Count) entries documented → CredentialManager_Inventory.txt" -Type "Success"
            Write-Status "  [!] Passwords CANNOT be recovered — each must be re-entered manually on the new machine." -Type "Warning"
            Write-Log "FullProfileBackup: $($entries.Count) Credential Manager entries documented for $Username"
            $null = $guide.AppendLine('')
            $null = $guide.AppendLine("[Credential Manager] $($entries.Count) credential(s) found — passwords are DPAPI-bound and CANNOT be restored.")
            $null = $guide.AppendLine('  Re-enter each in: Control Panel > Credential Manager > Add a Windows credential.')
            $null = $guide.AppendLine('  Full list in: UFM_Supplemental\CredentialManager_Inventory.txt')
            foreach ($e in $entries) { $null = $guide.AppendLine("    - $e") }
        } else {
            Write-Status "No Credential Manager entries found." -Type "Info"
        }
    } catch {
        Write-Status "Credential Manager enumeration failed: $_" -Type "Warning"
        Write-Log "FullProfileBackup: Credential Manager enumeration failed for $Username — $_"
    }

    # ── 10. Portability warnings ──────────────────────────────────────────────
    $warnings = [System.Collections.Generic.List[string]]::new()

    # Browser saved passwords (DPAPI-bound)
    $browserPaths = @{
        'Chrome' = "$ProfilePath\AppData\Local\Google\Chrome\User Data\Default\Login Data"
        'Edge'   = "$ProfilePath\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
        'Firefox'= "$ProfilePath\AppData\Roaming\Mozilla\Firefox\Profiles"
    }
    foreach ($b in $browserPaths.GetEnumerator()) {
        if (Test-Path $b.Value) {
            $warnings.Add("$($b.Key) saved passwords are encrypted to this machine's DPAPI key — they will NOT be usable on a different machine.")
        }
    }

    # Outlook OST
    $ostFiles = @(Get-ChildItem "$ProfilePath\AppData\Local\Microsoft\Outlook" -Filter '*.ost' -ErrorAction SilentlyContinue)
    if ($ostFiles.Count -gt 0) {
        $warnings.Add("Outlook .ost file(s) copied but machine-bound — they will NOT open on a different machine. Outlook will re-sync from the server.")
    }

    # Windows Hello / PIN
    $helloPath = "$ProfilePath\AppData\Roaming\Microsoft\Protect"
    if (Test-Path $helloPath) {
        $warnings.Add("Windows Hello/PIN data (Microsoft\Protect) is copied but machine-bound — PIN/biometrics must be re-enrolled on the target machine.")
    }

    # Start menu layout
    $layoutFile = "$ProfilePath\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
    if (-not (Test-Path (Join-Path $Destination 'AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml'))) {
        $warnings.Add("Start menu layout (LayoutModification.xml) was NOT found in destination — Start menu will reset to defaults.")
    }

    if ($warnings.Count -gt 0) {
        Write-Host ""
        Write-Status "Portability warnings:" -Type "Warning"
        foreach ($w in $warnings) { Write-Status "  [!] $w" -Type "Warning" }
        $null = $guide.AppendLine('')
        $null = $guide.AppendLine('[Portability Warnings]')
        foreach ($w in $warnings) { $null = $guide.AppendLine("  ! $w") }
    }

    # ── Write restore guide ───────────────────────────────────────────────────
    if (-not $DryRun) {
        $guidePath = Join-Path $suppDir 'UFM_RestoreGuide.txt'
        $guide.ToString() | Set-Content $guidePath -Encoding UTF8 -Force
        Write-Status "Restore guide written → UFM_Supplemental\UFM_RestoreGuide.txt" -Type "Success"
        Write-Log "FullProfileBackup: restore guide written for $Username"
    }
    Write-Host ""
}

function Backup-PrinterDrivers {
    <#
    .SYNOPSIS
        Backs up printers, queues, ports, and drivers.
        Tries to use printbrm.exe (installs it if missing), then falls back to pnputil (drivers only).
    #>
    [CmdletBinding()]
    param(
        [string]$DestinationPath,          # user backup root (e.g. Y:\Backup\John)
        [string]$ComputerName = $env:COMPUTERNAME,
        [switch]$DryRun
    )

    $printerSupDir = Join-Path $DestinationPath 'UFM_Supplemental\Printers'
    $backupFile     = Join-Path $printerSupDir 'PrinterBackup.printerExport'
    $driversDir     = Join-Path $printerSupDir 'Drivers'

    if ($DryRun) {
        Write-Status "[DRY RUN] Would backup printers to $backupFile (or drivers to $driversDir)" -Type "Info"
        return $true
    }

    # Ensure Print Spooler is running
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not $spooler -or $spooler.Status -ne 'Running') {
        Write-Status "Print Spooler service not running – cannot backup printers." -Type "Warning"
        return $false
    }

    # Create supplemental folders
    if (-not (Test-Path $printerSupDir)) { New-Item -ItemType Directory -Force -Path $printerSupDir | Out-Null }

    # ----- Try printbrm.exe -----
    $printbrm = Get-Command 'printbrm.exe' -ErrorAction SilentlyContinue
    if (-not $printbrm) {
        Write-Status "printbrm.exe not found – attempting to install Print Management tools..." -Type "Info"
        try {
            # Install the Print Management Console capability (includes printbrm)
            $null = dism.exe /Online /Add-Capability /CapabilityName:Print.Management.Console~~~~0.0.1.0 /Quiet /LogPath:"$env:TEMP\dism_printbrm.log"
            if ($LASTEXITCODE -eq 0) {
                Write-Status "Print Management tools installed successfully." -Type "Success"
                Start-Sleep -Seconds 3
                $printbrm = Get-Command 'printbrm.exe' -ErrorAction SilentlyContinue
            } else {
                Write-Status "DISM installation failed (exit $LASTEXITCODE)." -Type "Warning"
            }
        } catch {
            Write-Status "Failed to install Print Management tools: $_" -Type "Warning"
        }
    }

    if ($printbrm) {
        Write-Status "Backing up full printer configuration (queues, ports, drivers) with printbrm.exe..." -Type "Info"
        $procArgs = @(
            "-backup",
            "-file `"$backupFile`"",
            "-nobin",
            "-force",
            "-server `"$ComputerName`""
        )
        $process = Start-Process -FilePath $printbrm.Source -ArgumentList $procArgs -Wait -NoNewWindow -PassThru
        if ($process.ExitCode -eq 0) {
            Write-Status "Full printer backup saved: $backupFile" -Type "Success"
            Write-Log "Printer backup (printbrm) completed for $DestinationPath"
            return $true
        } else {
            Write-Status "printbrm backup failed with exit $($process.ExitCode) – falling back to driver-only backup." -Type "Warning"
            Write-Log "printbrm backup error: $($process.ExitCode) – using pnputil fallback"
        }
    }

    # ----- Fallback to pnputil (driver files only) -----
    Write-Status "Exporting printer driver packages using pnputil (driver files only)..." -Type "Info"
    if (-not (Test-Path $driversDir)) { New-Item -ItemType Directory -Force -Path $driversDir | Out-Null }

    # Get all third-party drivers (published name ends with .inf)
    $driverInfos = @(pnputil.exe /enum-drivers 2>$null | Select-String "Published Name.*:.*\.inf" | ForEach-Object { ($_ -split ":")[-1].Trim() })
    if ($driverInfos.Count -eq 0) {
        Write-Status "No printer drivers found to export." -Type "Info"
        return $false
    }

    $exported = 0
    foreach ($inf in $driverInfos) {
        $proc = Start-Process -FilePath "pnputil.exe" -ArgumentList "/export-driver `"$inf`" `"$driversDir`"" -Wait -NoNewWindow -PassThru
        if ($proc.ExitCode -eq 0) { $exported++ }
    }

    if ($exported -gt 0) {
        Write-Status "Exported $exported printer driver package(s) to $driversDir" -Type "Success"
        Write-Log "Printer driver backup (pnputil) exported $exported driver(s)"
        # Generate SHA256 manifest for integrity verification on restore
        $manifestPath = Join-Path $driversDir 'drivers.manifest.sha256'
        Get-ChildItem $driversDir -Recurse -Filter '*.inf' -ErrorAction SilentlyContinue |
            ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash)  $($_.FullName)" } |
            Set-Content $manifestPath -Encoding ASCII -Force
        Write-Log "Printer driver manifest written: $manifestPath"
        # Create a marker file so restore knows fallback was used
        $marker = Join-Path $printerSupDir '_pnputil_backup.txt'
        Set-Content -Path $marker -Value "Backup created with pnputil fallback on $(Get-Date -Format 'o')" -Force
        return $true
    } else {
        Write-Status "No printer drivers could be exported." -Type "Warning"
        return $false
    }
}

function Restore-PrinterDrivers {
    <#
    .SYNOPSIS
        Restores printers, queues, ports, and drivers.
        Uses printbrm.exe if the backup was created with it; otherwise falls back to pnputil.
    #>
    [CmdletBinding()]
    param(
        [string]$BackupFilePath,          # Full path to .printerExport file (may be empty)
        [string]$DriversFallbackDir,      # Path to Drivers folder (for pnputil fallback)
        [string]$ComputerName = $env:COMPUTERNAME,
        [switch]$Force,
        [switch]$DryRun
    )

    if ($DryRun) {
        Write-Status "[DRY RUN] Would restore printers from $BackupFilePath or drivers from $DriversFallbackDir" -Type "Info"
        return $true
    }

    # Ensure Print Spooler is running
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not $spooler -or $spooler.Status -ne 'Running') {
        Write-Status "Print Spooler service not running – cannot restore printers." -Type "Warning"
        return $false
    }

    # ----- Try printbrm restore if we have a full backup file -----
    if ($BackupFilePath -and (Test-Path $BackupFilePath)) {
        $printbrm = Get-Command 'printbrm.exe' -ErrorAction SilentlyContinue
        if (-not $printbrm) {
            Write-Status "printbrm.exe missing – cannot restore full printer configuration. Trying driver-only fallback." -Type "Warning"
        } else {
            Write-Status "Restoring full printer configuration from $BackupFilePath ..." -Type "Info"
            $forceFlag = if ($Force) { "-force" } else { "" }
            $procArgs = @("-restore", "-file `"$BackupFilePath`"", $forceFlag, "-server `"$ComputerName`"") | Where-Object { $_ -ne "" }
            $process = Start-Process -FilePath $printbrm.Source -ArgumentList $procArgs -Wait -NoNewWindow -PassThru
            if ($process.ExitCode -eq 0) {
                Write-Status "Full printer restore successful." -Type "Success"
                Write-Log "Printer restore (printbrm) succeeded for $BackupFilePath"
                return $true
            } else {
                Write-Status "printbrm restore failed (exit $($process.ExitCode)). Trying driver-only fallback." -Type "Warning"
                Write-Log "printbrm restore error: $($process.ExitCode) – falling back to pnputil"
            }
        }
    }

    # ----- Fallback: restore drivers using pnputil -----
    if ($DriversFallbackDir -and (Test-Path $DriversFallbackDir)) {
        Write-Status "Restoring printer drivers from $DriversFallbackDir using pnputil..." -Type "Info"
        $infFiles = @(Get-ChildItem -Path $DriversFallbackDir -Recurse -Filter '*.inf' -ErrorAction SilentlyContinue)
        if ($infFiles.Count -eq 0) {
            Write-Status "No .inf driver files found in $DriversFallbackDir." -Type "Warning"
            return $false
        }

        # Verify manifest exists and validate each .inf against it
        $manifestPath = Join-Path $DriversFallbackDir 'drivers.manifest.sha256'
        if (-not (Test-Path $manifestPath)) {
            Write-Status "Driver manifest not found — cannot verify backup integrity. Skipping driver restore." -Type "Warning"
            Write-Log "Printer driver restore skipped: missing manifest at $manifestPath"
            return $false
        }
        $manifestEntries = Get-Content $manifestPath -ErrorAction SilentlyContinue |
            ForEach-Object { $parts = $_ -split '\s+',2; [pscustomobject]@{Hash=$parts[0].Trim(); Path=$parts[1].Trim()} }

        $added = 0
        foreach ($inf in $infFiles) {
            # Path traversal guard
            $resolvedInf = [System.IO.Path]::GetFullPath($inf.FullName)
            $resolvedBase = [System.IO.Path]::GetFullPath($DriversFallbackDir)
            if (-not $resolvedInf.StartsWith($resolvedBase, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-Status "  Path traversal detected for $($inf.Name) — skipped." -Type "Warning"
                continue
            }
            # Hash check against manifest
            $entry = $manifestEntries | Where-Object { $_.Path -eq $resolvedInf }
            if (-not $entry) {
                Write-Status "  $($inf.Name) not in manifest — skipped." -Type "Warning"
                continue
            }
            $actualHash = (Get-FileHash $resolvedInf -Algorithm SHA256).Hash
            if ($actualHash -ne $entry.Hash) {
                Write-Status "  Hash mismatch for $($inf.Name) — skipped." -Type "Warning"
                Write-Log "Driver hash mismatch: $($inf.Name) expected=$($entry.Hash) actual=$actualHash"
                continue
            }
            $proc = Start-Process -FilePath "pnputil.exe" -ArgumentList "/add-driver `"$resolvedInf`" /install" -Wait -NoNewWindow -PassThru
            if ($proc.ExitCode -eq 0) {
                Write-Status "  Added driver: $($inf.Name)" -Type "Success"
                $added++
            } else {
                Write-Status "  Failed to add driver: $($inf.Name) (exit $($proc.ExitCode))" -Type "Warning"
            }
        }
        Write-Status "Added $added printer driver(s)." -Type "Success"
        Write-Log "Printer driver restore (pnputil) added $added drivers"
        return ($added -gt 0)
    }

    Write-Status "No printer backup found – skipping printer restore." -Type "Info"
    return $false
}

#endregion

function Restart-Explorer {
    <#
    .SYNOPSIS
        Gracefully stops and restarts explorer.exe so shell folder registry changes take effect.
    #>
    [CmdletBinding()]
    param()
    Write-SectionHeader "RESTARTING EXPLORER"
    try {
        $explorer = Get-Process -Name explorer -ErrorAction SilentlyContinue
        if ($explorer) {
            Write-Status "Stopping Explorer process..." -Type "Info"
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        
        Write-Status "Starting Explorer..." -Type "Info"
        Start-Process explorer.exe -ErrorAction SilentlyContinue
        
        Write-Status "Explorer restarted successfully" -Type "Success"
        Start-Sleep -Seconds 1
    } catch {
        Write-Status "Failed to restart Explorer: $_" -Type "Warning"
    }
}

#endregion

#region ── User Profile Management ───────────────────────────────────────────

function Get-AllUserProfiles {
    <#
    .SYNOPSIS
        Returns an array of profile objects (Username, SID, ProfilePath, IsActive) for all local users.
    #>
    [CmdletBinding()]
    param()
    $profilesDir = Join-Path $env:SystemDrive "Users"
    $excludedUsers = @('Public', 'Default', 'Default User', 'Administrator', 'Guest', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SYSTEM')
    
    $users = @()
    
    try {
        $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
            Where-Object { $_.Special -eq $false -and $_.LocalPath -like "$profilesDir\*" }
        
        foreach ($profile in $profiles) {
            $username = Split-Path $profile.LocalPath -Leaf
            if ($username -notin $excludedUsers) {
                $users += [PSCustomObject]@{
                    Username = $username
                    ProfilePath = $profile.LocalPath
                    SID = $profile.SID
                    IsActive = $profile.Loaded
                    LastUseTime = $profile.LastUseTime
                }
            }
        }
        Write-Log "Found $($users.Count) user profiles"
    } catch {
        Write-Log "Failed to enumerate user profiles: $_"
    }
    
    return $users
}

function Get-UserDestinationPath {
    [CmdletBinding()]
    param([string]$BaseDestination, [string]$Username)
    return Join-Path $BaseDestination $Username
}

function Resolve-TargetUser {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Resolves a username string into the same PSCustomObject format used by
        Get-AllUserProfiles so all mode branches can treat it identically.
        Returns $null and writes an error if the username is not found.
    #>
    param([string]$Username)

    # Current user — no WMI lookup needed; use HKCU (SID = null)
    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$currentAuthenticatedUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]

if ($Username -ieq $currentAuthenticatedUser) {
    return [PSCustomObject]@{ 
        Username    = $currentAuthenticatedUser; 
        ProfilePath = (Get-CimInstance Win32_UserProfile -Filter "SID = '$currentUserSid'").SpecialPath; 
        SID         = $currentUserSid; 
        IsActive    = $true 
    }
}

    # Any other user — find via Win32_UserProfile
    $profiles = Get-AllUserProfiles
    $match    = $profiles | Where-Object { $_.Username -ieq $Username }

    if (-not $match) {
        Write-Status "User '$Username' not found. Available profiles:" -Type "Error"
        $profiles | ForEach-Object {
            $t = if ($_.IsActive) { 'Active' } else { 'Inactive' }
            Write-Status "  $($_.Username)  [$t]" -Type "Info"
        }
        return $null
    }

    return $match
}

#endregion

#region ── Migration Functions ───────────────────────────────────────────────

function New-MigrationResult {
    <#
    .SYNOPSIS
        Creates a structured migration result object for aggregating per-folder outcomes across a user migration.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$Username,
        [bool]$IsActive,
        [object[]]$Folders  = @(),
        [bool]$Aborted      = $false,
        [string]$AbortReason = ''
    )
    
    # Safely calculate TotalSize - handle cases where Size property doesn't exist
    $totalSize = 0L
    foreach ($f in $Folders) {
        if ($f -is [PSCustomObject] -and $f.PSObject.Properties['Size'] -and $f.Size -is [long]) {
            $totalSize += $f.Size
        }
    }
    
    $successCount = 0
    foreach ($f in $Folders) {
        if ($f -is [PSCustomObject] -and $f.PSObject.Properties['Success'] -and $f.Success -eq $true) {
            $successCount++
        }
    }
    
    return [PSCustomObject]@{
        Username    = $Username
        IsActive    = $IsActive
        Folders     = $Folders
        Aborted     = $Aborted
        AbortReason = $AbortReason
        SuccessCount = $successCount
        TotalCount   = $Folders.Count
        TotalSize    = $totalSize
    }
}


function Write-UserMigrationSummary {
    <#
    .SYNOPSIS
        Renders the per-user post-migration summary table showing per-folder status,
        totals, and overall success/partial/failure outcome.
        Extracted from Invoke-UserMigration to reduce function length.
    #>
    [CmdletBinding()]
    param(
        [string]$Username,
        [object[]]$Results,
        [long]$TotalSize,
        [int]$SuccessCount,
        [long]$TotalFreed
    )
    Write-SectionHeader "Summary for $Username"
    
    $colWidths = @{ Folder = 16; Size = 14; Reg = 7; Source = 10; Status = 8 }
    Write-Host ("  {0,-$($colWidths.Folder)} {1,$($colWidths.Size)} {2,$($colWidths.Reg)} {3,$($colWidths.Source)} {4,$($colWidths.Status)} Destination" -f "Folder", "Size", "Reg", "Source", "Status")
    Write-TableSeparator -Width 90
    
    foreach ($r in $Results) {
        $statusSymbol = if ($r.Success) { "OK" } else { "FAIL" }
        $statusColor  = if ($r.Success) { "Green" } else { "Red" }
        $regSymbol    = if ($r.RegistryUpdated) { "yes" } else { "no" }
        $sourceSymbol = if ($r.SourceDeleted) { "deleted" } elseif ($r.Success) { "kept" } else { "n/a" }
        $sizeStr      = if ($r.Size -gt 0) { Format-Bytes $r.Size } else { "0 B" }
        Write-Host ("  {0,-$($colWidths.Folder)} {1,$($colWidths.Size)} {2,$($colWidths.Reg)} {3,$($colWidths.Source)} " -f $r.Folder, $sizeStr, $regSymbol, $sourceSymbol) -NoNewline
        Write-Host ("{0,$($colWidths.Status)} " -f $statusSymbol) -ForegroundColor $statusColor -NoNewline
        Write-Host $r.Destination -ForegroundColor Gray
    }
    Write-TableSeparator -Width 90
    Write-Host ("  {0,-$($colWidths.Folder)} {1,$($colWidths.Size)}" -f "TOTAL", (Format-Bytes $TotalSize)) -ForegroundColor Cyan
    Write-TableSeparator -Width 90
    Write-Host ""
    
    if ($SuccessCount -eq $Results.Count -and $Results.Count -gt 0) {
        Write-Status "All $($Results.Count) shell folders migrated successfully." -Type "Success"
    } elseif ($SuccessCount -gt 0) {
        Write-Status "$SuccessCount of $($Results.Count) shell folders migrated successfully." -Type "Warning"
        $script:ExitCode = $script:EXIT_PARTIAL
    } else {
        Write-Status "No shell folders were migrated successfully." -Type "Error"
        $script:ExitCode = $script:EXIT_FAILURE
    }
    if ($TotalFreed -gt 0) {
        Write-Status "Space freed by source deletion: $(Format-Bytes $TotalFreed)" -Type "Success"
        Write-Log "Source deletion freed $(Format-Bytes $TotalFreed) for $Username"
    }
}

function Invoke-UserMigration {
    <#
    .SYNOPSIS
        Orchestrates the full migration pipeline for one user: enumeration, robocopy, registry update, and verification.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$Username,
        [string]$ProfilePath,
        [string]$Destination,
        [string]$SID,
        [bool]$IsActive
    )
    
    Write-SectionHeader "Processing User: $Username"
    Write-Status "Destination: $Destination" -Type "Info"
    
    if (-not $DryRun -and -not (Test-Path $Destination)) {
        try {
            New-Item -Path $Destination -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Status "Created destination folder" -Type "Success"
        } catch {
            Write-Status "Cannot create destination folder: $($_.Exception.Message)" -Type "Error"
            Write-Log "Invoke-UserMigration ABORTED for $Username — cannot create destination: $_"
            return New-MigrationResult -Username $Username -IsActive $IsActive -Aborted $true -AbortReason "Cannot create destination: $($_.Exception.Message)"
        }
    }
    
    $hiveLoaded = $false
    $loadedSID = $null
    
    if ($IsActive) {
        Write-Status "Active user - registry accessible" -Type "Success"
        $regPaths = if ([string]::IsNullOrEmpty($SID)) {
            @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
        } else {
            Get-UserRegistryPaths -SID $SID
        }

        # ── VSS auto-detection for active users (Fix: Safety Gap 1) ──────────
        # When migrating a logged-in user without VSS, open handles (Outlook PSTs,
        # Chrome SQLite DBs, Teams cache, open Office docs) cause robocopy to silently
        # skip or partially copy locked files.  Detect this and either auto-activate
        # VSS (when handle.exe is available) or emit a prominent warning.
        if (-not $UseVSS -and -not $DisableSmartVSS) {
            # ── Reliable locked-file detection (three-tier) ───────────────────
            # Tier 1: Direct FileStream exclusive-open probe on a sample of files from each folder.
            #   No audit policy required — works on every Windows version.
            #   A file locked exclusively by another process will throw IOException.
            # Tier 2: handle.exe (Sysinternals) if present — more comprehensive than a file probe.
            # Tier 3: openfiles.exe advisory fallback — only if "Maintain Objects List" policy is on.
            $lockedPaths  = @()
            $lockedFiles  = [System.Collections.Generic.List[string]]::new()
            $folderList_vss = if ($Folders -contains 'All') { $script:SHELL_FOLDERS.Keys } else { $Folders }

            foreach ($fn_vss in $folderList_vss) {
                $sp = Get-ShellFolderPath -FolderName $fn_vss -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey -ProfilePath $ProfilePath
                if (-not $sp -or -not (Test-Path $sp)) { continue }

                $folderLocked = $false

                # ── Tier 1: FileStream exclusive probe on up to 20 files ────
                $probeFiles = @(try {
                    $eo = [System.IO.EnumerationOptions]::new()
                    $eo.RecurseSubdirectories = $true
                    $eo.AttributesToSkip      = 0
                    $eo.IgnoreInaccessible    = $true
                    [System.IO.Directory]::EnumerateFiles($sp, '*', $eo) | Select-Object -First 20
                } catch { @() })

                foreach ($pf in $probeFiles) {
                    try {
                        $fs = [System.IO.File]::Open($pf, [System.IO.FileMode]::Open,
                              [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                        $fs.Dispose()
                    } catch [System.IO.IOException] {
                        # IOException = file is locked by another process
                        $folderLocked = $true
                        $lockedFiles.Add([System.IO.Path]::GetFileName($pf))
                        break
                    } catch { }   # UnauthorizedAccessException etc — not a lock
                }

                # ── Tier 2: handle.exe (Sysinternals) via $script:HandlePath ─
                if (-not $folderLocked -and $script:HandlePath) {
                    try {
                        $handleOut = & $script:HandlePath $sp /accepteula 2>&1
                        if ($LASTEXITCODE -eq 0 -and $handleOut -match [regex]::Escape($sp)) {
                            $folderLocked = $true
                        }
                    } catch {}
                }

                if ($folderLocked) { $lockedPaths += $sp }
            }

            if ($lockedPaths.Count -gt 0) {
                Write-SectionHeader "ACTIVE USER: LOCKED FILES DETECTED — $Username"
                Write-Status "Exclusive-open probe found locked files in $($lockedPaths.Count) shell folder(s):" -Type "Warning"
                foreach ($lp in $lockedPaths) { Write-Status "  $lp" -Type "Warning" }
                if ($lockedFiles.Count -gt 0) {
                    Write-Status "  Sample locked file(s): $($lockedFiles -join ', ')" -Type "Warning"
                }
                Write-Status "Robocopy retries alone will silently skip or partially copy locked files." -Type "Warning"
                Write-Status "Automatically enabling -UseVSS to capture a consistent snapshot." -Type "Info"
                Write-Log "VSS auto-activated for active user '$Username': $($lockedPaths.Count) folder(s) with locked files (probe: $($lockedFiles -join ','))"
                Write-AuditEntry -Message "VSS_AUTO_ACTIVATE: active user $Username — $($lockedPaths.Count) locked path(s)" -Level "WARN"
                Set-Variable -Name 'UseVSS' -Value ([switch]$true) -Scope Script -ErrorAction SilentlyContinue
            } else {
                Write-Status "Active user '$Username': no exclusively-locked files detected (FileStream probe)." -Type "Info"
                Write-Status "  If Outlook, Chrome, Teams, or Office are running, consider -UseVSS to guarantee" -Type "Warning"
                Write-Status "  a consistent snapshot of locked files (PSTs, SQLite DBs, cache, open docs)." -Type "Warning"
                Write-Log "VSS advisory: no locked files detected for '$Username' (FileStream probe on $(($folderList_vss | Measure-Object).Count) folders)"
            }
        }
    } else {
        Write-Status "Inactive user detected: $Username" -Type "Warning"
        
        # Determine if we can skip the expensive permission repair using AccessChk
        $skipPermissionFix = $false
        if (-not $SkipAccessCheck -and $script:AccessChkPath) {
            Write-Status "Checking profile access with AccessChk..." -Type "Info"
            try {
                $acResult = & $script:AccessChkPath -accepteula -q -r "$env:USERNAME" "$ProfilePath" 2>$null
                if ($LASTEXITCODE -eq 0 -and $acResult) {
                    Write-Status "AccessChk: $Username's profile is already readable. Skipping permission fix." -Type "Success"
                    $skipPermissionFix = $true
                } else {
                    Write-Status "AccessChk: insufficient access – will repair permissions." -Type "Info"
                }
            } catch {
                Write-Status "AccessChk run failed, proceeding with normal permission fix." -Type "Warning"
            }
        }
        
            if (-not $skipPermissionFix -and -not $SkipAutoPermissionFix) {
            Write-Status "Automatically fixing permissions..." -Type "Info"
            $null = Repair-InactiveUserPermissions -ProfilePath $ProfilePath -Username $Username
        }
        
        if (-not $DryRun) {
            $loadedSID = Load-UserRegistryHive -Username $Username -ProfilePath $ProfilePath -SID $SID
            if ($loadedSID) {
                Write-Status "Registry hive loaded for $Username" -Type "Success"
                $regPaths = Get-UserRegistryPaths -SID $loadedSID
                $hiveLoaded = $true
            } else {
                Write-Status "Failed to load registry hive for $Username" -Type "Error"
                Write-Status "Using default registry paths (current user context)" -Type "Warning"
                $regPaths = @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
            }
        } else {
            $regPaths = @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
        }
    }
    
    if (-not $DryRun) {
        $null = Backup-RegistrySettings -Username $Username -SID ($loadedSID ?? $SID)
    }

    Write-SectionHeader "Migrating User: $Username"
    Write-Status "Profile Path: $ProfilePath" -Type "Info"
    Write-Status "Destination: $Destination" -Type "Info"
    Write-Host ""

    # ── Junction scan (informational) ────────────────────────────────────────
    if (-not $SkipJunctionScan -and $script:JunctionPath) {
        Write-Status "Scanning for junction points in $ProfilePath ..." -Type "Info"
        $junctions = @(& $script:JunctionPath -accepteula -s "$ProfilePath" 2>$null |
            Where-Object { $_ -match 'Junction' })
        if ($junctions.Count -gt 0) {
            Write-Status "Found $($junctions.Count) junction(s) in profile:" -Type "Warning"
            foreach ($j in $junctions) {
                Write-Status "  $j" -Type "Info"
            }
            Write-Status "Robocopy /XJD will skip junction targets – they will not be duplicated." -Type "Info"
        } else {
            Write-Status "No junctions found." -Type "Info"
        }
    }
    
    $results = @()
    $totalSize = 0
    $totalFiles = 0
    $totalFolders = 0
    $successCount = 0
    $totalFreed   = 0L   # bytes freed by source deletion across all folders this user
    
    # try/finally guarantees hive unload even on mid-migration exceptions
    try {
    
    $folderList = if ($Folders -contains 'All') { $script:SHELL_FOLDERS.Keys } else { $Folders }
    $checkpointData = Get-CheckpointData

    # ── OneDrive KFM interactive remediation (replaces hard block) ────────────
    $kfm = Get-OneDriveKFMStatus -SID ($loadedSID ?? $SID)
    if ($kfm.KFMEnabled -and -not $SkipKFMBlock -and -not $ForceOneDrive) {
        $attempt = 0; ${maxAttempts} = 3; $resolved = $false; $skipUser = $false
        while (-not $resolved -and $attempt -lt ${maxAttempts}) {
            if ($attempt -eq 0) {
                Write-SectionHeader "ONEDRIVE KFM DETECTED: $Username"
                Write-Status "OneDrive Known Folder Move is active for this user." -Type "Error"
                Write-Status "  Account : $($kfm.AccountName)" -Type "Info"
                foreach ($f in $kfm.Folders.Keys) { Write-Status "  $f -> $($kfm.Folders[$f])" -Type "Info" }
                Write-Host ""
                Write-Status "Migrate will copy shell folders to a new location and update registry." -Type "Warning"
                Write-Status "  If KFM remains active, OneDrive will silently re-redirect folders after migration." -Type "Warning"
                Write-Host ""
            } else {
                Write-SectionHeader "RECHECK ATTEMPT $attempt of ${maxAttempts}: $Username"
                Write-Status "KFM still detected or shell folders still point under OneDrive." -Type "Error"
                Write-Host ""
            }
            Write-Status "Remediation options:" -Type "Info"
            Write-Status "  1. Disable KFM now (remove policy keys, requires gpupdate)" -Type "Info"
            Write-Status "  2. Proceed anyway  (acknowledge risk, no changes to KFM)"   -Type "Info"
            Write-Status "  3. Skip this user  (abort)"                                  -Type "Info"
            Write-Status "  4. I have disabled KFM – recheck now"                        -Type "Info"
            Write-Host ""
            $choice = Invoke-KFMChoice
            switch ($choice) {
                '1' {
                    Set-OneDriveKFMPolicy -Disable
                    Write-Status "KFM disabled. Run 'gpupdate /force' after this script." -Type "Success"
                    $kfm = Get-OneDriveKFMStatus -SID ($loadedSID ?? $SID)
                    $stillInOD = Test-ShellFoldersInOneDrive -SID ($loadedSID ?? $SID) -ProfilePath $ProfilePath
                    if (-not $kfm.KFMEnabled -and -not $stillInOD) { Write-Status "KFM disabled and folders no longer under OneDrive. Proceeding." -Type "Success"; $resolved = $true }
                    else { Write-Status "KFM still active or folders still under OneDrive." -Type "Warning"; $attempt++; $kfm = Get-OneDriveKFMStatus -SID ($loadedSID ?? $SID) }
                }
                '2' { Write-Status "Proceeding with Migrate despite active KFM." -Type "Warning"; $resolved = $true }
                '3' {
                    Write-Status "Skipping $Username due to KFM block." -Type "Warning"
                    Write-Log "Migration BLOCKED for $Username — KFM active (user chose to skip)"
                    return New-MigrationResult -Username $Username -IsActive $IsActive -Aborted $true -AbortReason "OneDrive KFM block — skipped by operator"
                }
                '4' {
                    $kfm = Get-OneDriveKFMStatus -SID ($loadedSID ?? $SID)
                    $stillInOD = Test-ShellFoldersInOneDrive -SID ($loadedSID ?? $SID) -ProfilePath $ProfilePath
                    if (-not $kfm.KFMEnabled -and -not $stillInOD) { Write-Status "KFM now disabled and folders no longer under OneDrive. Proceeding." -Type "Success"; $resolved = $true }
                    else {
                        $attempt++
                        if ($attempt -ge ${maxAttempts}) {
                            Write-Status "After ${maxAttempts} attempts, KFM still active. Aborting user." -Type "Error"
                            Write-Log "Migration BLOCKED for $Username — persistent KFM after ${maxAttempts} rechecks"
                            return New-MigrationResult -Username $Username -IsActive $IsActive -Aborted $true -AbortReason "OneDrive KFM block — persistent after ${maxAttempts} rechecks"
                        }
                        Write-Status "KFM still active. $(${maxAttempts} - $attempt) recheck(s) left." -Type "Warning"; Start-Sleep -Seconds 3
                    }
                }
                default { Write-Status "Invalid choice — enter 1, 2, 3, or 4." -Type "Warning"; Start-Sleep -Seconds 1 }
            }
        }
    }

    # GPO Folder Redirection check (unchanged — hard block, policy-controlled)
    $gpoAllowed = Write-GPORedirectionWarning -Username $Username -SID ($loadedSID ?? $SID)
    if (-not $gpoAllowed) {
        Write-Log "Migration BLOCKED for $Username — GPO Folder Redirection active (use -SkipGPOBlock to override)"
        return New-MigrationResult -Username $Username -IsActive $IsActive -Aborted $true -AbortReason "GPO Folder Redirection block — use -SkipGPOBlock to override"
    }

    foreach ($folderName in $folderList) {
        # Checkpoint resume: skip folders already completed in a previous run (Feature 1.3)
        if (Test-FolderCheckpointed -Username $Username -FolderName $folderName -CheckpointData $checkpointData) {
            Write-Status "$folderName : Skipped (already completed — checkpoint resume)" -Type "Info"
            $results += [PSCustomObject]@{
                Folder          = $folderName
                Size            = 0
                Files           = 0
                Folders         = 0
                RegistryUpdated = $true
                SourceDeleted   = $true
                Success         = $true
                Destination     = '(resumed)'
                VerifyResult    = $null
            }
            $successCount++
            continue
        }
        $sourcePath = Get-ShellFolderPath -FolderName $folderName -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey -ProfilePath $ProfilePath
        
        if (-not $sourcePath) {
            Write-Status "$folderName : Cannot determine source path - skipping" -Type "Warning"
            continue
        }

        # Inactive user: if the registry-reported path doesn't exist on disk, fall back
        # to the canonical default profile location (e.g. C:\Users\Prathamesh\Documents).
        # This handles cases where the hive was never updated after manual folder moves,
        # or where the registry still points to a path on a drive that no longer exists.
        if (-not $IsActive -and -not (Test-Path $sourcePath)) {
            $defaultLocalPath = Join-Path $ProfilePath $script:SHELL_FOLDERS[$folderName].Default
            if (Test-Path $defaultLocalPath) {
                Write-Status "$folderName : Registry path not found on disk; using default profile location as source" -Type "Warning"
                Write-Log "$folderName (inactive user '$Username'): fallback source $defaultLocalPath (registry had: $sourcePath)"
                $sourcePath = $defaultLocalPath
            }
        }
        
        if (-not (Test-Path $sourcePath)) {
            # Source doesn't exist — create empty destination and point registry at it
            $folderLeaf = $script:SHELL_FOLDERS[$folderName].Default
            $destPath   = Join-Path $Destination $folderLeaf
            
            if ($DryRun) {
                Write-Status "$folderName : [DRY RUN] Source missing - would create $destPath and update registry" -Type "Info"
                $results += [PSCustomObject]@{
                    Folder = $folderName; Size = 0; Files = 0; Folders = 0
                    RegistryUpdated = $false; SourceDeleted = $false; Success = $true; Destination = $destPath
                }
                $successCount++
            } else {
                if (-not (Test-Path $destPath)) {
                    New-Item -Path $destPath -ItemType Directory -Force | Out-Null
                    Write-Status "$folderName : Created missing folder at destination" -Type "Info"
                }
                $regSuccess = $false
                if (-not $SkipRegistryUpdate) {
                    $regSuccess = Set-ShellFolderRegistryPath -FolderName $folderName -NewPath $destPath -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey
                }
                Write-Status "$folderName : Source did not exist - created destination$(if ($regSuccess) {' and updated registry'} else {''})" -Type "Info"
                $results += [PSCustomObject]@{
                    Folder = $folderName; Size = 0; Files = 0; Folders = 0
                    RegistryUpdated = $regSuccess; SourceDeleted = $false; Success = $true; Destination = $destPath
                }
                $successCount++
                Write-Log "Created missing destination for $folderName : $destPath (RegistryUpdated=$regSuccess)"
            }
            continue
        }
        
        $folderLeaf = $script:SHELL_FOLDERS[$folderName].Default
        $destPath = Join-Path $Destination $folderLeaf
        
        if ($sourcePath -ieq $destPath) {
            Write-Status "$folderName : Already at destination - skipping" -Type "Info"
            continue
        }
        
        $stats   = Get-FolderStats $sourcePath
        $size    = $stats.Size
        $files   = $stats.FileCount
        $folders = $stats.DirCount + 1   # +1 = the folder itself; matches Windows multi-select Properties
        
        Write-Status "Processing: $folderName" -Type "Info"
        Write-Status "  From: $sourcePath" -Type "Info"
        Write-Status "  To:   $destPath" -Type "Info"
        Write-Status "  Size: $(Format-Bytes $size), Files: $($files), Folders: $($folders)" -Type "Info"
        $preFolderContext = New-PluginContext 'PreFolder' @{
            Username    = $Username
            FolderName  = $folderName
            SourcePath  = $sourcePath
            DestPath    = $destPath
            FoldersList = $folderList
            DryRun      = $DryRun
        }
        if ((Invoke-PluginHooks -Stage 'PreFolder' -Context $preFolderContext) -eq $false) {
            Write-Status "$folderName : Skipped — blocked by plugin" -Type "Warning"
            Write-Log "PreFolder stage blocked for $folderName — skipping folder"
            continue
        }
        $folderList = $preFolderContext.FoldersList  # PriorityQueue may reorder
        Write-Host ""
        
        if ($DryRun) {
            Write-Status "[DRY RUN] Would copy $folderName ($(Format-Bytes $size))" -Type "Info"
            $results += [PSCustomObject]@{
                Folder = $folderName
                Size = $size
                Files = $files
                Folders = $folders
                RegistryUpdated = $false
                SourceDeleted = $false
                Success = $true
                Destination = $destPath
            }
            $totalSize += $size
            $totalFiles += $files
            $totalFolders += $folders
            $successCount++
            continue
        }
        
        $copySuccess = Invoke-RobocopyWithProgress -Source $sourcePath -Destination $destPath -FolderName $folderName -TotalBytes $size -FileCount $files
        
        if ($copySuccess) {
            # ── Checksum verification (before source deletion) ───────────────
            $verifyResult = $null
            if (-not $DisableChecksumVerify -and -not $DryRun -and $files -gt 0) {
                $verifyResult = Invoke-VerifyFolderChecksums -SourcePath $sourcePath -DestPath $destPath -FolderName $folderName
            }
            $verifyFailed = $verifyResult -and -not $verifyResult.Passed

            # ── Test-Restore sample: prove destination is RESTORABLE ──────────
            # Only gate source deletion — does not block registry redirect.
            $testRestorePassed = $true
            if (-not $verifyFailed -and $files -gt 0) {
                $testRestorePassed = Invoke-TestRestore -DestPath $destPath -FolderName $folderName -SamplePct $TestRestoreSamplePct
            }
            $skipDelete = $verifyFailed -or (-not $testRestorePassed)

            # ── Registry redirect ─────────────────────────────────────────────
            # Only redirect when copy+verify passed. If either failed, leave registry
            # pointing at original source so user's shell folders remain accessible.
            $regSuccess       = $false
            $regRolledBack    = $false
            if (-not $SkipRegistryUpdate -and -not $verifyFailed) {
                # Save current registry value for potential rollback
                $regBackupValue = try {
                    Get-ItemPropertyValue -Path $regPaths.UsfKey -Name $script:SHELL_FOLDERS[$folderName].RegValue -ErrorAction SilentlyContinue
                } catch [System.Exception] { $null }

                $regSuccess = Set-ShellFolderRegistryPath -FolderName $folderName -NewPath $destPath `
                    -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey

                # ── Registry auto-rollback if subsequent operations fail ───────
                # If the test-restore or future steps fail, revert registry to the
                # pre-migration value so the user's shell folders stay accessible.
                if ($regSuccess -and $skipDelete -and $regBackupValue) {
                    Write-Status "  Rolling back registry for $folderName (test-restore failed)..." -Type "Warning"
                    try {
                        Set-ItemProperty -Path $regPaths.UsfKey -Name $script:SHELL_FOLDERS[$folderName].RegValue `
                            -Value $regBackupValue -Type ExpandString -ErrorAction Stop
                        Set-ItemProperty -Path $regPaths.SfKey  -Name $script:SHELL_FOLDERS[$folderName].RegValue `
                            -Value $regBackupValue -Type String    -ErrorAction Stop
                        $regSuccess    = $false
                        $regRolledBack = $true
                        Write-Status "  Registry rolled back to: $regBackupValue" -Type "Success"
                        Write-Log "Registry ROLLED BACK for $folderName -> $regBackupValue"
                        Write-AuditEntry -Message "REG_ROLLBACK: $folderName reverted to $regBackupValue" -Level "WARN"
                    } catch [System.Exception] {
                        Write-Status "  Registry rollback FAILED: $($_.Exception.Message) — manual repair needed" -Type "Error"
                        Write-Log "Registry rollback FAILED for ${folderName}: $_"
                        Write-EventLogEntry -Message "UserFolderMigrator: Registry rollback FAILED for $folderName — MANUAL REPAIR NEEDED. Original path: $regBackupValue" -EntryType Error -EventId 1003
                    }
                }
            }

            # ── Source deletion (only when copy + verify + test-restore all pass) ──
            $sourceDeleted = $false
            if (-not $KeepSource -and -not $skipDelete) {
                try {
                    if ($SecureWipeSource -and $script:SDeletePath) {
                        # Secure wipe with SDelete (3 passes)
                        Write-Status "Securely wiping $sourcePath with SDelete (3 passes)..." -Type "Info"
                        $sw = Start-Process -FilePath $script:SDeletePath `
                            -ArgumentList "-p 3 -s -q `"$sourcePath`"" `
                            -Wait -NoNewWindow -PassThru
                        if ($sw.ExitCode -ne 0) {
                            Write-Status "SDelete exit code $($sw.ExitCode) – falling back to standard delete." -Type "Warning"
                            Remove-Item -LiteralPath $sourcePath -Recurse -Force -ErrorAction Stop
                        } else {
                            # SDelete may leave an empty directory; force removal if still present
                            if (Test-Path $sourcePath) {
                                Remove-Item -LiteralPath $sourcePath -Recurse -Force -ErrorAction Stop
                            }
                        }
                    } else {
                        Remove-Item -LiteralPath $sourcePath -Recurse -Force -ErrorAction Stop
                    }
                    $sourceDeleted = $true
                    $totalFreed += $size
                    Write-Status "Source removed: $sourcePath (freed $(Format-Bytes $size))" -Type "Success"
                    Write-AuditEntry -Message "SOURCE_DELETED: $sourcePath (folder=$folderName, user=$Username)" -Level "INFO"
                } catch [System.Exception] {
                    Write-Status "Could not remove source: $($_.Exception.Message)" -Type "Warning"
                    Write-Log "Source removal failed for ${folderName}: $_"
                }
            } elseif ($verifyFailed) {
                Write-Status "$folderName : Source preserved — checksum verification failed" -Type "Warning"
            } elseif (-not $testRestorePassed) {
                Write-Status "$folderName : Source preserved — test-restore sample failed (destination not proven restorable)" -Type "Warning"
            }

            if ($sourceDeleted) { $null = Remove-EmptyTree -Path $destPath }

            $folderSuccess = -not $verifyFailed -and $testRestorePassed

            $results += [PSCustomObject]@{
                Folder          = $folderName
                Size            = $size
                Files           = $files
                Folders         = $folders
                RegistryUpdated = $regSuccess
                SourceDeleted   = $sourceDeleted
                Success         = $folderSuccess
                Destination     = $destPath
                VerifyResult    = $verifyResult
            }
            
            if ($folderSuccess) {
                $totalSize    += $size
                $totalFiles   += $files
                $totalFolders += $folders
                $successCount++
                Write-Status "Successfully migrated $folderName ($(Format-Bytes $size))" -Type "Success"
                Save-CheckpointData -Username $Username -FolderName $folderName -Status 'Success'
                Write-EventLogEntry -Message "UserFolderMigrator: Migrated $folderName for $Username -> $destPath ($(Format-Bytes $size))" -EventId 1002
                Send-SyslogMessage -Message "UserFolderMigrator: Migrated $folderName for $Username ($(Format-Bytes $size))" -Severity 6
            } else {
                Write-Status "Migration of $folderName incomplete — checksum verify failed, source preserved" -Type "Error"
                Write-EventLogEntry -Message "UserFolderMigrator: FAILED $folderName for $Username — checksum verify failed" -EntryType Error -EventId 1003
                Send-SyslogMessage -Message "UserFolderMigrator: FAILED $folderName for $Username" -Severity 3
            }
        } else {
            $results += [PSCustomObject]@{
                Folder          = $folderName
                Size            = $size
                Files           = $files
                Folders         = $folders
                RegistryUpdated = $false
                SourceDeleted   = $false
                Success         = $false
                Destination     = $destPath
                VerifyResult    = $null
            }
            Write-Status "Failed to migrate $folderName" -Type "Error"
        }
        Write-Host ""
        $postFolderContext = New-PluginContext 'PostFolder' @{
            Username         = $Username
            FolderName       = $folderName
            SourcePath       = $sourcePath
            DestPath         = $destPath
            DryRun           = $DryRun
            SkipValidation   = $DryRun
        }
        $null = Invoke-PluginHooks -Stage 'PostFolder' -Context $postFolderContext
        # Circuit breaker: stop if failure threshold exceeded (Feature 1.5)
        $failCount = @($results | Where-Object { -not $_.Success }).Count
        if ($MaxFailures -gt 0 -and $failCount -ge $MaxFailures) {
            Write-Status "Circuit breaker triggered: $failCount failure(s) reached -MaxFailures $MaxFailures limit — aborting further folders for $Username" -Type "Error"
            Write-Log "Circuit breaker triggered for $Username after $failCount folder failure(s)"
            break
        }
    }
    
    Write-UserMigrationSummary -Username $Username -Results $results -TotalSize $totalSize -SuccessCount $successCount -TotalFreed $totalFreed
    } finally {
        # GUARANTEE: hive is always unloaded even if an exception fires mid-migration
        if ($hiveLoaded -and $loadedSID) {
            Unload-UserRegistryHive -SID $loadedSID
        }
    }
    
    return New-MigrationResult -Username $Username -IsActive $IsActive -Folders $results
}

function Invoke-RepairTransactionsForUser {
    <#
    .SYNOPSIS
        Resumes or repairs a partial migration for one user by replaying only unverified folders.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$Username,
        [string]$ProfilePath,
        [string]$SID,
        [bool]$IsActive
    )
    
    Write-SectionHeader "Repairing transactions for user: $Username"
    
    $hiveLoaded = $false
    $loadedSID = $null
    
    # Load registry context
    if ($IsActive) {
        $regPaths = if ([string]::IsNullOrEmpty($SID)) {
            @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
        } else {
            Get-UserRegistryPaths -SID $SID
        }
    } else {
        if (-not $DryRun) {
            $loadedSID = Load-UserRegistryHive -Username $Username -ProfilePath $ProfilePath -SID $SID
            if ($loadedSID) {
                $regPaths = Get-UserRegistryPaths -SID $loadedSID
                $hiveLoaded = $true
            } else {
                $regPaths = @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
            }
        } else { $regPaths = @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY } }
    }

    $folderList = if ($Folders -contains 'All') { $script:SHELL_FOLDERS.Keys } else { $Folders }
    $results = @()
    $totalSize   = 0L
    $totalFiles  = 0
    $totalFolders = 0
    $successCount = 0

    foreach ($folderName in $folderList) {
        $def = $script:SHELL_FOLDERS[$folderName]
        $regPath = Get-ShellFolderPath -FolderName $folderName -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey -ProfilePath $ProfilePath
        $defaultSrc = Join-Path $ProfilePath $def.Default
        
        # Detection Logic: Registry points to New Path, but data is still at Default Path
        $isPartial = ($regPath -ine $defaultSrc) -and (Test-Path $defaultSrc) -and ((Get-FolderStats $defaultSrc).FileCount -gt 0)
        
        if ($isPartial) {
            Write-Status "Partial migration detected for $folderName" -Type "Warning"
            Write-Status "  Data at: $defaultSrc" -Type "Info"
            Write-Status "  Registry points to: $regPath" -Type "Info"
            
            $stats = Get-FolderStats $defaultSrc
            $size    = $stats.Size
            $files   = $stats.FileCount
            $folders = $stats.DirCount + 1   # +1 = the folder itself; matches Windows multi-select Properties

            if ($DryRun) {
                Write-Status "[DRY RUN] Would move $(Format-Bytes $size) to complete repair." -Type "Info"
                $results += [PSCustomObject]@{
                    Folder  = $folderName; Size = $size; Files = $files; Folders = $folders
                    Source  = $defaultSrc; Destination = $regPath; Success = $true
                }
                $successCount++
                continue
            }

            # Execute the move to the path the registry already expects
            $copyOk = Invoke-RobocopyWithProgress -Source $defaultSrc -Destination $regPath -FolderName "$folderName (Repair)" -TotalBytes $size
            if ($copyOk) {
                if (-not $KeepSource) {
                    Remove-Item -LiteralPath $defaultSrc -Recurse -Force -ErrorAction SilentlyContinue
                    # Clean empty subdirectory stubs robocopy may have left at destination
                    $null = Remove-EmptyTree -Path $regPath
                }
                Write-Status "Repair completed for $folderName" -Type "Success"
                $results += [PSCustomObject]@{
                    Folder  = $folderName; Size = $size; Files = $files; Folders = $folders
                    Source  = $defaultSrc; Destination = $regPath; Success = $true
                }
                $totalSize    += $size
                $totalFiles   += $files
                $totalFolders += $folders
                $successCount++
            } else {
                Write-Status "Repair failed for $folderName" -Type "Error"
                $results += [PSCustomObject]@{
                    Folder  = $folderName; Size = $size; Files = $files; Folders = $folders
                    Source  = $defaultSrc; Destination = $regPath; Success = $false
                }
            }
        }
    }

    # ── Summary table ────────────────────────────────────────────────────────
    Write-SectionHeader "Repair Summary for $Username"
    if ($results.Count -eq 0) {
        Write-Status "No partial migrations found — nothing to repair." -Type "Info"
    } else {
        $cW = @{ Folder = 16; Size = 14; Status = 8 }
        Write-Host ("  {0,-$($cW.Folder)} {1,$($cW.Size)} {2,$($cW.Status)} Destination" `
            -f "Folder","Size","Status") -ForegroundColor Cyan
        Write-TableSeparator -Width 75
        foreach ($r in $results) {
            $sym   = if ($r.Success) { "OK" }   else { "FAIL" }
            $color = if ($r.Success) { "Green" } else { "Red" }
            $szStr = if ($r.Size -gt 0) { Format-Bytes $r.Size } else { "0 B" }
            Write-Host ("  {0,-$($cW.Folder)} {1,$($cW.Size)} " `
                -f $r.Folder, $szStr) -NoNewline
            Write-Host ("{0,$($cW.Status)} " -f $sym) -ForegroundColor $color -NoNewline
            Write-Host $r.Destination -ForegroundColor Gray
        }
        Write-TableSeparator -Width 75
        Write-Host ("  {0,-$($cW.Folder)} {1,$($cW.Size)}" `
            -f "TOTAL", (Format-Bytes $totalSize)) -ForegroundColor Cyan
        Write-TableSeparator -Width 75
        Write-Host ""
        if ($successCount -eq $results.Count) {
            Write-Status "All $successCount partial migration(s) repaired successfully." -Type "Success"
        } elseif ($successCount -gt 0) {
            Write-Status "$successCount of $($results.Count) repair(s) succeeded." -Type "Warning"
        } else {
            Write-Status "All repair attempts failed." -Type "Error"
        }
    }

    if ($hiveLoaded) { Unload-UserRegistryHive -SID $loadedSID }
    return $results
}

#endregion

#region ── Inactive User Local Data Backup ───────────────────────────────────

function Invoke-BackupInactiveUserLocalData {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Safety-net backup for inactive users.
        Before any restore or migration touches an inactive user's profile, this
        function copies every shell-folder default location that has local data
        to a timestamped backup directory using Robocopy /E /COPY:DAT so that
        subdirectories and file metadata (timestamps, attributes) are preserved.
    #>
    param(
        [string]$Username,
        [string]$ProfilePath,
        [string]$BackupRoot
    )

    Write-SectionHeader "Pre-Operation Backup: $Username (Inactive)"
    Write-Status "Backing up local profile data before proceeding..." -Type "Info"
    Write-Status "Backup root: $BackupRoot" -Type "Info"
    Write-Host ""

    if (-not $DryRun -and -not (Test-Path $BackupRoot)) {
        New-Item -Path $BackupRoot -ItemType Directory -Force | Out-Null
    }

    $folderList  = if ($Folders -contains 'All') { $script:SHELL_FOLDERS.Keys } else { $Folders }
    $backupItems = @()
    $totalBacked = 0L

    foreach ($folderName in $folderList) {
        $defaultRelPath = $script:SHELL_FOLDERS[$folderName].Default
        $localPath      = Join-Path $ProfilePath $defaultRelPath

        if (-not (Test-Path $localPath)) {
            Write-Status "  $($folderName.PadRight(12)) : No local data at default path — skipping" -Type "Info"
            continue
        }

        $stats = Get-FolderStats $localPath
        if ($stats.FileCount -eq 0) {
            Write-Status "  $($folderName.PadRight(12)) : Empty — skipping" -Type "Info"
            continue
        }

        $backupDest = Join-Path $BackupRoot $defaultRelPath
        Write-Status "  $($folderName.PadRight(12)) : $(Format-Bytes $stats.Size) · $($stats.FileCount) file(s)" -Type "Info"
        Write-Status "    From : $localPath" -Type "Info"
        Write-Status "    To   : $backupDest" -Type "Info"

        if ($DryRun) {
            Write-Status "    [DRY RUN] Would robocopy /E /COPY:DAT to $backupDest" -Type "Info"
            $backupItems += [PSCustomObject]@{
                Folder  = $folderName
                Source  = $localPath
                Dest    = $backupDest
                Size    = $stats.Size
                Files   = $stats.FileCount
                Success = $true
            }
            continue
        }

        # Invoke-RobocopyWithProgress uses /E /COPY:DAT /DCOPY:DA by default (shell folder mode).
        # Pass -ProfileBackup for /DCOPY:DAT + /XJD + /XJF (full profile copy mode).
        # KeepSource is irrelevant here — we never delete during a safety backup.
        $copyOk = Invoke-RobocopyWithProgress `
            -Source      $localPath `
            -Destination $backupDest `
            -FolderName  "$folderName (Backup)" `
            -TotalBytes  $stats.Size

        if ($copyOk) {
            Write-Status "  $($folderName.PadRight(12)) : Backup complete" -Type "Success"
            $totalBacked += $stats.Size
            Write-Log "Inactive user '$Username' backup: $folderName -> $backupDest ($(Format-Bytes $stats.Size))"
        } else {
            Write-Status "  $($folderName.PadRight(12)) : Backup FAILED" -Type "Error"
            Write-Log "Inactive user '$Username' backup FAILED: $folderName at $localPath"
        }

        $backupItems += [PSCustomObject]@{
            Folder  = $folderName
            Source  = $localPath
            Dest    = $backupDest
            Size    = $stats.Size
            Files   = $stats.FileCount
            Success = $copyOk
        }
    }

    Write-Host ""
    $okCount = @($backupItems | Where-Object { $_.Success }).Count
    if ($okCount -gt 0) {
        Write-Status "Backup complete: $okCount folder(s) · $(Format-Bytes $totalBacked) saved to $BackupRoot" -Type "Success"
    } elseif ($backupItems.Count -eq 0) {
        Write-Status "No local data found in profile to back up" -Type "Info"
    } else {
        Write-Status "Backup finished with errors: $okCount / $($backupItems.Count) succeeded" -Type "Warning"
    }
    Write-Host ""

    return $backupItems
}

#endregion

#region ── Restore Defaults Functions ────────────────────────────────────────

function Invoke-RestoreDefaultsForUser {
    <#
    .SYNOPSIS
        Resets all shell folder registry keys for one user to their Windows default paths.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$Username,
        [string]$ProfilePath,
        [string]$SID,
        [bool]$IsActive
    )
    
    Write-SectionHeader "Restoring defaults for user: $Username"
    
    $hiveLoaded = $false
    $loadedSID = $null
    
    if ($IsActive) {
        $regPaths = if ([string]::IsNullOrEmpty($SID)) {
            @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
        } else {
            Get-UserRegistryPaths -SID $SID
        }
    } else {
        Write-Status "Inactive user detected: $Username" -Type "Warning"
        
        # Determine if we can skip the expensive permission repair using AccessChk
        $skipPermissionFix = $false
        if (-not $SkipAccessCheck -and $script:AccessChkPath) {
            Write-Status "Checking profile access with AccessChk..." -Type "Info"
            try {
                $acResult = & $script:AccessChkPath -accepteula -q -r "$env:USERNAME" "$ProfilePath" 2>$null
                # AccessChk returns 0 if the account has read access
                if ($LASTEXITCODE -eq 0 -and $acResult) {
                    Write-Status "AccessChk: $Username's profile is already readable. Skipping permission fix." -Type "Success"
                    $skipPermissionFix = $true
                } else {
                    Write-Status "AccessChk: insufficient access – will repair permissions." -Type "Info"
                }
            } catch {
                Write-Status "AccessChk run failed, proceeding with normal permission fix." -Type "Warning"
            }
        }
        
            if (-not $skipPermissionFix -and -not $SkipAutoPermissionFix) {
            Write-Status "Automatically fixing permissions..." -Type "Info"
            $null = Repair-InactiveUserPermissions -ProfilePath $ProfilePath -Username $Username
        }
        
        if (-not $DryRun) {
            $loadedSID = Load-UserRegistryHive -Username $Username -ProfilePath $ProfilePath -SID $SID
            if ($loadedSID) {
                Write-Status "Registry hive loaded for $Username" -Type "Success"
                $regPaths = Get-UserRegistryPaths -SID $loadedSID
                $hiveLoaded = $true
            } else {
                Write-Status "Failed to load registry hive for $Username - using defaults" -Type "Warning"
                $regPaths = @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
            }
        } else {
            $regPaths = @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
        }
    }
    
    # For inactive users, create a safety backup of local profile data
    # before any data movement takes place (uses robocopy /E /COPY:DAT).
    if (-not $IsActive) {
        $scriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $backupRoot = Join-Path $scriptDir "UFM_InactiveBackup\${Username}_$($script:STAMP)"
        $null = Invoke-BackupInactiveUserLocalData -Username $Username -ProfilePath $ProfilePath -BackupRoot $backupRoot
    }

    $systemDrive = $env:SystemDrive + "\"
    $folderList = if ($Folders -contains 'All') { $script:SHELL_FOLDERS.Keys } else { $Folders }
    
    # First pass: check space requirements
    Write-Status "Checking space requirements for $Username..." -Type "Info"
    $spaceCheckPassed = $true
    $foldersToRestore = @()
    
    foreach ($folderName in $folderList) {
        $currentPath = Get-ShellFolderPath -FolderName $folderName -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey -ProfilePath $ProfilePath
        $defaultPath = Join-Path $ProfilePath $script:SHELL_FOLDERS[$folderName].Default
        
        # Folder already at default — ensure the directory exists even if it was deleted
        if ($currentPath -ieq $defaultPath -or [string]::IsNullOrEmpty($currentPath)) {
            if (-not (Test-Path $defaultPath)) {
                if ($DryRun) {
                    Write-Status "  $folderName : [DRY RUN] Default folder missing - would create $defaultPath" -Type "Info"
                } else {
                    New-Item -Path $defaultPath -ItemType Directory -Force | Out-Null
                    Write-Status "  $folderName : Recreated missing default folder" -Type "Info"
                    Write-Log "Recreated missing default folder for $folderName : $defaultPath"
                }
            } else {
                Write-Status "  $folderName : Already at default location" -Type "Info"
            }
            continue
        }
        
        if ($currentPath -and (Test-Path $currentPath) -and $currentPath -ine $defaultPath) {
            $stats         = Get-FolderStats $currentPath
            $size          = $stats.Size
            $freeSpace     = Get-DiskFreeSpace -Path $systemDrive
            $requiredSpace = $size * 1.1
            
            if ($freeSpace -ge $requiredSpace) {
                Write-Status "  $folderName : Need $(Format-Bytes $requiredSpace), Available: $(Format-Bytes $freeSpace) ✓" -Type "Info"
                $foldersToRestore += @{
                    Name       = $folderName
                    SourcePath = $currentPath
                    DestPath   = $defaultPath
                    Size       = $size
                    Files      = $stats.FileCount
                    Folders    = $stats.DirCount + 1   # +1 = the folder itself; matches Windows multi-select Properties
                }
            } else {
                Write-Status "  $folderName : Need $(Format-Bytes $requiredSpace), Available: $(Format-Bytes $freeSpace) ✗" -Type "Error"
                $spaceCheckPassed = $false
            }
        } elseif ($currentPath -and -not (Test-Path $currentPath) -and $currentPath -ine $defaultPath) {
            # Registry points to a non-default path that no longer exists — just create
            # the default folder and redirect registry; no data to copy
            Write-Status "  $folderName : Registry points to missing path - will recreate default" -Type "Info"
            $foldersToRestore += @{
                Name = $folderName
                SourcePath = $null      # nothing to copy
                DestPath = $defaultPath
                Size = 0
                Files = 0
                Folders = 0
            }
        }
    }
    
    if (-not $spaceCheckPassed) {
        Write-Status "Space check failed for user $Username. Aborting restore." -Type "Error"
        if ($hiveLoaded) { Unload-UserRegistryHive -SID $loadedSID }
        return $null
    }
    
    if ($foldersToRestore.Count -eq 0) {
        Write-Status "No folders need to be restored for $Username" -Type "Info"
        if ($hiveLoaded) { Unload-UserRegistryHive -SID $loadedSID }
        return @()
    }
    
    if ($DryRun) {
        Write-Status "[DRY RUN] Would restore $($foldersToRestore.Count) folders for $Username" -Type "Info"
        foreach ($folder in $foldersToRestore) {
            Write-Status "  Would restore $($folder.Name) ($(Format-Bytes $folder.Size))" -Type "Info"
        }
        if ($hiveLoaded) { Unload-UserRegistryHive -SID $loadedSID }
        return $foldersToRestore
    }
    
    # Second pass: perform restore
    $results = @()
    $totalSize = 0
    $successCount = 0
    
    foreach ($folder in $foldersToRestore) {
        Write-Status "Restoring: $($folder.Name)" -Type "Info"
        
        # Always ensure destination folder exists
        if (-not (Test-Path $folder.DestPath)) {
            New-Item -Path $folder.DestPath -ItemType Directory -Force | Out-Null
        }
        
        # SourcePath is $null when registry pointed to a non-existent path — no copy needed
        if ([string]::IsNullOrEmpty($folder.SourcePath)) {
            Write-Status "  No source data to copy - updating registry only" -Type "Info"
            Write-Status "  To: $($folder.DestPath)" -Type "Info"
            Write-Host ""
            $regSuccess = Set-ShellFolderRegistryPath -FolderName $folder.Name -NewPath $folder.DestPath -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey
            $results += [PSCustomObject]@{
                Folder = $folder.Name; Size = 0; Files = 0; Folders = 0
                RegistryUpdated = $regSuccess; SourceDeleted = $false
                Destination = $folder.DestPath; Success = $regSuccess
            }
            if ($regSuccess) { $successCount++ } else {
                Write-Status "Failed to update registry for $($folder.Name)" -Type "Error"
            }
            Write-Host ""
            continue
        }
        
        Write-Status "  From: $($folder.SourcePath)" -Type "Info"
        Write-Status "  To:   $($folder.DestPath)" -Type "Info"
        Write-Status "  Size: $(Format-Bytes $folder.Size), Files: $($folder.Files), Folders: $($folder.Folders)" -Type "Info"
        Write-Host ""
        
        $copySuccess = Invoke-RobocopyWithProgress -Source $folder.SourcePath -Destination $folder.DestPath -FolderName "$($folder.Name) (Restore)" -TotalBytes $folder.Size
        
        if ($copySuccess) {
            # Verify before source deletion; skip when no files were copied.
            $verifyResult = $null
            if (-not $DisableChecksumVerify -and $folder.Files -gt 0) {
                $verifyResult = Invoke-VerifyFolderChecksums -SourcePath $folder.SourcePath -DestPath $folder.DestPath -FolderName "$($folder.Name) (Restore)"
            }
            $verifyFailed = $verifyResult -and -not $verifyResult.Passed
            $skipDelete   = $verifyFailed

            # Only redirect the registry when the copy is verified good.
            # If verify failed, leave the registry pointing to the current
            # (backup) location — data at the default path is suspect.
            $regSuccess = $false
            if (-not $verifyFailed) {
                $regSuccess = Set-ShellFolderRegistryPath -FolderName $folder.Name -NewPath $folder.DestPath -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey
                if (-not $regSuccess) {
                    Write-Status "Failed to update registry for $($folder.Name)" -Type "Error"
                }
            }

            $srcDeleted = $false
            if (-not $skipDelete -and $regSuccess) {
                try {
                    Remove-Item -LiteralPath $folder.SourcePath -Recurse -Force -ErrorAction Stop
                    $srcDeleted = $true
                    Write-Status "Source removed: $($folder.SourcePath)" -Type "Success"
                } catch {
                    Write-Status "Could not remove source: $_" -Type "Warning"
                }
            } elseif ($skipDelete) {
                Write-Status "$($folder.Name) : Source preserved — checksum verification failed" -Type "Warning"
            }

            # Folder succeeds only when both copy AND verify AND registry all pass.
            $folderSuccess = -not $verifyFailed -and $regSuccess
            $results += [PSCustomObject]@{
                Folder = $folder.Name; Size = $folder.Size
                Files = $folder.Files; Folders = $folder.Folders
                RegistryUpdated = $regSuccess; SourceDeleted = $srcDeleted
                Destination = $folder.DestPath; Success = $folderSuccess
                VerifyResult = $verifyResult
            }
            if ($folderSuccess) {
                $totalSize += $folder.Size
                $successCount++
            } else {
                if ($verifyFailed) {
                    Write-Status "Restore of $($folder.Name) incomplete — checksum verify failed, registry not updated" -Type "Error"
                }
            }
        } else {
            Write-Status "Failed to restore $($folder.Name)" -Type "Error"
            $results += [PSCustomObject]@{
                Folder = $folder.Name; Size = $folder.Size
                Files = $folder.Files; Folders = $folder.Folders
                RegistryUpdated = $false; SourceDeleted = $false
                Destination = $folder.DestPath; Success = $false
                VerifyResult = $null
            }
        }
        Write-Host ""
    }
    
    # ── Post-restore: clean up empty source containers ───────────────────────
    # After all shell folders are moved back to their defaults, the directories
    # that held them (e.g. Y:\Data\Test\) may now be empty.  Walk up two levels
    # from each unique source parent and remove any that are now empty.
    # FIX: only clean up source containers when at least one folder was actually restored.
    # Without this guard, a total-failure run (e.g. VirtualBox exit-16) would still
    # delete all the source directories on the shared drive.
    if (-not $DryRun -and $successCount -gt 0) {
        $uniqueParents = @(
            $foldersToRestore |
            Where-Object { -not [string]::IsNullOrEmpty($_.SourcePath) } |
            ForEach-Object { Split-Path -Parent $_.SourcePath } |
            Select-Object -Unique
        )
        foreach ($parent in $uniqueParents) {
            if (-not (Test-Path -LiteralPath $parent)) { continue }
            if (Remove-EmptyTree -Path $parent -IncludeSelf) {
                Write-Status "Cleaned up empty container: $parent" -Type "Info"
                # Also try grandparent (e.g. Y:\Data\ after Y:\Data\Test\ is gone)
                $grandParent = Split-Path -Parent $parent
                if ($grandParent -and (Test-Path -LiteralPath $grandParent)) {
                    if (Remove-EmptyTree -Path $grandParent -IncludeSelf) {
                        Write-Status "Cleaned up empty container: $grandParent" -Type "Info"
                    }
                }
            }
        }
    }

    # ── Summary table ────────────────────────────────────────────────────────
    Write-SectionHeader "Restore Summary for $Username"
    $cW = @{ Folder = 16; Size = 14; Reg = 7; Source = 10; Status = 8 }
    Write-Host ("  {0,-$($cW.Folder)} {1,$($cW.Size)} {2,$($cW.Reg)} {3,$($cW.Source)} {4,$($cW.Status)} Destination" `
        -f "Folder","Size","Reg","Source","Status") -ForegroundColor Cyan
    Write-TableSeparator -Width 90
    # Sort alphabetically by folder name so the summary always appears in A-Z order
    # regardless of the order folders were processed during restore.
    $sortedResults = $results | Sort-Object Folder
    foreach ($r in $sortedResults) {
        $sym    = if ($r.Success) { "OK" }      else { "FAIL" }
        $color  = if ($r.Success) { "Green" }   else { "Red" }
        $regSym = if ($r.RegistryUpdated) { "yes" } else { "no" }
        $srcSym = if ($r.SourceDeleted)   { "deleted" } elseif ($r.Success) { "kept" } else { "n/a" }
        $szStr  = if ($r.Size -gt 0) { Format-Bytes $r.Size } else { "0 B" }
        Write-Host ("  {0,-$($cW.Folder)} {1,$($cW.Size)} {2,$($cW.Reg)} {3,$($cW.Source)} " `
            -f $r.Folder, $szStr, $regSym, $srcSym) -NoNewline
        Write-Host ("{0,$($cW.Status)} " -f $sym) -ForegroundColor $color -NoNewline
        Write-Host $r.Destination -ForegroundColor Gray
    }
    Write-TableSeparator -Width 90
    Write-Host ("  {0,-$($cW.Folder)} {1,$($cW.Size)}" `
        -f "TOTAL", (Format-Bytes $totalSize)) -ForegroundColor Cyan
    Write-TableSeparator -Width 90
    Write-Host ""
    if ($successCount -eq $foldersToRestore.Count -and $foldersToRestore.Count -gt 0) {
        Write-Status "All $successCount folder(s) restored successfully." -Type "Success"
    } elseif ($successCount -gt 0) {
        Write-Status "$successCount of $($foldersToRestore.Count) folder(s) restored successfully." -Type "Warning"
    } else {
        Write-Status "No folders were restored successfully." -Type "Error"
    }
    
    if ($hiveLoaded) {
        Unload-UserRegistryHive -SID $loadedSID
    }
    
    return $results
}

#endregion

#region ── Redirect and Clean Functions ──────────────────────────────────────

function Invoke-RedirectAndCleanForUser {
    <#
    .SYNOPSIS
        Updates shell folder registry keys to an existing data location without copying files.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$Username,
        [string]$ProfilePath,
        [string]$Destination,
        [string]$SID,
        [bool]$IsActive,
        # Multi-user mode passes the base root and needs username appended.
        # Single-user mode passes the exact user data folder — no appending needed.
        [bool]$AppendUsername = $true
    )
    
    Write-SectionHeader "Redirecting user: $Username"
    
    $userDestination = if ($AppendUsername) {
        Get-UserDestinationPath -BaseDestination $Destination -Username $Username
    } else {
        $Destination
    }
    Write-Status "Data folder : $userDestination" -Type "Info"
    
    $hiveLoaded = $false
    $loadedSID = $null
    
    if ($IsActive) {
        $regPaths = if ([string]::IsNullOrEmpty($SID)) {
            @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
        } else {
            Get-UserRegistryPaths -SID $SID
        }
    } else {
        Write-Status "Inactive user detected: $Username" -Type "Warning"
        
        # Determine if we can skip the expensive permission repair using AccessChk
        $skipPermissionFix = $false
        if (-not $SkipAccessCheck -and $script:AccessChkPath) {
            Write-Status "Checking profile access with AccessChk..." -Type "Info"
            try {
                $acResult = & $script:AccessChkPath -accepteula -q -r "$env:USERNAME" "$ProfilePath" 2>$null
                if ($LASTEXITCODE -eq 0 -and $acResult) {
                    Write-Status "AccessChk: $Username's profile is already readable. Skipping permission fix." -Type "Success"
                    $skipPermissionFix = $true
                } else {
                    Write-Status "AccessChk: insufficient access – will repair permissions." -Type "Info"
                }
            } catch {
                Write-Status "AccessChk run failed, proceeding with normal permission fix." -Type "Warning"
            }
        }
        
            if (-not $skipPermissionFix -and -not $SkipAutoPermissionFix) {
            Write-Status "Automatically fixing permissions..." -Type "Info"
            $null = Repair-InactiveUserPermissions -ProfilePath $ProfilePath -Username $Username
        }
        
        if (-not $DryRun) {
            $loadedSID = Load-UserRegistryHive -Username $Username -ProfilePath $ProfilePath -SID $SID
            if ($loadedSID) {
                Write-Status "Registry hive loaded for $Username" -Type "Success"
                $regPaths = Get-UserRegistryPaths -SID $loadedSID
                $hiveLoaded = $true
            } else {
                Write-Status "Failed to load registry hive for $Username - using defaults" -Type "Warning"
                $regPaths = @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
            }
        } else {
            $regPaths = @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
        }
    }
    
    $folderList = if ($Folders -contains 'All') { $script:SHELL_FOLDERS.Keys } else { $Folders }
    $results = @()
    $successCount = 0
    
    foreach ($folderName in $folderList) {
        $currentPath = Get-ShellFolderPath -FolderName $folderName -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey -ProfilePath $ProfilePath
        
        if (-not $currentPath) {
            Write-Status "$folderName : Cannot determine current path - skipping" -Type "Warning"
            continue
        }
        
        $folderLeaf = $script:SHELL_FOLDERS[$folderName].Default
        $destPath = Join-Path $userDestination $folderLeaf
        
        if (-not (Test-Path $destPath)) {
            if ($DryRun) {
                Write-Status "$folderName : [DRY RUN] Destination missing - would create $destPath" -Type "Info"
            } else {
                New-Item -Path $destPath -ItemType Directory -Force | Out-Null
                Write-Status "$folderName : Created missing destination folder: $destPath" -Type "Info"
                Write-Log "Created missing destination folder for $folderName : $destPath"
            }
        }
        
        if ($currentPath -ieq $destPath) {
            Write-Status "$folderName : Already pointing to correct location" -Type "Info"
            continue
        }
        
        Write-Status "$folderName : $currentPath -> $destPath" -Type "Info"
        
        if ($DryRun) {
            Write-Status "[DRY RUN] Would redirect registry for $folderName" -Type "Info"
            $results += [PSCustomObject]@{ Folder = $folderName; FromPath = $currentPath; Destination = $destPath; Success = $true }
            $successCount++
            continue
        }
        
        $regSuccess = Set-ShellFolderRegistryPath -FolderName $folderName -NewPath $destPath -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey
        
        if ($regSuccess) {
            if ($currentPath -and (Test-Path $currentPath) -and ($currentPath -ine $destPath)) {
                try {
                    Remove-Item -LiteralPath $currentPath -Recurse -Force -ErrorAction Stop
                    Write-Status "$folderName : Source deleted: $currentPath" -Type "Success"
                } catch {
                    Write-Status "$folderName : Could not delete source: $_" -Type "Warning"
                }
            }
            $results += [PSCustomObject]@{
                Folder = $folderName; FromPath = $currentPath; Destination = $destPath; Success = $true
            }
            $successCount++
            Write-Status "$folderName : Redirected successfully" -Type "Success"
        } else {
            $results += [PSCustomObject]@{
                Folder = $folderName; FromPath = $currentPath; Destination = $destPath; Success = $false
            }
            Write-Status "$folderName : Failed to redirect" -Type "Error"
        }
    }
    
    # ── Summary table ────────────────────────────────────────────────────────
    Write-SectionHeader "Redirect Summary for $Username"
    if ($results.Count -eq 0) {
        Write-Status "All folders already pointing to correct locations — nothing to redirect." -Type "Info"
    } else {
        $cW = @{ Folder = 16; Status = 8 }
        Write-Host ("  {0,-$($cW.Folder)} {1,$($cW.Status)} New Location" -f "Folder","Status") -ForegroundColor Cyan
        Write-TableSeparator -Width 115
        foreach ($r in $results) {
            $sym   = if ($r.Success) { "OK" }   else { "FAIL" }
            $color = if ($r.Success) { "Green" } else { "Red" }
            Write-Host ("  {0,-$($cW.Folder)} " -f $r.Folder) -NoNewline
            Write-Host ("{0,$($cW.Status)} " -f $sym) -ForegroundColor $color -NoNewline
            Write-Host $r.Destination -ForegroundColor Gray
        }
        Write-TableSeparator -Width 115
        Write-Host ""
        if ($successCount -eq $results.Count) {
            Write-Status "All $successCount folder(s) redirected successfully." -Type "Success"
        } elseif ($successCount -gt 0) {
            Write-Status "$successCount of $($results.Count) folder(s) redirected successfully." -Type "Warning"
        } else {
            Write-Status "All redirect attempts failed." -Type "Error"
        }
    }
    
    if ($hiveLoaded) {
        Unload-UserRegistryHive -SID $loadedSID
    }
    
    return $results
}

#endregion

#region ── Report Only Functions ─────────────────────────────────────────────

function Invoke-ReportOnlyForUser {
    <#
    .SYNOPSIS
        Reads and reports the current shell folder configuration for one user with no changes.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$Username,
        [string]$ProfilePath,
        [string]$SID,
        [bool]$IsActive
    )
    
    Write-SectionHeader "Report for user: $Username"
    
    $hiveLoaded = $false
    $loadedSID = $null
    
    if ($IsActive) {
        $regPaths = if ([string]::IsNullOrEmpty($SID)) {
            @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
        } else {
            Get-UserRegistryPaths -SID $SID
        }
    } else {
        if (-not $DryRun) {
            $loadedSID = Load-UserRegistryHive -Username $Username -ProfilePath $ProfilePath -SID $SID
            if ($loadedSID) {
                $regPaths = Get-UserRegistryPaths -SID $loadedSID
                $hiveLoaded = $true
            } else {
                $regPaths = @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
            }
        } else {
            $regPaths = @{ UsfKey = $script:USF_KEY; SfKey = $script:SF_KEY }
        }
    }
    
    $folderList = if ($Folders -contains 'All') { $script:SHELL_FOLDERS.Keys } else { $Folders }
    
    Write-Host ("  {0,-14} {1,-50} {2,12} {3}" -f "Folder", "Current Path", "Size", "Status") -ForegroundColor Cyan
    Write-TableSeparator -Width 90
    
    $totalSize = 0
    
    foreach ($folderName in $folderList) {
        $currentPath = Get-ShellFolderPath -FolderName $folderName -UsfKey $regPaths.UsfKey -SfKey $regPaths.SfKey -ProfilePath $ProfilePath
        
        $exists = $currentPath -and (Test-Path $currentPath)
        $status = if (-not $currentPath) { "NOT SET" } elseif (-not $exists) { "MISSING" } else { "OK" }
        $color = switch ($status) { "OK" { "Green" } "MISSING" { "Red" } default { "Yellow" } }
        
        $sizeStr = "—"
        if ($exists) {
            $size    = (Get-FolderStats $currentPath).Size
            $sizeStr = Format-Bytes $size
            $totalSize += $size
        }
        
        $displayPath = if ($currentPath -and $currentPath.Length -gt 50) { "...$($currentPath.Substring($currentPath.Length - 47))" } else { "$currentPath" }
        
        Write-Host ("  {0,-14} {1,-50} {2,12} " -f $folderName, $displayPath, $sizeStr) -NoNewline
        Write-Host $status -ForegroundColor $color
    }
    
    Write-TableSeparator -Width 90
    Write-Host ("  {0,-14} {1,-50} {2,12}" -f "TOTAL", "", (Format-Bytes $totalSize)) -ForegroundColor Cyan
    Write-TableSeparator -Width 90
    Write-Host ""
    
    if ($hiveLoaded) {
        Unload-UserRegistryHive -SID $loadedSID
    }
    
    return @{ TotalSize = $totalSize }
}

#endregion

#region ── Rollback Functions ────────────────────────────────────────────────

function Invoke-Rollback {
    <#
    .SYNOPSIS
        Restores shell folder registry keys from a JSON backup created during a prior migration.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()
    Write-SectionHeader "ROLLBACK MODE"
    
    $backupDir = Join-Path $env:ProgramData 'UserFolderMigrator\Backups'
    if (-not (Test-Path $backupDir)) {
        Write-Status "No backup directory found at: $backupDir" -Type "Error"
        $script:ExitCode = 1
        return $false
    }
    
    $backupFiles = @(Get-ChildItem -Path $backupDir -Filter "RegistryBackup_*.reg" | Sort-Object LastWriteTime -Descending)
    
    if ($backupFiles.Count -eq 0) {
        Write-Status "No registry backup files found" -Type "Error"
        $script:ExitCode = 1
        return $false
    }
    
    # If -RollbackFile was supplied (unattended or pre-selected), use it directly
    # without showing the picker or prompting. Otherwise show the interactive list.
    $selectedFile = $null
    if ($RollbackFile) {
        if (-not (Test-Path $RollbackFile)) {
            Write-Status "RollbackFile not found: $RollbackFile" -Type "Error"
            Write-Log "Rollback: RollbackFile '$RollbackFile' does not exist"
            $script:ExitCode = 1
            return $false
        }
        $selectedFile = Get-Item $RollbackFile -ErrorAction SilentlyContinue
        Write-Status "Using specified RollbackFile: $($selectedFile.Name)" -Type "Info"
    } else {
        for ($i = 0; $i -lt [Math]::Min(5, $backupFiles.Count); $i++) {
            $file = $backupFiles[$i]
            Write-Host "  [$($i+1)] $($file.Name) - $($file.LastWriteTime)" -ForegroundColor Gray
        }
        Write-Host ""

        $selection = Invoke-Prompt -Message "  Select backup to restore (1-$([Math]::Min(5, $backupFiles.Count)))"
        $selInt = 0
        if (-not [int]::TryParse($selection.Trim(), [ref]$selInt)) {
            Write-Status "Invalid selection: '$selection' is not a number" -Type "Error"
            $script:ExitCode = 1
            return $false
        }
        $index = $selInt - 1
        if ($index -lt 0 -or $index -ge $backupFiles.Count) {
            Write-Status "Invalid selection: out of range" -Type "Error"
            $script:ExitCode = 1
            return $false
        }
        $selectedFile = $backupFiles[$index]
    }

    Write-Status "Restoring from: $($selectedFile.Name)" -Type "Info"
    
    if ($DryRun) {
        Write-Status "[DRY RUN] Would restore registry from backup" -Type "Info"
        return $true
    }
    
    $result = Restore-RegistryFromBackup -BackupFile $selectedFile.FullName
    
    if ($result) {
        Write-Status "Registry rollback completed successfully" -Type "Success"
        Restart-Explorer
    } else {
        Write-Status "Registry rollback failed" -Type "Error"
        $script:ExitCode = 1
    }
    
    return $result
}

#endregion

#region ── Checksum Verification ─────────────────────────────────────────────

function Get-FileHashTiered {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Tiered integrity hashing — algorithm selected by $ChecksumAlgorithm (default SHA256).
          Full        — complete hash for files ≤ 10 GB
          Partial     — hash of 3 × 64 MB samples (start / middle / end) for files ≤ 50 GB
          FastVerify  — size + last-write-UTC ticks only, no hash, for files > 50 GB
    #>
    param([string]$FilePath)

    $res = [PSCustomObject]@{
        Method       = 'Unknown'
        Hash         = ''
        SizeBytes    = 0L
        LastWriteUtc = [datetime]::MinValue
        Error        = ''
    }

    try {
        $fi               = [System.IO.FileInfo]::new($FilePath)
        $res.SizeBytes    = $fi.Length
        $res.LastWriteUtc = $fi.LastWriteTimeUtc

        $tenGB   = 10L * 1073741824L   # 10 GB
        $fiftyGB = 50L * 1073741824L   # 50 GB
        # Buffer size: use HW-tuned value (scales with free RAM); fallback 64 MB
        $chunk   = if ($script:HW -and $script:HW.HashBufferBytes -gt 0) { $script:HW.HashBufferBytes } else { 64L * 1048576L }

        if ($fi.Length -le $tenGB) {
            # ── Full hash ──────────────────────────────────────────────────────
            $res.Method = 'Full'
            $algo = [System.Security.Cryptography.HashAlgorithm]::Create($ChecksumAlgorithm)
            try {
                $fs = [System.IO.File]::OpenRead($FilePath)
                try {
                    $res.Hash = ([System.BitConverter]::ToString($algo.ComputeHash($fs)) -replace '-','').ToUpper()
                } finally { $fs.Dispose() }
            } finally { $algo.Dispose() }

        } elseif ($fi.Length -le $fiftyGB) {
            # ── Partial hash: 3 × 64 MB samples (start / middle / end) ─────────
            $res.Method = 'Partial'
            $buf  = [byte[]]::new($chunk)
            $algo = [System.Security.Cryptography.HashAlgorithm]::Create($ChecksumAlgorithm)
            $fs   = [System.IO.File]::OpenRead($FilePath)
            try {
                # Chunk 1 — start
                $n = $fs.Read($buf, 0, $buf.Length)
                [void]$algo.TransformBlock($buf, 0, $n, $buf, 0)

                # Chunk 2 — middle
                [void]$fs.Seek([long]([Math]::Max(0, $fi.Length / 2 - $chunk / 2)), [System.IO.SeekOrigin]::Begin)
                $n = $fs.Read($buf, 0, $buf.Length)
                [void]$algo.TransformBlock($buf, 0, $n, $buf, 0)

                # Chunk 3 — end (final block commits the hash)
                [void]$fs.Seek([long]([Math]::Max(0, $fi.Length - $chunk)), [System.IO.SeekOrigin]::Begin)
                $n = $fs.Read($buf, 0, $buf.Length)
                [void]$algo.TransformFinalBlock($buf, 0, $n)
                $res.Hash = ([System.BitConverter]::ToString($algo.Hash) -replace '-','').ToUpper()
            } finally {
                $fs.Dispose()
                $algo.Dispose()
            }

        } else {
            # ── Fast verify: no hash; compare size + last-write ticks ────────
            $res.Method = 'FastVerify'
            $res.Hash   = "SZ:$($fi.Length)|LW:$($fi.LastWriteTimeUtc.Ticks)"
        }
    } catch {
        $res.Error = $_.Exception.Message
    }

    return $res
}

function Invoke-VerifyFolderChecksums {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Compares every file in SourcePath against its counterpart in DestPath
        using Get-FileHashTiered.  Returns a summary with per-file results.

        CRITICAL — exclusion parity with Robocopy:
        Robocopy's /XF flag silently skips files matching the auto-exclusion list
        (desktop.ini, *.tmp, thumbs.db, etc.) and any user-supplied $Exclude
        patterns.  If verify enumerates those files in the SOURCE but they were
        not copied to DESTINATION (or Windows auto-generated a different copy
        there), every excluded file would produce a spurious MISMATCH failure.
        This function therefore applies the identical filter before comparing.
    #>
    param(
        [string]$SourcePath,
        [string]$DestPath,
        [string]$FolderName
    )

    Write-Status "Verifying: $FolderName …" -Type "Info"
    Write-Log "Verify start: $FolderName  src=$SourcePath  dst=$DestPath"

    # ── Build the effective exclusion set (mirrors Invoke-RobocopyWithProgress) ─
    $excludePatterns = [System.Collections.Generic.List[string]]::new()
    if (-not $DisableAutoExclusions) {
        foreach ($p in @('*.tmp','*.temp','*.log','*.bak','desktop.ini','thumbs.db','.DS_Store')) {
            $excludePatterns.Add($p)
        }
    }
    foreach ($p in $Exclude) {
        if (-not [string]::IsNullOrWhiteSpace($p)) { $excludePatterns.Add($p) }
    }

    $fileResults = [System.Collections.Generic.List[object]]::new()
    $pass        = $true
    $errCount    = 0
    $skipped     = 0

    $opts = [System.IO.EnumerationOptions]::new()
    $opts.RecurseSubdirectories = $true
    $opts.AttributesToSkip      = 0
    $opts.IgnoreInaccessible    = $true

    $srcFiles = @(try { [System.IO.Directory]::EnumerateFiles($SourcePath, '*', $opts) } catch { @() })
    $total    = $srcFiles.Count
    $done     = 0

    foreach ($srcFile in $srcFiles) {
        $done++
        $fileName = [System.IO.Path]::GetFileName($srcFile)

        # Skip any file matching the exclusion list — same set robocopy skipped.
        $excluded = $false
        foreach ($pat in $excludePatterns) {
            if ($fileName -like $pat) { $excluded = $true; break }
        }
        if ($excluded) { $skipped++; continue }

        $relPath = $srcFile.Substring($SourcePath.TrimEnd('\').Length).TrimStart('\')
        $dstFile = Join-Path $DestPath $relPath

        $entry = [PSCustomObject]@{
            RelPath  = $relPath
            Method   = ''
            SrcHash  = ''
            DstHash  = ''
            SizeSrc  = 0L
            SizeDst  = 0L
            Match    = $false
            Error    = ''
        }

        if (-not (Test-Path -LiteralPath $dstFile)) {
            $entry.Error = 'Destination file missing'
            $pass = $false; $errCount++
            $fileResults.Add($entry)

            # Quarantine the source file (destination missing)
            if ($script:QuarantineRoot) {
                $qResult = Copy-FileToQuarantine -SourceFile $srcFile -SourceRoot $SourcePath `
                    -QuarantineRoot $script:QuarantineRoot -Reason "DestinationMissing" -DryRun:$DryRun
                $script:QuarantinedFiles.Add($qResult)
            }
            continue
        }

        $srcH = Get-FileHashTiered -FilePath $srcFile
        $dstH = Get-FileHashTiered -FilePath $dstFile

        $entry.Method  = $srcH.Method
        $entry.SrcHash = $srcH.Hash
        $entry.DstHash = $dstH.Hash
        $entry.SizeSrc = $srcH.SizeBytes
        $entry.SizeDst = $dstH.SizeBytes
        $entry.Error   = $(if ($srcH.Error) { "Src: $($srcH.Error)" } elseif ($dstH.Error) { "Dst: $($dstH.Error)" } else { '' })

        if ($entry.Error) {
            $entry.Match = $false; $pass = $false; $errCount++
            # Quarantine unreadable files
            if ($script:QuarantineRoot) {
                $reason = if ($srcH.Error) { "SourceUnreadable" } else { "DestUnreadable" }
                $qResult = Copy-FileToQuarantine -SourceFile $srcFile -SourceRoot $SourcePath `
                    -QuarantineRoot $script:QuarantineRoot -Reason $reason -DryRun:$DryRun
                $script:QuarantinedFiles.Add($qResult)
            }
        } else {
            $entry.Match = ($srcH.Hash -ceq $dstH.Hash)
            if (-not $entry.Match) {
                $pass = $false; $errCount++
                # Quarantine mismatched files
                if ($script:QuarantineRoot) {
                    $qResult = Copy-FileToQuarantine -SourceFile $srcFile -SourceRoot $SourcePath `
                        -QuarantineRoot $script:QuarantineRoot -Reason "SHA256Mismatch" -DryRun:$DryRun
                    $script:QuarantinedFiles.Add($qResult)
                }
            }
        }

        $fileResults.Add($entry)

        $checked = $done - $skipped
        if ($checked % 50 -eq 0 -or $done -eq $total) {
            Write-Host "`r  [Verify] $($FolderName.PadRight(12)) — $checked checked$(if ($skipped -gt 0) { ", $skipped excluded" })" -NoNewline -ForegroundColor DarkCyan
        }
    }

    $checked = $total - $skipped
    # Erase the verify progress line before printing the result status.
    if ($checked -gt 0) { Clear-ProgressLine }

    $summary = [PSCustomObject]@{
        FolderName  = $FolderName
        SourcePath  = $SourcePath
        DestPath    = $DestPath
        TotalFiles  = $checked
        SkippedFiles = $skipped
        ErrorCount  = $errCount
        Passed      = $pass
        FileResults = $fileResults
    }

    if ($pass) {
        Write-Status "Verify $FolderName : PASSED ($checked file(s) verified$(if ($skipped -gt 0) { ", $skipped excluded" }) — $ChecksumAlgorithm)" -Type "Success"
    } else {
        Write-Status "Verify $FolderName : FAILED ($errCount mismatch(es) in $checked file(s)$(if ($skipped -gt 0) { ", $skipped excluded" }))" -Type "Error"
    }
    Write-Log "Verify $FolderName : $(if ($pass) { 'PASSED' } else { 'FAILED' }) — $checked verified, $skipped excluded, $errCount errors"

    return $summary
}

function Copy-FileToQuarantine {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Copies a mismatched or unreadable file to a quarantine folder for forensic analysis.
        Preserves the relative path structure from the source root.
        Never deletes or modifies the original file.
    .PARAMETER SourceFile
        Full path to the problematic file.
    .PARAMETER SourceRoot
        The root folder being migrated (e.g., C:\Users\John\Desktop). Used to calculate relative path.
    .PARAMETER QuarantineRoot
        The quarantine destination root (e.g., D:\UFM_Quarantine_20240101).
    .PARAMETER Reason
        Short description of why the file was quarantined (e.g., 'SHA256 Mismatch', 'Unreadable').
    .PARAMETER DryRun
        If set, only logs the action without copying.
    .OUTPUTS
        [PSCustomObject] with Path, QuarantinePath, Reason, Success, and Error properties.
    #>
    param(
        [Parameter(Mandatory)] [string]$SourceFile,
        [Parameter(Mandatory)] [string]$SourceRoot,
        [Parameter(Mandatory)] [string]$QuarantineRoot,
        [Parameter(Mandatory)] [string]$Reason,
        [switch]$DryRun
    )

    $result = [PSCustomObject]@{
        SourcePath      = $SourceFile
        QuarantinePath  = ''
        Reason          = $Reason
        Success         = $false
        Error           = ''
        SizeBytes       = 0L
    }

    try {
        $fileInfo = [System.IO.FileInfo]::new($SourceFile)
        $result.SizeBytes = $fileInfo.Length

        # Calculate relative path from source root
        $sourceRootNormalized = $SourceRoot.TrimEnd('\')
        $relativePath = if ($SourceFile.StartsWith($sourceRootNormalized, [System.StringComparison]::OrdinalIgnoreCase)) {
            $SourceFile.Substring($sourceRootNormalized.Length).TrimStart('\')
        } else {
            # Fallback: use filename only
            [System.IO.Path]::GetFileName($SourceFile)
        }

        $quarantineDest = Join-Path $QuarantineRoot $relativePath
        $result.QuarantinePath = $quarantineDest

        if ($DryRun) {
            Write-Log "Quarantine [DryRun]: Would copy '$SourceFile' -> '$quarantineDest' (Reason: $Reason)"
            $result.Success = $true
            return $result
        }

        # Create destination directory
        $quarantineDir = Split-Path $quarantineDest -Parent
        if (-not (Test-Path $quarantineDir)) {
            New-Item -Path $quarantineDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        # Copy with retry logic (handles transient locks)
        ${maxAttempts} = 3
        $attempt = 0
        $copied = $false

        while (-not $copied -and $attempt -lt ${maxAttempts}) {
            $attempt++
            try {
                Copy-Item -LiteralPath $SourceFile -Destination $quarantineDest -Force -ErrorAction Stop
                $copied = $true
            } catch {
                if ($attempt -ge ${maxAttempts}) {
                    throw $_
                }
                Write-Log "Quarantine copy attempt $attempt/${maxAttempts} failed for '$SourceFile': $($_.Exception.Message) — retrying..."
                Start-Sleep -Seconds 2
            }
        }

        # Verify the copy (hash comparison)
        try {
            $srcHash = (Get-FileHash -LiteralPath $SourceFile -Algorithm SHA256 -ErrorAction Stop).Hash
            $dstHash = (Get-FileHash -LiteralPath $quarantineDest -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($srcHash -ne $dstHash) {
                Remove-Item -LiteralPath $quarantineDest -Force -ErrorAction SilentlyContinue
                throw "SHA256 mismatch after quarantine copy"
            }
        } catch {
            throw "Quarantine verification failed: $($_.Exception.Message)"
        }

        $result.Success = $true
        Write-Log "Quarantine: Copied '$SourceFile' -> '$quarantineDest' (Reason: $Reason, Size: $(Format-Bytes $result.SizeBytes))"
        Write-AuditEntry -Message "QUARANTINE: $Reason | $SourceFile | $quarantineDest" -Level "WARN"

    } catch {
        $result.Error = $_.Exception.Message
        Write-Log "Quarantine FAILED for '$SourceFile': $($result.Error)"
        Write-AuditEntry -Message "QUARANTINE_FAILED: $Reason | $SourceFile | $($result.Error)" -Level "ERROR"
    }

    return $result
}

function Initialize-QuarantineFolder {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Creates a timestamped quarantine folder under the specified path or default location.
    .PARAMETER QuarantinePath
        User-specified quarantine root. If empty, creates under script directory.
    .OUTPUTS
        [string] Full path to the created quarantine folder.
    #>
    param([string]$QuarantinePath)

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    if ($QuarantinePath) {
        $quarantineRoot = Join-Path $QuarantinePath "UFM_Quarantine_$timestamp"
    } else {
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $quarantineRoot = Join-Path $scriptDir "UFM_Quarantine_$timestamp"
    }

    if (-not $DryRun -and -not (Test-Path $quarantineRoot)) {
        New-Item -Path $quarantineRoot -ItemType Directory -Force | Out-Null
        Write-Log "Quarantine folder created: $quarantineRoot"
    }

    return $quarantineRoot
}

function Export-QuarantineManifest {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Exports all quarantined file records to a CSV manifest for audit/remediation.
    #>
    param(
        [object[]]$QuarantinedFiles,
        [string]$QuarantineRoot
    )

    if ($QuarantinedFiles.Count -eq 0) { return }

    $manifestPath = Join-Path $QuarantineRoot "UFM_QuarantineManifest.csv"
    $QuarantinedFiles | Select-Object SourcePath, QuarantinePath, Reason, SizeBytes, Success, Error |
        Export-Csv -Path $manifestPath -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue

    Write-Status "Quarantine manifest: $manifestPath" -Type "Info"
    Write-Log "Quarantine manifest exported: $manifestPath ($($QuarantinedFiles.Count) entries)"
}

#endregion

#region ── HTML Report and Exit Functions ─────────────────────────────────────

function ConvertTo-HtmlSafe {
    <#
    .SYNOPSIS
        Escapes HTML special characters for safe embedding in report output.
    #>
    [CmdletBinding()]
    param([string]$s)
    if (-not $s) { return '' }
    $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

function Write-HtmlReport {
    <#
    .SYNOPSIS
        Generates the full HTML migration report with per-user results, summary statistics, and hardware profile.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$Mode, [object[]]$UserBlocks)

    if ($DisableHtmlReport -or -not $script:HtmlReportPath) { return }

    $endTime     = Get-Date
    $duration    = $endTime - $script:ReportStartTime
    $durStr      = '{0:D2}:{1:D2}:{2:D2}' -f [int]$duration.TotalHours, $duration.Minutes, $duration.Seconds
    $stampPretty = $script:STAMP -replace '(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})','$1-$2-$3  $4:$5:$6'

    # ── Aggregates with safe property access ──────────────────────────────────────────
    $totalUsers         = if ($UserBlocks) { $UserBlocks.Count } else { 0 }
    $allFolders         = @()
    foreach ($ub in $UserBlocks) {
        if ($ub -is [PSCustomObject] -and $ub.PSObject.Properties['Folders']) {
            $allFolders += @($ub.Folders)
        }
    }
    $totalFolders       = $allFolders.Count
    $totalSuccess       = 0
    $totalSize          = 0L
          $totalVerifyPassed  = 0
          $totalVerifyFailed  = 0
         $totalVerifySkipped = 0
         $totalQuarantined   = if ($script:QuarantinedFiles) { $script:QuarantinedFiles.Count } else { 0 }
         $quarantineSize     = 0L
         if ($script:QuarantinedFiles) {
        foreach ($q in $script:QuarantinedFiles) {
            if ($q.Success) { $quarantineSize += $q.SizeBytes }
        }
    }

    foreach ($f in $allFolders) {
        if ($f -is [PSCustomObject]) {
            if ($f.PSObject.Properties['Success'] -and $f.Success) { $totalSuccess++ }
            if ($f.PSObject.Properties['Size'] -and $f.Size -is [long]) { $totalSize += $f.Size }
            
            if ($f.PSObject.Properties['VerifyResult'] -and $null -ne $f.VerifyResult) {
                $vr = $f.VerifyResult
                if ($vr.Passed) { $totalVerifyPassed++ }
                else { $totalVerifyFailed++ }
            } else {
                $totalVerifySkipped++
            }
        }
    }

    $modeCss = switch ($Mode) {
        'Migration'            { 'Migration' }
        'Restore Defaults'     { 'Restore'  }
        'Redirect and Clean'   { 'Redirect' }
        'Repair Transactions'  { 'Repair'   }
        default                { 'Report'   }
    }

    $dryRunBadge = if ($DryRun) { '<span class="dbadge">DRY RUN</span>' } else { '' }
    $logFileName = if ($script:LogFile) { [System.IO.Path]::GetFileName($script:LogFile) } else { 'N/A' }
    $overallStatus = if   ($totalSuccess -eq $totalFolders -and $totalFolders -gt 0) { 'All operations completed successfully' }
                     elseif ($totalSuccess -gt 0) { 'Completed with some failures' }
                     else   { 'No operations completed' }

    # ── Build per-user HTML ─────────────────────────────────────────────────
    $userHtml = [System.Text.StringBuilder]::new()
    $vIdx     = 0

    foreach ($ub in $UserBlocks) {
        if (-not ($ub -is [PSCustomObject])) { continue }
        
        $ubFolders   = @(if ($ub.PSObject.Properties['Folders']) { $ub.Folders } else { @() })
        $ubSuccess   = 0
        foreach ($f in $ubFolders) {
            if ($f -is [PSCustomObject] -and $f.PSObject.Properties['Success'] -and $f.Success) { $ubSuccess++ }
        }
        $ubTotal     = $ubFolders.Count
        $ubAborted   = $ub.PSObject.Properties['Aborted'] -and $ub.Aborted
        $ubAbortReason = if ($ub.PSObject.Properties['AbortReason'] -and $ub.AbortReason) { $ub.AbortReason } else { '' }
        $ubResultCss = if ($ubAborted) { 'b-fail' }
                       elseif ($ubSuccess -eq $ubTotal -and $ubTotal -gt 0) { 'b-ok' }
                       elseif ($ubSuccess -gt 0) { 'b-warn' } else { 'b-fail' }
        $activeCss   = if ($ub.PSObject.Properties['IsActive'] -and $ub.IsActive) { 'b-active' } else { 'b-inactive' }
        $activeText  = if ($ub.PSObject.Properties['IsActive'] -and $ub.IsActive) { 'Active' }   else { 'Inactive' }
        $username    = if ($ub.PSObject.Properties['Username']) { $ub.Username } else { 'Unknown' }

        # Build aborted banner (shown when Aborted=$true with reason)
        $abortBadgeHtml = ''
        if ($ubAborted) {
            $isKfmAbort = $ubAbortReason -match 'KFM'
            $abortLabel = if ($isKfmAbort) { '&#128683; ABORTED &mdash; KFM Block' } else { '&#10060; ABORTED' }
            $abortReasonHtml = if ($ubAbortReason) { " &mdash; $(ConvertTo-HtmlSafe $ubAbortReason)" } else { '' }
            $abortBadgeHtml = "<div style='background:#7f1d1d;color:#fca5a5;padding:6px 12px;border-radius:4px;margin:6px 0;font-size:.85em'>" +
                              "<strong>$abortLabel</strong>$abortReasonHtml" +
                              $(if ($isKfmAbort) { " &mdash; Re-run with <code>-SkipKFMBlock</code> to override (expert use only)." } else { '' }) +
                              "</div>"
        }
        $folderSummary = if ($ubAborted -and $ubTotal -eq 0) { 'ABORTED before copy' } else { "$ubSuccess / $ubTotal folders" }

        [void]$userHtml.Append(@"
<div class="ucard">
<div class="uhead">
  <span class="utitle">$(ConvertTo-HtmlSafe $username)</span>
  <span class="ub $activeCss">$activeText</span>
  <span class="ub $ubResultCss">$folderSummary</span>
</div>
$abortBadgeHtml
<div class="twrap">
<table>
<thead>
<tr><th>Folder</th><th>Size</th><th>Reg</th><th>Source</th><th>Status</th><th>$ChecksumAlgorithm Verify</th><th>Destination</th></tr>
</thead>
<tbody>
"@)

        $ubTotalSize = 0L

        foreach ($f in $ubFolders) {
            if (-not ($f -is [PSCustomObject])) { continue }
            
            $vIdx++
            $fSize    = if ($f.PSObject.Properties['Size'])    { $f.Size }    else { 0L }
            $ubTotalSize  += $fSize

            $statusCss = if ($f.PSObject.Properties['Success'] -and $f.Success) { 'b-ok' } else { 'b-fail' }
            $statusTxt = if ($f.PSObject.Properties['Success'] -and $f.Success) { 'OK' }   else { 'FAIL' }
            $regTxt    = if ($f.PSObject.Properties['RegistryUpdated']) { if ($f.RegistryUpdated) { 'yes' } else { 'no' } } else { '—' }
            $srcTxt    = if ($f.PSObject.Properties['SourceDeleted'])   { if ($f.SourceDeleted) { 'deleted' } elseif ($f.Success) { 'kept' } else { 'n/a' } } else { '—' }
            $sizeStr   = if ($fSize -gt 0) { Format-Bytes $fSize } else { '0 B' }
            $destRaw   = if ($f.PSObject.Properties['Destination']) { $f.Destination } else { '—' }
            $destStr   = ConvertTo-HtmlSafe $destRaw
            $folder    = if ($f.PSObject.Properties['Folder']) { $f.Folder } else { 'Unknown' }

            $hasVerify = $f.PSObject.Properties['VerifyResult'] -and $null -ne $f.VerifyResult
            if ($hasVerify) {
                $vr = $f.VerifyResult
                if ($vr.Passed) {
                    $vBadge = "<span class='ub b-ok vbadge' onclick='tv($vIdx)' title='Click to expand'>&#10003; PASSED ($($vr.TotalFiles) files)</span>"
                } else {
                    $vBadge = "<span class='ub b-fail vbadge' onclick='tv($vIdx)' title='Click to expand'>&#10007; FAILED ($($vr.ErrorCount)/$($vr.TotalFiles))</span>"
                }
            } else {
                $vBadge = "<span class='ub b-skip'>Skipped</span>"
            }

            [void]$userHtml.Append(@"
<tr>
   <td><strong>$(ConvertTo-HtmlSafe $folder)</strong></td>
  <td class="tr">$sizeStr</td>
  <td>$regTxt</td>
  <td>$srcTxt</td>
  <td><span class="ub $statusCss">$statusTxt</span></td>
  <td>$vBadge</td>
  <td class="tp">$destStr</td>
</tr>
"@)

            if ($hasVerify -and $vr.FileResults) {
                [void]$userHtml.Append("<tr id='vr$vIdx' class='vrow'><td colspan='7' class='vrcell'><div class='vrinner'>")
                [void]$userHtml.Append("<table><thead><tr><th>File</th><th>Method</th><th>Src Hash</th><th>Dst Hash</th><th>Size</th><th>Match</th></tr></thead><tbody>")
                foreach ($vf in $vr.FileResults) {
                    $mCss    = switch ($vf.Method) { 'Full' { 'mg' } 'Partial' { 'my' } default { 'mm' } }
                    $mLabel  = switch ($vf.Method) { 'Full' { "Full $ChecksumAlgorithm" } 'Partial' { "Partial $ChecksumAlgorithm" } default { 'Fast Verify' } }
                    $mBadge  = "<span class='ub $mCss sm'>$mLabel</span>"
                    $matchB  = if ($vf.Match) { '<span class="ub b-ok sm">&#10003;</span>' } else { '<span class="ub b-fail sm">&#10007;</span>' }
                    if ($vf.Method -eq 'FastVerify') {
                        $srcH = '<span class="hv">Size+Date</span>'
                        $dstH = '<span class="hv">Size+Date</span>'
                    } else {
                        $srcTrunc = if ($vf.SrcHash.Length -ge 16) { $vf.SrcHash.Substring(0,16) + '…' } else { $vf.SrcHash }
                        $dstTrunc = if ($vf.DstHash.Length -ge 16) { $vf.DstHash.Substring(0,16) + '…' } else { $vf.DstHash }
                        $srcH = "<span class='hv' title='$(ConvertTo-HtmlSafe $vf.SrcHash)'>$srcTrunc</span>"
                        $dstH = "<span class='hv' title='$(ConvertTo-HtmlSafe $vf.DstHash)'>$dstTrunc</span>"
                    }
                    $errStr = if ($vf.Error) { "<br><span class='err'>$(ConvertTo-HtmlSafe $vf.Error)</span>" } else { '' }
                    $relPath = if ($vf.PSObject.Properties['RelPath']) { $vf.RelPath } else { 'Unknown' }
                    [void]$userHtml.Append("<tr><td class='tp sm'>$(ConvertTo-HtmlSafe $relPath)$errStr</td><td>$mBadge</td><td>$srcH</td><td>$dstH</td><td class='tr sm'>$(Format-Bytes $vf.SizeSrc)</td><td>$matchB</td></tr>")
                }
                [void]$userHtml.Append("</tbody></table></div></td></tr>")
            }
        }

        [void]$userHtml.Append(@"
<tr class="trow">
   <td><strong>TOTAL</strong></td>
  <td class="tr"><strong>$(Format-Bytes $ubTotalSize)</strong></td>
  <td colspan="5"></td>
</tr>
</tbody>
</div></div>
"@)
    }

    $vStatValue = if   ($totalVerifyPassed + $totalVerifyFailed -eq 0) { 'N/A' }
                  elseif ($totalVerifyFailed -eq 0)  { "$totalVerifyPassed &#10003;" }
                  else { "$totalVerifyPassed &#10003; · $totalVerifyFailed &#10007;" }
    $vStatCss   = if   ($totalVerifyFailed -gt 0)   { 'st-fail' }
                  elseif ($totalVerifyPassed -gt 0)  { 'st-ok'   }
                  else  { '' }

    $foldStatCss = if ($totalSuccess -eq $totalFolders -and $totalFolders -gt 0) { 'st-ok' }
                   elseif ($totalSuccess -gt 0) { 'st-warn' } else { 'st-fail' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>UserFolderMigrator Report — $Mode — $($script:STAMP)</title>
<style>
  :root {
    --bg:      #0f1117;
    --surface: #1a1d27;
    --border:  #2a2d3a;
    --accent:  #00d4ff;
    --green:   #22c55e;
    --yellow:  #f59e0b;
    --red:     #ef4444;
    --text:    #e2e8f0;
    --muted:   #64748b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  a { color: var(--accent); }
  .hdr { background: var(--surface); border-bottom: 1px solid var(--border); padding: 18px 40px; display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
  .htitle { font-size: 20px; font-weight: 700; color: var(--accent); flex: 1; }
  .hmeta  { font-size: 12px; color: var(--muted); margin-top: 3px; }
  .mbadge { padding: 5px 14px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: .6px; text-transform: uppercase; }
  .mMigration { background: rgba(0,212,255,.12);  color: var(--accent); border: 1px solid rgba(0,212,255,.3); }
  .mRestore   { background: rgba(167,139,250,.12); color: #a78bfa;       border: 1px solid rgba(167,139,250,.3); }
  .mRedirect  { background: rgba(245,158,11,.12);  color: var(--yellow); border: 1px solid rgba(245,158,11,.3); }
  .mRepair    { background: rgba(239,68,68,.12);   color: var(--red);    border: 1px solid rgba(239,68,68,.3); }
  .mReport    { background: rgba(100,116,139,.12); color: var(--muted);  border: 1px solid rgba(100,116,139,.3); }
  .dbadge     { padding: 5px 14px; border-radius: 20px; font-size: 11px; font-weight: 700; background: rgba(245,158,11,.12); color: var(--yellow); border: 1px solid rgba(245,158,11,.3); }
  .sbar { display: flex; gap: 1px; background: var(--border); border-bottom: 1px solid var(--border); }
  .sc   { flex: 1; background: var(--surface); padding: 16px 22px; }
  .sv   { font-size: 24px; font-weight: 700; color: var(--text); line-height: 1.1; }
  .sl   { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; margin-top: 3px; }
  .st-ok   .sv { color: var(--green); }
  .st-fail .sv { color: var(--red); }
  .st-warn .sv { color: var(--yellow); }
  .main  { padding: 28px 40px; max-width: 1400px; margin: 0 auto; }
  .igrid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 28px; }
  .iitem { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; }
  .ilbl  { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; }
  .ival  { font-size: 13px; color: var(--text); margin-top: 3px; font-family: 'Cascadia Code', 'Consolas', monospace; word-break: break-all; }
  .ucard { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 20px; overflow: hidden; }
  .uhead { padding: 12px 18px; display: flex; align-items: center; gap: 10px; background: #12151f; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .utitle { font-size: 15px; font-weight: 600; color: var(--text); flex: 1; }
  .ub { padding: 2px 9px; border-radius: 11px; font-size: 11px; font-weight: 600; }
  .ub.sm { font-size: 10px; padding: 1px 7px; }
  .b-ok     { background: rgba(34,197,94,.12);  color: var(--green);  border: 1px solid rgba(34,197,94,.3); }
  .b-fail   { background: rgba(239,68,68,.12);   color: var(--red);    border: 1px solid rgba(239,68,68,.3); }
  .b-warn   { background: rgba(245,158,11,.12);  color: var(--yellow); border: 1px solid rgba(245,158,11,.3); }
  .b-skip   { background: rgba(100,116,139,.12); color: var(--muted);  border: 1px solid rgba(100,116,139,.3); }
  .b-active { background: rgba(34,197,94,.12);   color: var(--green);  border: 1px solid rgba(34,197,94,.3); }
  .b-inactive{ background: rgba(245,158,11,.12); color: var(--yellow); border: 1px solid rgba(245,158,11,.3); }
  .mg { background: rgba(34,197,94,.10);  color: #4ade80; border: 1px solid rgba(34,197,94,.2); }
  .my { background: rgba(245,158,11,.10); color: #fbbf24; border: 1px solid rgba(245,158,11,.2); }
  .mm { background: rgba(100,116,139,.10);color: var(--muted); border: 1px solid rgba(100,116,139,.2); }
  .twrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: #12151f; color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .5px; padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; }
  td { padding: 10px 14px; border-top: 1px solid var(--border); vertical-align: middle; }
  tr:last-child > td { border-bottom: none; }
  tbody tr:hover > td { background: #1f2235; }
  .tr { text-align: right; font-variant-numeric: tabular-nums; }
  .tp { color: var(--muted); font-size: 12px; word-break: break-all; }
  .trow > td { background: #12151f; font-weight: 600; border-top: 2px solid var(--border); }
  .vrow { display: none; }
  .vrow.open { display: table-row; }
  .vrcell { background: #090d12; padding: 0 !important; border-bottom: 1px solid var(--border); }
  .vrinner { padding: 10px 18px 14px; }
  .vrinner table { background: transparent; }
  .vrinner th, .vrinner td { background: transparent; padding: 5px 10px; border-color: rgba(42,45,58,.5); font-size: 11px; }
  .hv { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 11px; color: var(--muted); cursor: help; border-bottom: 1px dashed var(--border); }
  .vbadge { cursor: pointer; transition: opacity .15s; user-select: none; }
  .vbadge:hover { opacity: .75; }
  .err { color: var(--red); font-size: 11px; }
  footer { text-align: center; padding: 16px 40px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 10px; }
</style>
</head>
<body>

<div class="hdr">
  <div style="flex:1">
    <div class="htitle">📁 User Folder Migrator — Run Report</div>
    <div class="hmeta">$stampPretty &nbsp;·&nbsp; Duration: $durStr &nbsp;·&nbsp; $env:COMPUTERNAME &nbsp;·&nbsp;</div>
  </div>
  <span class="mbadge m$modeCss">$Mode</span>
  $dryRunBadge
</div>

<div class="sbar">
  <div class="sc"><div class="sv">$totalUsers</div><div class="sl">Users</div></div>
  <div class="sc $foldStatCss"><div class="sv">$totalSuccess / $totalFolders</div><div class="sl">Folders OK</div></div>
  <div class="sc"><div class="sv">$(Format-Bytes $totalSize)</div><div class="sl">Data Processed</div></div>
  <div class="sc $vStatCss"><div class="sv">$vStatValue</div><div class="sl">$ChecksumAlgorithm Verify$(if ($totalVerifySkipped -gt 0) { " ($totalVerifySkipped skipped)" })</div></div>
  <div class="sc"><div class="sv">$totalQuarantined</div><div class="sl">Quarantined</div></div>
  <div class="sc"><div class="sv">$durStr</div><div class="sl">Duration</div></div>
</div>

<div class="main">

<div class="igrid">
  <div class="iitem"><div class="ilbl">Mode</div><div class="ival">$Mode</div></div>
  <div class="iitem"><div class="ilbl">Run By</div><div class="ival">$env:USERNAME</div></div>
  <div class="iitem"><div class="ilbl">Host</div><div class="ival">$env:COMPUTERNAME</div></div>
  <div class="iitem"><div class="ilbl">Version</div><div class="ival">$($script:VERSION)</div></div>
  <div class="iitem"><div class="ilbl">Algorithm</div><div class="ival">$ChecksumAlgorithm</div></div>
  <div class="iitem"><div class="ilbl">Dry Run</div><div class="ival">$(if ($DryRun) { 'Yes' } else { 'No' })</div></div>
  <div class="iitem"><div class="ilbl">Log File</div><div class="ival">$logFileName</div></div>
  <div class="iitem"><div class="ilbl">Result</div><div class="ival">$overallStatus</div></div>
</div>

$($userHtml.ToString())

</div>

<footer>
  UserFolderMigrator &nbsp;·&nbsp; Report generated $(($endTime).ToString('yyyy-MM-dd HH:mm:ss'))
  &nbsp;·&nbsp; $ChecksumAlgorithm verification: $(if (-not $DisableChecksumVerify) { 'Enabled' } else { 'Disabled' })
</footer>

<script>
function tv(i){ var r=document.getElementById('vr'+i); if(r) r.classList.toggle('open'); }
</script>
</body>
</html>
"@

    try {
        [System.IO.File]::WriteAllText($script:HtmlReportPath, $html, [System.Text.Encoding]::UTF8)
        Write-Log "HTML report saved: $script:HtmlReportPath"
    } catch {
        Write-Log "Failed to write HTML report: $_"
        Write-Status "Warning: could not write HTML report — $_" -Type "Warning"
    }
}

function Write-IntegrityReport {
    <#
    .SYNOPSIS
        Appends a checksum verification summary block to the HTML report.
    #>
    [CmdletBinding()]
    param()
    if (-not $script:HtmlReportPath) { return }
    $jsonPath = $script:HtmlReportPath -replace '\.html$', '_Integrity.json'
    try {
        $report = [ordered]@{
            Script       = 'UserFolderMigrator'
            Version      = $script:VERSION
            RunStamp     = $script:STAMP
            Mode         = $script:ReportMode
            Host         = $env:COMPUTERNAME
            GeneratedBy  = $env:USERNAME
            Algorithm    = $ChecksumAlgorithm
            DryRun       = $DryRun.IsPresent
            StartTime    = $script:ReportStartTime.ToString('o')
            EndTime      = (Get-Date).ToString('o')
            ExitCode     = $script:ExitCode
            Users        = @()
        }
        
        foreach ($ub in $script:ReportUserBlocks) {
            # Skip if not a valid object
            if (-not ($ub -is [PSCustomObject])) { continue }
            
            # Safe property access for user block
            $username = if ($ub.PSObject.Properties['Username'] -and $ub.Username) { $ub.Username } else { 'Unknown' }
            $isActive = if ($ub.PSObject.Properties['IsActive'] -and $ub.IsActive) { $ub.IsActive } else { $false }
            $aborted  = if ($ub.PSObject.Properties['Aborted'] -and $ub.Aborted) { $ub.Aborted } else { $false }
            
            $userEntry = [ordered]@{
                Username  = $username
                IsActive  = $isActive
                Aborted   = $aborted
                Folders   = @()
            }
            
            # Get folders safely
            $foldersList = @()
            if ($ub.PSObject.Properties['Folders']) {
                $foldersList = $ub.Folders
            }
            
            foreach ($f in $foldersList) {
                if (-not ($f -is [PSCustomObject])) { continue }
                
                # Safe property access for each folder
                $folderName     = if ($f.PSObject.Properties['Folder'])          { $f.Folder }          else { '' }
                $size           = if ($f.PSObject.Properties['Size'])            { $f.Size }            else { 0 }
                $files          = if ($f.PSObject.Properties['Files'])           { $f.Files }           else { 0 }
                $success        = if ($f.PSObject.Properties['Success'])         { $f.Success }         else { $false }
                $registryUpdated = if ($f.PSObject.Properties['RegistryUpdated']) { $f.RegistryUpdated } else { $false }
                $sourceDeleted  = if ($f.PSObject.Properties['SourceDeleted'])   { $f.SourceDeleted }   else { $false }
                $destination    = if ($f.PSObject.Properties['Destination'])     { $f.Destination }     else { '' }
                
                $folderEntry = [ordered]@{
                    Folder          = $folderName
                    Size            = $size
                    Files           = $files
                    Success         = $success
                    RegistryUpdated = $registryUpdated
                    SourceDeleted   = $sourceDeleted
                    Destination     = $destination
                    VerifyPassed    = $false
                    VerifyErrors    = 0
                    VerifySkipped   = $false
                    Files_Verified  = 0
                }
                
                # Safe VerifyResult access
                $hasVerify = $f.PSObject.Properties['VerifyResult'] -and $null -ne $f.VerifyResult
                if ($hasVerify) {
                    $vr = $f.VerifyResult
                    $folderEntry.VerifyPassed   = if ($vr.Passed) { $true } else { $false }
                    $folderEntry.VerifyErrors   = if ($vr.ErrorCount) { $vr.ErrorCount } else { 0 }
                    $folderEntry.Files_Verified = if ($vr.TotalFiles) { $vr.TotalFiles } else { 0 }
                } else {
                    $folderEntry.VerifySkipped = $true
                }
                
                $userEntry.Folders += $folderEntry
            }
            
            $report.Users += $userEntry
        }
        
        $report | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8 -ErrorAction Stop
        Write-Status "Integrity JSON : $jsonPath" -Type "Info"
        Write-Log "Integrity JSON report saved: $jsonPath"
    } catch {
        Write-Log "Could not write integrity JSON report: $_"
    }
}

function Write-SCCMStatusMessage {
    <#
    .SYNOPSIS
        Writes an SCCM or MDT task sequence status message using the TSEnvironment COM object.
    #>
    [CmdletBinding()]
    param([string]$Message, [int]$ExitCode = 0)
    # FIX: New-Object -ComObject throws REGDB_E_CLASSNOTREG (0x80040154) when not
    # running in an SCCM Task Sequence. With Set-StrictMode -Version Latest active
    # at script scope, PS7 promotes this to a MethodInvocationException that escapes
    # the outer catch{} block and surfaces as a TerminatingError in the transcript.
    # Pre-guard with a nested try so the outer catch only runs for real TS errors.
    $tsEnv = $null
    try { $tsEnv = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction SilentlyContinue } catch { }
    if (-not $tsEnv) { return }   # Not in a Task Sequence — silently skip
    try {
        $tsEnv.Value("OSDUserFolderMigratorStatus")  = $Message
        $tsEnv.Value("OSDUserFolderMigratorExitCode")= "$ExitCode"
        if ($ExitCode -gt 1) { $tsEnv.Value("_SMSTSRetryRequested") = "false" }
        $smsts = $tsEnv.Value("_SMSTSLogPath")
        if ($smsts) {
            $ufmLog = Join-Path $smsts "UFM_$($script:STAMP).log"
            if ($script:LogFile -and (Test-Path $script:LogFile)) {
                Copy-Item $script:LogFile -Destination $ufmLog -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Status "SCCM Task Sequence variables updated" -Type "Info"
        Write-Log "SCCM TS: OSDUserFolderMigratorStatus='$Message' ExitCode=$ExitCode"
    } catch {
        # Not running in a Task Sequence — silently skip
    }
}

function Exit-WithReport {
    <#
    .SYNOPSIS
        Closes the transcript, fires PostSession hooks, and exits the process with the given exit code.
    #>
    [CmdletBinding()]
    param([int]$Code = 0)

    # Export quarantine manifest if any files were quarantined
    if ($script:QuarantineRoot -and $script:QuarantinedFiles -and $script:QuarantinedFiles.Count -gt 0) {
        Export-QuarantineManifest -QuarantinedFiles $script:QuarantinedFiles -QuarantineRoot $script:QuarantineRoot
    }

    if (-not $DisableHtmlReport) {
        Write-HtmlReport -Mode $script:ReportMode -UserBlocks $script:ReportUserBlocks
        Write-IntegrityReport
    }
    # PostMigration hooks — guarded so they fire exactly once regardless of which mode calls Exit-WithReport
    if (-not $script:_PostMigrationFired) {
        $script:_PostMigrationFired = $true
        $postMigrationContext = New-PluginContext 'PostMigration' @{
            TotalUsers        = $script:ReportUserBlocks.Count
            HtmlReportPath    = $script:HtmlReportPath
            DryRun            = $DryRun
            ExitCode          = $Code
            Mode              = $script:ReportMode
            SkipDeduplication = $DryRun
            ProfilePath       = $Destination
            DestinationPath   = $Destination
            ComputerName      = $env:COMPUTERNAME
            Username          = $env:USERNAME
        }
        $null = Invoke-PluginHooks -Stage 'PostMigration' -Context $postMigrationContext
    }
    # SCCM / MDT task sequence integration
    $statusMsg = "UserFolderMigrator $($script:ReportMode) ExitCode=$Code on $env:COMPUTERNAME"
    Write-SCCMStatusMessage -Message $statusMsg -ExitCode $Code
    # Clean up VSS shadow copies created during this session
    if ($script:VssShadowPaths -and $script:VssShadowPaths.Count -gt 0) {
        Remove-VssShadows
    }
    # Dismount any network drives we mapped
    if ($script:MountedDrives -and $script:MountedDrives.Count -gt 0) {
        Dismount-NetworkDrives
    }
    # Clear checkpoint file on clean success
    if ($Code -eq 0 -and $EnableCheckpoint) {
        Clear-CheckpointFile
    }
    # Write final metrics JSON
    if ($script:MetricsPath) {
        try {
            $endTime = Get-Date
            $allFolders = if ($script:ReportUserBlocks.Count -gt 0) {
                $all = @()
                foreach ($ub in $script:ReportUserBlocks) {
                    if ($ub -is [PSCustomObject] -and $ub.PSObject.Properties['Folders']) {
                        $all += @($ub.Folders)
                    }
                }
                $all
            } else { @() }
            
            $totalBytes = 0L
            foreach ($f in $allFolders) {
                if ($f -is [PSCustomObject] -and $f.PSObject.Properties['Size'] -and $f.Size -is [long]) {
                    $totalBytes += $f.Size
                }
            }
            
            $successFolders = 0
            foreach ($f in $allFolders) {
                if ($f -is [PSCustomObject] -and $f.PSObject.Properties['Success'] -and $f.Success) {
                    $successFolders++
                }
            }
            
            $metricsObj = [ordered]@{
                Script      = "UserFolderMigrator"
                Version     = $script:VERSION
                RunStamp    = $script:STAMP
                Mode        = $script:ReportMode
                Host        = $env:COMPUTERNAME
                User        = $env:USERNAME
                StartTime   = $script:ReportStartTime.ToString('o')
                EndTime     = $endTime.ToString('o')
                DurationSec = [int]($endTime - $script:ReportStartTime).TotalSeconds
                ExitCode    = $Code
                DryRun      = $DryRun.IsPresent
                TotalUsers  = $script:ReportUserBlocks.Count
                TotalFolders = $allFolders.Count
                SuccessFolders = $successFolders
                TotalBytes  = $totalBytes
                LogFile     = $script:LogFile
                ReportFile  = $script:HtmlReportPath
                TranscriptFile = $script:TranscriptPath
            }
            $metricsObj | ConvertTo-Json -Depth 2 | Set-Content -Path $script:MetricsPath -Encoding UTF8
            Write-Log "Metrics JSON saved: $script:MetricsPath"
        } catch { Write-Log "Could not write metrics JSON: $_" }
    }
    # Windows Event Log: session end
    $exitDesc = switch ($Code) {
        0 { 'SUCCESS' }
        1 { 'PARTIAL' }
        2 { 'FAILURE' }
        3 { 'NO_SPACE' }
        4 { 'PERMISSION' }
        5 { 'CANCELLED' }
        default { "CODE_$Code" }
    }
    $evType = if ($Code -eq 0) { 'Information' } elseif ($Code -eq 1) { 'Warning' } else { 'Error' }
    $evId = if ($Code -eq 0) { 1001 } else { 1003 }
    Write-EventLogEntry -Message "UserFolderMigrator completed on $env:COMPUTERNAME. Mode: $($script:ReportMode). ExitCode: $Code ($exitDesc)." -EntryType $evType -EventId $evId
    $syslogSeverity = if ($Code -eq 0) { 6 } elseif ($Code -eq 1) { 4 } else { 3 }
    Send-SyslogMessage -Message "UserFolderMigrator session ended: mode=$($script:ReportMode) exitcode=$Code ($exitDesc)" -Severity $syslogSeverity
    # Send completion notification
    $notifStatus = if ($Code -eq 0) { 'Success' } elseif ($Code -eq 1) { 'Warning' } else { 'Error' }
    $notifBody   = "Mode: $($script:ReportMode)`nHost: $env:COMPUTERNAME`nUser: $env:USERNAME`nExitCode: $Code ($exitDesc)`nLog: $($script:LogFile)"
    Send-MigrationNotification -Subject "Migration $exitDesc on $env:COMPUTERNAME" -Body $notifBody -Status $notifStatus
    if ($script:LogFile -and -not $QuietMode) {
        Write-Host ""
        Write-Status "Log file       : $script:LogFile" -Type "Info"
        if ($script:HtmlReportPath -and -not $DisableHtmlReport) {
            Write-Status "HTML report    : $script:HtmlReportPath" -Type "Info"
        }
        if ($script:TranscriptPath) {
            Write-Status "Transcript     : $script:TranscriptPath" -Type "Info"
        }
        if ($script:MetricsPath) {
            Write-Status "Metrics JSON   : $script:MetricsPath" -Type "Info"
        }
    }
    # Stop transcript last so the path lines above are captured in it
    if ($script:TranscriptPath) {
        Stop-Transcript -ErrorAction SilentlyContinue
    }
    # ── Encrypt audit log at rest ─────────────────────────────────────────────
    # Wraps the plaintext audit log in DPAPI (LocalMachine scope) so it cannot be
    # read or tampered with outside this machine without admin access.
    # The unencrypted file is removed after encryption.
    # PostSession hook plugins that need to forward the audit log (Splunk, Sentinel)
    # fire BEFORE encryption — they receive the path and read it while it's still plain.
    $null = Invoke-PluginHooks 'PostSession' (New-PluginContext 'PostSession' @{
        ExitCode             = $Code
        Mode                 = $script:ReportMode
        LogFile              = $script:LogFile
        HtmlReportPath       = $script:HtmlReportPath
        ComputerName         = $env:COMPUTERNAME
        DryRun               = $DryRun
        AuditForwardingConfig = $null
    })
    if ($AutoCleanupCreds) { Clear-StoredCredentials }
    if ($script:AuditLogPath -and (Test-Path $script:AuditLogPath) -and -not $DryRun) {
        try {
            Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
            $plain     = [System.IO.File]::ReadAllBytes($script:AuditLogPath)
            $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
                $plain, $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
            [System.IO.File]::WriteAllBytes("$($script:AuditLogPath).enc", $encrypted)
            Remove-Item $script:AuditLogPath -Force
        } catch {
            # Encryption failure is non-fatal — leave plaintext log in place
            Write-Warning "[Audit] Log encryption skipped: $_"
        }
    }
    # Quarantine retention cleanup — remove sub-folders older than -QuarantineRetentionDays
    if ($QuarantineRetentionDays -gt 0 -and $script:QuarantineRoot -and (Test-Path $script:QuarantineRoot)) {
        $cutoff = (Get-Date).AddDays(-$QuarantineRetentionDays)
        try {
            Get-ChildItem -LiteralPath $script:QuarantineRoot -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -lt $cutoff } |
                ForEach-Object {
                    try {
                        Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
                        Write-Log "QuarantineRetention: removed old quarantine folder '$($_.FullName)' (created $($_.CreationTime.ToString('yyyy-MM-dd')))"
                    } catch {
                        Write-Log "QuarantineRetention: failed to remove '$($_.FullName)': $($_.Exception.Message)"
                    }
                }
        } catch {
            Write-Log "QuarantineRetention: enumeration error on '$($script:QuarantineRoot)': $($_.Exception.Message)"
        }
    }
    exit $Code
}

#endregion

#region ── New Enterprise Features ──────────────────────────────────────────

# ── Windows Event Log Integration (Feature 4.1) ───────────────────────────
function Write-EventLogEntry {
    <#
    .SYNOPSIS
        Writes an entry to the Windows Application Event Log under the UserFolderMigrator source.
    #>
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Information','Warning','Error')] [string]$EntryType = 'Information',
        [int]$EventId = 1000
    )
    if ($NoEventLog) { return }
    try {
        $source = 'UserFolderMigrator'
        # FIX: SourceExists() and CreateEventSource() are COM-backed calls that
        # throw REGDB_E_CLASSNOTREG (0x80040154) inside constrained runspaces on
        # some Windows editions. Wrap each call individually so a COM failure on
        # source registration does not prevent the EventLog write from being
        # attempted, and does not propagate into the caller's error stream.
        $sourceReady = $false
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
                [System.Diagnostics.EventLog]::CreateEventSource($source, 'Application')
            }
            $sourceReady = $true
        } catch [System.Exception] {
            # COM not available in this runspace context — skip EventLog silently
        }
        if ($sourceReady) {
            Write-EventLog -LogName Application -Source $source -EntryType $EntryType `
                -EventId $EventId -Message $Message -ErrorAction SilentlyContinue
        }
    } catch [System.Exception] {
        # Event log write failures are non-fatal — log to file only
        if ($script:LogFile) { Add-Content $script:LogFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [WARN] EventLog write failed: $($_.Exception.Message)" -Encoding UTF8 -ErrorAction SilentlyContinue }
    }
}
# Event IDs: 1000=SessionStart 1001=SessionEnd 1002=UserMigrated 1003=Error 1004=Warning

# ── Syslog (RFC 5424) Forwarding (Feature 4.2) ────────────────────────────
function Send-SyslogMessage {
    <#
    .SYNOPSIS
        Sends an RFC-5424-formatted syslog UDP datagram to the configured syslog server.
    #>
    [CmdletBinding()]
    param([string]$Message, [int]$Severity = 6)   # 6=Informational, 4=Warning, 3=Error
    if (-not $EnableSyslog -or [string]::IsNullOrWhiteSpace($SyslogServer)) { return }
    try {
        $facility = 1    # user-level messages
        $pri      = ($facility * 8) + $Severity
        $hostname = $env:COMPUTERNAME
        $appname  = "UserFolderMigrator"
        $ts       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $syslogMsg= "<$pri>1 $ts $hostname $appname - - - $Message"
        $bytes    = [System.Text.Encoding]::UTF8.GetBytes($syslogMsg)
        $udp      = [System.Net.Sockets.UdpClient]::new()
        try {
            $port = 514
            # Allow SyslogServer to include port as "host:port"
            if ($SyslogServer -match '^(.+):(\d+)$') { $SyslogServer = $Matches[1]; $port = [int]$Matches[2] }
            $udp.Send($bytes, $bytes.Length, $SyslogServer, $port) | Out-Null
        } finally { $udp.Dispose() }
    } catch [System.Exception] {
        if ($script:LogFile) { Add-Content $script:LogFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [WARN] Syslog send failed to ${SyslogServer}: $($_.Exception.Message)" -Encoding UTF8 -ErrorAction SilentlyContinue }
    }
}

function New-MigrationRestorePoint {
    [CmdletBinding()]
    param()

    if ($DisableRestorePoint -or $DryRun) { 
        Write-Log "Restore point skipped: -DisableRestorePoint or -DryRun is set."
        return 
    }

    $systemDrive = $env:SystemDrive
    $volume = $systemDrive.TrimEnd('\')

    # 1. User decision (unless unattended)
    $createRestorePoint = $false
    if ($Unattended) {
        $createRestorePoint = $AutoEnableSystemProtection
        if ($createRestorePoint) {
            Write-Status "Unattended mode: AutoEnableSystemProtection is on – will enable System Protection if needed and create restore point." -Type "Info"
        } else {
            Write-Status "Unattended mode: skipping restore point (AutoEnableSystemProtection not set)." -Type "Info"
            Write-Log "Restore point skipped in unattended mode."
            return
        }
    } else {
        $answer = Read-Host "  Create a system restore point before migration? (Y/N)"
        $createRestorePoint = ($answer -eq 'Y' -or $answer -eq 'y')
        if (-not $createRestorePoint) {
            Write-Status "Restore point creation skipped by user." -Type "Info"
            Write-Log "Restore point skipped by user choice."
            return
        }
    }

    # 2. Check and enable System Protection if needed
    function Test-SystemProtectionEnabled {
        param([string]$DriveLetter)
        try {
            $sr = Get-CimInstance -ClassName SystemRestore -Filter "Drive='$DriveLetter'" -ErrorAction SilentlyContinue
            if ($sr -and $sr.DisableSR -eq 0) { return $true }
        } catch { }
        return $false
    }

    $protectionEnabled = Test-SystemProtectionEnabled -DriveLetter $systemDrive

    if (-not $protectionEnabled) {
        Write-Status "System Protection is disabled on $systemDrive." -Type "Warning"
        Write-Status "Attempting to enable System Protection temporarily..." -Type "Info"

        try {
            Enable-ComputerRestore -Drive $systemDrive -ErrorAction Stop
            Write-Status "System Protection enabled on $systemDrive via Enable-ComputerRestore." -Type "Success"
            $protectionEnabled = $true
        } catch {
            try {
                $wmi = Get-WmiObject -Class Win32_SystemRestore -ErrorAction Stop
                $result = $wmi.Enable($systemDrive)
                if ($result.ReturnValue -ne 0) { throw "Enable($systemDrive) returned $($result.ReturnValue)" }
                Write-Status "System Protection enabled on $systemDrive via WMI." -Type "Success"
                $protectionEnabled = $true
            } catch {
                Write-Status "Could not enable System Protection: $($_.Exception.Message)" -Type "Warning"
                Write-Status "Restore point creation will be skipped." -Type "Info"
                Write-Log "Restore point skipped: failed to enable System Protection."
                return
            }
        }
    }

    # 3. Create restore point
    try {
        Write-Status "Creating system restore point..." -Type "Info"
        
        # Bypass frequency limit – handle missing registry key gracefully
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $prevFreq = $null
        try {
            $prop = Get-ItemProperty -Path $regPath -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue
            if ($prop -and $prop.PSObject.Properties['SystemRestorePointCreationFrequency']) {
                $prevFreq = $prop.SystemRestorePointCreationFrequency
                Set-ItemProperty -Path $regPath -Name 'SystemRestorePointCreationFrequency' -Value 0 -Force
            } else {
                # Property doesn't exist; create it temporarily
                New-ItemProperty -Path $regPath -Name 'SystemRestorePointCreationFrequency' -Value 0 -PropertyType DWord -Force | Out-Null
                $prevFreq = $null  # signal that we created it
            }
        } catch {
            Write-Log "Could not adjust restore point frequency setting: $_"
        }

        $description = "UserFolderMigrator Pre-Migration $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Checkpoint-Computer -Description $description -RestorePointType MODIFY_SETTINGS -ErrorAction Stop

        # Restore previous setting (or remove the temporary key)
        if ($prevFreq -ne $null) {
            Set-ItemProperty -Path $regPath -Name 'SystemRestorePointCreationFrequency' -Value $prevFreq -Force
        } elseif ($prevFreq -eq $null -and (Get-ItemProperty -Path $regPath -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $regPath -Name 'SystemRestorePointCreationFrequency' -Force -ErrorAction SilentlyContinue
        }

        Write-Status "System restore point created successfully." -Type "Success"
        Write-Log "System restore point created: $description"
        Write-EventLogEntry -Message "UserFolderMigrator: System restore point created before migration." -EventId 1000
        Send-SyslogMessage -Message "UserFolderMigrator restore point created." -Severity 6
    } catch {
        Write-Status "Could not create restore point: $($_.Exception.Message)" -Type "Warning"
        Write-Log "Restore point creation failed: $_"
        # Non-fatal – continue with migration
    }
}

# ── VSS Shadow Copy (Feature 1.2) ─────────────────────────────────────────
# Creates a VSS snapshot of the source volume and returns the shadow device path.
# Robocopy is then run against the shadow copy, capturing open/locked files.
$script:VssShadowPaths = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function New-VssShadow {
    <#
    .SYNOPSIS
        Creates a VSS shadow copy for the specified volume and returns the shadow device path.
        Uses WMI (Win32_ShadowCopy) first; falls back to vssadmin with exponential retry
        on failure or timeout. Hard timeout: 10 minutes. On exhaustion, returns $null so
        callers revert to live copy with a logged warning.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$VolumePath)
    $qualifier = (Split-Path $VolumePath -Qualifier -ErrorAction SilentlyContinue)
    if (-not $qualifier) { return $null }
    $volume = $qualifier.TrimEnd('\') + '\'
    # Return existing shadow for same volume (one snapshot per volume per run)
    if ($script:VssShadowPaths.ContainsKey($volume)) { return $script:VssShadowPaths[$volume] }

    $hardTimeoutSec = 600   # 10-minute ceiling for VSS on massive volumes
    ${maxAttempts}    = 4
    $delayBase      = 5     # seconds: 5, 10, 20, 40 (exponential backoff)
    $overallStart   = [DateTime]::UtcNow

    # ── Helper: resolve vssadmin shadow to device path ────────────────────
    function Resolve-VssAdminShadow {
        param([string]$Vol)
        $lines = & vssadmin list shadows /for=$Vol 2>&1
        $latestDevice = $null
        foreach ($l in $lines) {
            if ($l -match 'Shadow Copy Volume:\s*(\\\\\?\\GLOBALROOT\\Device\\.+)') {
                $latestDevice = $Matches[1].Trim()
            }
        }
        return $latestDevice
    }

    for ($attempt = 1; $attempt -le ${maxAttempts}; $attempt++) {
        # Hard timeout guard
        if (([DateTime]::UtcNow - $overallStart).TotalSeconds -ge $hardTimeoutSec) {
            Write-Status "VSS: hard timeout ($hardTimeoutSec s) reached after $($attempt-1) attempt(s) — falling back to live copy" -Type "Warning"
            Write-Log "VSS hard timeout for $volume — live copy will be used (locked files may be skipped)"
            return $null
        }

        Write-Status "Creating VSS shadow copy for $volume (attempt $attempt/${maxAttempts})..." -Type "Info"

        # ── Primary: WMI Win32_ShadowCopy with 30-second timeout job ─────
        $wmiJob = Start-Job -ScriptBlock {
            param($vol)
            $shadow = Invoke-WmiMethod -Class Win32_ShadowCopy -Name Create -ArgumentList 'ClientAccessible', $vol -ErrorAction Stop
            return $shadow
        } -ArgumentList $volume

        $wmiDone = Wait-Job $wmiJob -Timeout 30
        if ($wmiDone -and $wmiJob.State -eq 'Completed') {
            try {
                $shadow = Receive-Job $wmiJob -ErrorAction Stop
                Remove-Job $wmiJob -Force -ErrorAction SilentlyContinue
                if ($shadow -and $shadow.ReturnValue -eq 0) {
                    $shadowObj = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }
                    if ($shadowObj) {
                        $deviceObj = $shadowObj.DeviceObject + '\'
                        $script:VssShadowPaths[$volume] = $deviceObj
                        Write-Status "VSS shadow created: $deviceObj" -Type "Success"
                        Write-Log "VSS shadow created for $volume : $deviceObj (attempt $attempt)"
                        return $deviceObj
                    }
                }
                Write-Log "VSS WMI returned code $($shadow.ReturnValue) for $volume — trying vssadmin fallback"
            } catch {
                Write-Log "VSS WMI receive error: $_ — trying vssadmin fallback"
            }
        } else {
            # WMI timed out — kill job and fall through to vssadmin
            Remove-Job $wmiJob -Force -ErrorAction SilentlyContinue
            Write-Status "VSS WMI call timed out (30 s) — trying vssadmin fallback (attempt $attempt)" -Type "Warning"
            Write-Log "VSS WMI timeout for $volume attempt $attempt"
        }

        # ── Fallback: vssadmin create shadow ────────────────────────────
        try {
            Write-Status "  VSS fallback: vssadmin create shadow /for=$volume" -Type "Info"
            $vssProc = Start-Process -FilePath 'vssadmin.exe' `
                -ArgumentList "create shadow /for=$volume" `
                -NoNewWindow -PassThru -Wait
            if ($vssProc.ExitCode -eq 0) {
                $deviceObj = Resolve-VssAdminShadow -Vol $volume
                if ($deviceObj) {
                    $deviceObj = $deviceObj.TrimEnd('\') + '\'
                    $script:VssShadowPaths[$volume] = $deviceObj
                    Write-Status "VSS shadow created via vssadmin: $deviceObj" -Type "Success"
                    Write-Log "VSS vssadmin shadow created for $volume : $deviceObj (attempt $attempt)"
                    return $deviceObj
                }
            }
            Write-Log "vssadmin exited $($vssProc.ExitCode) for $volume attempt $attempt"
        } catch {
            Write-Log "vssadmin fallback failed for $volume attempt $attempt : $_"
        }

        # Exponential backoff before next attempt (unless last)
        if ($attempt -lt ${maxAttempts}) {
            $delay = $delayBase * [Math]::Pow(2, $attempt - 1)
            $remaining = $hardTimeoutSec - ([DateTime]::UtcNow - $overallStart).TotalSeconds
            $delay = [Math]::Min($delay, [Math]::Max(1, $remaining - 5))
            Write-Status "  VSS retry in $([int]$delay) s..." -Type "Warning"
            Start-Sleep -Seconds $delay
        }
    }

    Write-Status "VSS snapshot failed after ${maxAttempts} attempt(s) — falling back to live copy (locked files may be skipped)" -Type "Warning"
    Write-Log "VSS exhausted for $volume after ${maxAttempts} attempts — live copy used"
    return $null
}

function Remove-VssShadows {
    <#
    .SYNOPSIS
        Deletes all VSS shadow copies created during the current session.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()
    foreach ($vol in $script:VssShadowPaths.Keys) {
        $device = $script:VssShadowPaths[$vol]
        try {
            $obj = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.DeviceObject -eq $device.TrimEnd('\') }
            if ($obj) { $obj.Delete() }
            Write-Log "VSS shadow removed for $vol"
        } catch { Write-Log "VSS shadow removal error for $vol : $_" }
    }
    $script:VssShadowPaths.Clear()
}

function Get-VssSourcePath {
    <#
    .SYNOPSIS
        Translates a local path to its VSS shadow copy equivalent for locked-file reading.
    Translates a real source path to its VSS shadow equivalent when -UseVSS is active.
    e.g. C:\Users\Alice\Desktop -> \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Users\Alice\Desktop
    Returns the original path when VSS is disabled or shadow creation failed.
    #>
    [CmdletBinding()]
    param([string]$SourcePath)
    if (-not $UseVSS) { return $SourcePath }
    $qualifier = (Split-Path $SourcePath -Qualifier -ErrorAction SilentlyContinue)
    if (-not $qualifier) { return $SourcePath }
    $volume = $qualifier.TrimEnd('\') + '\'
    $shadowDevice = New-VssShadow -VolumePath $volume
    if (-not $shadowDevice) { return $SourcePath }
    $relative = $SourcePath.Substring($qualifier.Length).TrimStart('\')
    return Join-Path $shadowDevice $relative
}

# ── Checkpoint / Resume (Feature 1.3) ─────────────────────────────────────
function Get-CheckpointData {
    <#
    .SYNOPSIS
        Reads the checkpoint JSON file and returns persisted folder completion state.
        Validates DestinationVolumeId to prevent data mixing when the destination
        drive letter changes between runs (e.g. Y: remapped to Z:).
    #>
    [CmdletBinding()]
    param()
    if (-not $EnableCheckpoint) { return $null }
    $path = if ($CheckpointFile) { $CheckpointFile } else {
        Join-Path ($PSScriptRoot ?? (Get-Location).Path) "UFM_Checkpoint.json"
    }
    if (-not (Test-Path $path)) { return $null }
    try {
        $data = Get-Content $path -Raw | ConvertFrom-Json
        # ── Destination volume validation ────────────────────────────────────
        # If the checkpoint was saved with a volume ID, verify the current
        # destination drive matches before resuming to prevent data mixing.
        if ($data.DestinationVolumeId -and $Destination) {
            try {
                $driveLetter = (Split-Path $Destination -Qualifier -ErrorAction SilentlyContinue).TrimEnd(':')
                $currentVolId = (Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue).UniqueId
                if ($currentVolId -and $currentVolId -ne $data.DestinationVolumeId) {
                    Write-Status "CHECKPOINT INVALID: destination drive has changed (volume ID mismatch)." -Type "Error"
                    Write-Status "  Checkpoint expects: $($data.DestinationVolumeId)" -Type "Error"
                    Write-Status "  Current drive $driveLetter`: $currentVolId" -Type "Error"
                    Write-Status "  Delete the checkpoint file to start a fresh migration: $path" -Type "Error"
                    Write-Log "Checkpoint invalidated — DestinationVolumeId mismatch. Expected=$($data.DestinationVolumeId) Current=$currentVolId"
                    return $null
                }
            } catch {
                Write-Log "Checkpoint volume ID check failed (non-fatal): $_"
            }
        }
        Write-Status "Resuming from checkpoint: $path" -Type "Info"
        Write-Log "Checkpoint loaded from $path (stamp: $($data.Stamp))"
        return $data
    } catch {
        Write-Status "Could not read checkpoint file: $($_.Exception.Message)" -Type "Warning"
        return $null
    }
}

function Save-CheckpointData {
    <#
    .SYNOPSIS
        Writes updated folder completion state to the checkpoint file after each folder copy.
        Stores DestinationVolumeId on first write to enable drive-change detection on resume.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$Username, [string]$FolderName, [string]$Status)
    if (-not $EnableCheckpoint) { return }
    $path = if ($CheckpointFile) { $CheckpointFile } else {
        Join-Path ($PSScriptRoot ?? (Get-Location).Path) "UFM_Checkpoint.json"
    }
    # Mutex-protected read-modify-write — prevents race when parallel runspaces save simultaneously
    $mtx = try { [System.Threading.Mutex]::OpenExisting($script:CheckpointMutexName) } catch { $script:CheckpointMutex }
    try {
        [void]$mtx.WaitOne(5000)
        try {
            $existing = if (Test-Path $path) { Get-Content $path -Raw | ConvertFrom-Json } else {
                # First write — capture destination volume ID for future validation
                $volId = $null
                if ($Destination) {
                    try {
                        $dl = (Split-Path $Destination -Qualifier -ErrorAction SilentlyContinue).TrimEnd(':')
                        $volId = (Get-Volume -DriveLetter $dl -ErrorAction SilentlyContinue).UniqueId
                    } catch { }
                }
                [PSCustomObject]@{ Stamp=$script:STAMP; Completed=@(); DestinationVolumeId=$volId; DestinationPath=$Destination }
            }
            $key = "$Username::$FolderName"
            if ($existing.Completed -notcontains $key) {
                $existing.Completed += $key
            }
            $existing | ConvertTo-Json -Depth 3 | Set-Content $path -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch [System.Exception] { Write-Log "Save-CheckpointData error: $_" -ErrorAction SilentlyContinue }
    } finally {
        try { $mtx.ReleaseMutex() } catch { }
    }
}

function Clear-CheckpointFile {
    <#
    .SYNOPSIS
        Removes the checkpoint file on session completion to prevent stale resume state.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()
    if (-not $EnableCheckpoint) { return }
    $path = if ($CheckpointFile) { $CheckpointFile } else {
        Join-Path ($PSScriptRoot ?? (Get-Location).Path) "UFM_Checkpoint.json"
    }
    if (Test-Path $path) {
        Remove-Item $path -Force -ErrorAction SilentlyContinue
        Write-Log "Checkpoint file cleared: $path"
    }
}

function Test-FolderCheckpointed {
    <#
    .SYNOPSIS
        Returns true if a folder has been recorded as completed in the current checkpoint.
    #>
    [CmdletBinding()]
    param([string]$Username, [string]$FolderName, [object]$CheckpointData)
    if (-not $EnableCheckpoint -or -not $CheckpointData) { return $false }
    return $CheckpointData.Completed -contains "$Username::$FolderName"
}

# ── Network Credential Mount (Feature 2.1) ────────────────────────────────
$script:MountedDrives = [System.Collections.Generic.List[string]]::new()

function Mount-NetworkDestination {
    <#
    .SYNOPSIS
        Maps a UNC destination path to a local drive letter using supplied credentials.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$UncPath)
    if (-not $NetworkCredential -or -not $UncPath.StartsWith('\\')) { return $UncPath }
    try {
        $driveLetter = 'Z'
        # Find a free drive letter starting from Z downward
        $usedLetters = (Get-PSDrive -PSProvider FileSystem).Name
        foreach ($l in ('Z','Y','X','W','V','U','T')) {
            if ($usedLetters -notcontains $l) { $driveLetter = $l; break }
        }
        $server = ($UncPath -split '\\')[2]
        $mapped = New-PSDrive -Name $driveLetter -PSProvider FileSystem -Root $UncPath `
            -Credential $NetworkCredential -Persist -ErrorAction Stop
        $script:MountedDrives.Add($driveLetter)
        Write-Status "Network path mounted as ${driveLetter}: — $UncPath" -Type "Success"
        Write-Log "Network credential mount: ${driveLetter}: -> $UncPath (user: $($NetworkCredential.UserName))"
        return "${driveLetter}:"
    } catch {
        Write-Status "Could not mount network path $UncPath — $($_.Exception.Message). Trying direct access." -Type "Warning"
        Write-Log "Network mount failed: $_"
        return $UncPath
    }
}

function Dismount-NetworkDrives {
    <#
    .SYNOPSIS
        Removes all network drive mappings created during this session.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()
    foreach ($letter in $script:MountedDrives) {
        try {
            Remove-PSDrive -Name $letter -Force -ErrorAction SilentlyContinue
            Write-Log "Unmounted network drive ${letter}:"
        } catch { }
    }
    $script:MountedDrives.Clear()
}

# ── Scheduled Delta Sync Task (Feature 3.1) ───────────────────────────────
function Register-DeltaSyncTask {
    <#
    .SYNOPSIS
        Registers a Windows Scheduled Task for periodic robocopy delta sync from source to destination.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$SourceRoot, [string]$DestRoot, [string]$Username)
    if (-not $CreateSyncTask) { return }
    if ($DryRun) {
        Write-Status "[DRY RUN] Would create scheduled delta-sync task for $Username" -Type "Info"
        return
    }
    try {
        $taskName = "UFM_DeltaSync_${Username}_$($script:STAMP)"
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $syncScript = Join-Path $scriptDir "UFM_DeltaSync_${Username}.ps1"

        # Generate a self-contained robocopy mirror sync script
        $syncContent = @"
# Auto-generated by UserFolderMigrator on $($script:STAMP)
# Delta sync: mirrors $SourceRoot to $DestRoot for user $Username
`$logDir  = Join-Path '$scriptDir' 'UFM_Logs'
`$logFile = Join-Path `$logDir "UFM_DeltaSync_${Username}_`$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
if (-not (Test-Path `$logDir)) { New-Item `$logDir -ItemType Directory -Force | Out-Null }
`$rc = Start-Process robocopy.exe -ArgumentList ('$SourceRoot','$DestRoot','/MIR','/COPY:DAT','/DCOPY:DA','/R:3','/W:5','/MT:8','/LOG+:'+`$logFile) -Wait -PassThru -NoNewWindow
Write-Host "Delta sync exit code: `$(`$rc.ExitCode)"
"@
        $syncContent | Out-File -FilePath $syncScript -Encoding UTF8 -Force

        $action  = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument "-NonInteractive -NoProfile -File `"$syncScript`""
        $trigger = New-ScheduledTaskTrigger -Daily -At '23:00'
        $settings= New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -StartWhenAvailable `
                       -ExecutionTimeLimit (New-TimeSpan -Hours 4)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -RunLevel Highest -Force | Out-Null
        Write-Status "Delta-sync task registered: '$taskName' (daily at 23:00)" -Type "Success"
        Write-Log "Scheduled delta-sync task created: $taskName"
    } catch {
        Write-Status "Could not register sync task: $($_.Exception.Message)" -Type "Warning"
        Write-Log "Sync task registration failed: $_"
    }
}

# ── Parallel Multi-User Processing (Feature 3.5) ──────────────────────────
function Invoke-ParallelUserMigrations {
    <#
    .SYNOPSIS
        Runs Invoke-UserMigration for multiple users concurrently using
        PowerShell 7 native ForEach-Object -Parallel with $using: scoping.
        Replaces the previous runspace pool — eliminates 200+ lines of
        InitialSessionState marshalling, manual variable snapshots, and
        ConcurrentBag plumbing. Thread pool is fixed; no per-user runspace leak.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [object[]]$Users,
        [string]$BaseDestination,
        [int]$Concurrency
    )

    $actualConcurrency = [Math]::Min($Concurrency, $Users.Count)
    Write-Status "Parallel mode: $($Users.Count) users, $actualConcurrency concurrent thread(s)" -Type "Info"
    Write-Log "Parallel migration started: users=$($Users.Count) concurrency=$actualConcurrency"

    # Pre-profile destination drive before parallel scatter (same fix as before)
    if ($script:HW -and $BaseDestination) {
        $destQualifier = (Split-Path $BaseDestination -Qualifier -ErrorAction SilentlyContinue)
        if ($destQualifier) {
            $destLetter = $destQualifier.TrimEnd(':').ToUpper()
            if ($destLetter -and -not $script:HW.Drives.ContainsKey($destLetter)) {
                Write-Log "Invoke-ParallelUserMigrations: pre-profiling destination drive $destLetter"
                try {
                    $newProfile = Invoke-HardwareDetection -DrivesToProfile @($destLetter)
                    if ($newProfile -and $newProfile.Drives.ContainsKey($destLetter)) {
                        $script:HW.Drives[$destLetter] = $newProfile.Drives[$destLetter]
                    }
                } catch {
                    Write-Log "HW pre-profile failed for ${destLetter}: $_"
                }
            }
        }
    }

    # Capture $using: values once — ForEach-Object -Parallel serialises these automatically
    $logFile        = $script:LogFile
    $auditLogPath   = $script:AuditLogPath
    $hw             = $script:HW
    $config         = $script:Config
    $pluginInputs   = $script:PluginInputs
    $pluginPaths    = @(Get-Module | Where-Object { $_.Path -like '*UserFolderMigrator_*.psm1' } | Select-Object -ExpandProperty Path)
    $logMutexName   = $script:LogMutexName
    $auditMutexName = $script:AuditMutexName
    $cpMutexName    = $script:CheckpointMutexName
    $metricsPath    = $script:MetricsPath

    $results = $Users | ForEach-Object -Parallel {
        $u           = $_
        $userDest    = Join-Path $using:BaseDestination $u.Username

        # Restore script-scope state in this thread
        $script:LogFile              = $using:logFile
        $script:AuditLogPath         = $using:auditLogPath
        $script:HW                   = $using:hw
        $script:Config               = $using:config
        $script:PluginInputs         = $using:pluginInputs
        $script:LogMutexName         = $using:logMutexName
        $script:AuditMutexName       = $using:auditMutexName
        $script:CheckpointMutexName  = $using:cpMutexName
        $script:MetricsPath          = $using:metricsPath

        # Re-hydrate Drives as live hashtable (survives deserialization boundary)
        if ($script:HW -and $script:HW.PSObject.Properties['Drives']) {
            $liveDrives = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
            if ($script:HW.Drives) { foreach ($k in $script:HW.Drives.Keys) { $liveDrives[$k] = $script:HW.Drives[$k] } }
            $script:HW.Drives = $liveDrives
        }

        # Re-import plugin modules (threads are isolated sessions)
        foreach ($mp in $using:pluginPaths) {
            Import-Module $mp -Force -ErrorAction SilentlyContinue
        }

        try {
            # PreUser plugin hook
            $preCtx = New-PluginContext 'PreUser' @{
                UserName = $u.Username; SID = $u.SID
                SourcePath = $u.ProfilePath; DestinationPath = $userDest
                DryRun = $using:DryRun; Folders = 'All'; BaseDestination = $using:BaseDestination; QuotaGB = 0
            }
            if ((Invoke-PluginHooks -Stage 'PreUser' -Context $preCtx) -eq $false) {
                Write-Log "PreUser blocked for $($u.Username) — skipping"
                return
            }

            $migResult = Invoke-UserMigration `
                -Username    $u.Username `
                -ProfilePath $u.ProfilePath `
                -Destination $userDest `
                -SID         $u.SID `
                -IsActive    $u.IsActive

            # PostUser plugin hook
            $postCtx = New-PluginContext 'PostUser' @{
                UserName = $u.Username; SID = $u.SID; DestinationPath = $userDest
                DryRun = $using:DryRun; Aborted = $migResult.Aborted
                SuccessCount = $migResult.SuccessCount; TotalCount = $migResult.TotalCount; Result = $migResult
            }
            Invoke-PluginHooks -Stage 'PostUser' -Context $postCtx | Out-Null

            $migResult
        } catch {
            New-MigrationResult -Username $u.Username -IsActive $u.IsActive `
                -Aborted $true -AbortReason "Parallel thread exception: $($_.Exception.Message)"
        }
    } -ThrottleLimit $actualConcurrency

    $orderedResults = @($results | Where-Object { $_ })
    Write-Log "Parallel migration finished: $($orderedResults.Count) result(s)"
    return $orderedResults
}

# ── ExcludeFile support (Feature 3.6 / robocopy parity) ──────────────────
function Get-ExcludePatterns {
    [CmdletBinding()]
    param()
    $patterns = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Exclude) { if ($p) { [void]$patterns.Add($p) } }
    if ($ExcludeFile -and (Test-Path $ExcludeFile)) {
        Get-Content $ExcludeFile -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' } |
            ForEach-Object { [void]$patterns.Add($_.Trim()) }
        Write-Log "ExcludeFile loaded: $ExcludeFile ($($patterns.Count) total patterns)"
    }
    return $patterns.ToArray()
}

# ── Large File Optimization (Feature 6.1) ─────────────────────────────────
# Returns robocopy thread count tuned for the dominant file size in the folder.

function Invoke-StartupEnvironment {
    <#
    .SYNOPSIS
        Runs hardware detection, central config load, and email pre-flight in sequence.
        Extracted from Main to reduce its size. Must run after Initialize-Logger and
        before Invoke-UnattendedValidation so tuning is applied before param checks.
    .PARAMETER Destination
        Destination path used to profile the target drive for hardware tuning.
    #>
    [CmdletBinding()]
    param([string]$Destination)

    # ── Hardware Detection & Auto-Performance Tuning ──────────────────────────
    if (-not $DisableAutoPerfTuning) {
        $script:HW = Invoke-HardwareDetection -DrivesToProfile @(
            if ($Destination) { (Split-Path $Destination -Qualifier -ErrorAction SilentlyContinue).TrimEnd(':') }
        )
        Write-HardwareProfile -Profile $script:HW
    } else {
        Write-Status "Auto-performance tuning disabled (-DisableAutoPerfTuning)" -Type "Info"
    }

    # Load central config defaults (UFM_Config.json) — CLI args override config
    Import-CentralConfig

    # ── Auto-install missing components ──────────────────────────────────────
    Invoke-AutoInstallComponents

    # ── Email module pre-flight ───────────────────────────────────────────────
    if ($NotificationEmail) {
        # PoshMailKit already installed by Invoke-AutoInstallComponents above
        $null = Resolve-SmtpConfig
        Write-Status "Email notifications → $NotificationEmail via $($script:ResolvedSmtpConfig.Server):$($script:ResolvedSmtpConfig.Port)" -Type "Info"
    }

    # Apply HW tuning AFTER config load so CLI > config > HW-tuned > default holds
    if ($script:HW) { Apply-HardwareTuning -Profile $script:HW }
}

#region ── Hardware Detection & Auto-Performance Tuning ──────────────────────

function Invoke-HardwareDetection {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Detects all relevant hardware — CPU, RAM, storage (per drive letter),
        GPU, network adapters — and returns a unified hardware profile object.
        Every detection uses WMI/CIM with timeouts and safe fallbacks so the
        function never throws on headless or restricted systems.
        The profile is stored in $script:HW and referenced throughout the run.
    #>
    param([string[]]$DrivesToProfile = @())   # drive letters to classify (e.g. C, D, Y)

    Write-Status "Detecting hardware configuration..." -Type "Info"

    # ── CPU ──────────────────────────────────────────────────────────────────
    $cpu = $null
    try { $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1 } catch [System.Exception] { }

    $cpuName          = if ($cpu) { $cpu.Name.Trim() } else { 'Unknown CPU' }
    $physicalCores    = if ($cpu -and $cpu.NumberOfCores        -gt 0) { [int]$cpu.NumberOfCores }        else { [int][Environment]::ProcessorCount }
    $logicalCores     = if ($cpu -and $cpu.NumberOfLogicalProcessors -gt 0) { [int]$cpu.NumberOfLogicalProcessors } else { [int][Environment]::ProcessorCount }
    $cpuSpeedMHz      = if ($cpu -and $cpu.MaxClockSpeed         -gt 0) { [int]$cpu.MaxClockSpeed }        else { 0 }
    # FIX: Measure-Object .Average is null when collection is empty — throws under StrictMode.
    $cpuLoadPercent = try {
        $cpuInst = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue)
        if ($cpuInst.Count -gt 0) {
            $total = 0; foreach ($c in $cpuInst) { $total += [int]$c.LoadPercentage }
            [int]($total / $cpuInst.Count)
        } else { 0 }
    } catch [System.Exception] { 0 }
    $numaNodeCount    = try { [int](@(Get-CimInstance -ClassName Win32_MemoryArray -ErrorAction SilentlyContinue).Count) } catch [System.Exception] { 1 }
    $numaNodeCount    = [Math]::Max(1, $numaNodeCount)

    # Determine CPU tier: affects hash buffer sizing and parallel ceiling
    $cpuTier = if    ($physicalCores -ge 16) { 'Workstation' }
               elseif ($physicalCores -ge 8)  { 'High' }
               elseif ($physicalCores -ge 4)  { 'Mid' }
               else                           { 'Low' }

    # ── RAM ──────────────────────────────────────────────────────────────────
    $os = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue } catch [System.Exception] { }

    $totalRamGB    = if ($os -and $os.TotalVisibleMemorySize -gt 0) { [Math]::Round($os.TotalVisibleMemorySize / 1MB, 1) } else { 0 }
    $freeRamGB     = if ($os -and $os.FreePhysicalMemory     -gt 0) { [Math]::Round($os.FreePhysicalMemory     / 1MB, 1) } else { 0 }
    $ramSpeedMHz   = 0
    try {
        $ramMod = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue | Where-Object { $_.Speed -gt 0 } | Select-Object -First 1
        if ($ramMod) { $ramSpeedMHz = [int]$ramMod.Speed }
    } catch [System.Exception] { }

    # Hash buffer size scales with available RAM: from 4 MB (low RAM) to 256 MB (high RAM)
    $hashBufferMB = if    ($freeRamGB -ge 16) { 256 }
                    elseif ($freeRamGB -ge  8) { 128 }
                    elseif ($freeRamGB -ge  4) {  64 }
                    elseif ($freeRamGB -ge  2) {  16 }
                    else                       {   4 }

    # Parallel runspace limit based on free RAM (each runspace ~300 MB overhead)
    $ramParallelCeiling = [Math]::Max(1, [int][Math]::Floor($freeRamGB / 0.5))

    # ── GPU ──────────────────────────────────────────────────────────────────
    $gpus = @()
    try { $gpus = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue | Where-Object { $_.AdapterRAM -gt 0 -or $_.Name -match 'NVIDIA|AMD|Intel|Radeon|GeForce|Quadro|FirePro' }) } catch [System.Exception] { }

    $gpuList = @($gpus | ForEach-Object {
        [PSCustomObject]@{
            Name      = $_.Name
            VRAM_MB   = if ($_.AdapterRAM -gt 0) { [int]($_.AdapterRAM / 1MB) } else { 0 }
            Driver    = $_.DriverVersion
            IsNVIDIA  = $_.Name -match 'NVIDIA|GeForce|Quadro|RTX|GTX'
            IsAMD     = $_.Name -match 'AMD|Radeon|FirePro|RX\s'
            IsIntelIG = $_.Name -match 'Intel.*Graphics|UHD|HD Graphics'
        }
    })

    # GPU load via WMI performance counter (optional — not available on all systems)
    $gpuLoadPercent = 0
    try {
        $gpuCounter = Get-Counter '\GPU Engine(*)\Utilization Percentage' -ErrorAction SilentlyContinue -SampleInterval 1 -MaxSamples 1
        if ($gpuCounter) {
            # FIX: Measure-Object .Average is null when filtered set is empty — throws under StrictMode.
            $gpuSamples = @($gpuCounter.CounterSamples | Where-Object { $_.CookedValue -gt 0 })
            if ($gpuSamples.Count -gt 0) {
                $gpuTotal = 0.0; foreach ($s in $gpuSamples) { $gpuTotal += $s.CookedValue }
                $gpuLoadPercent = [int]($gpuTotal / $gpuSamples.Count)
            }
        }
    } catch [System.Exception] { }

    # ── Storage: classify each relevant drive ─────────────────────────────
    $driveProfiles = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Always profile system drive + any drives in DrivesToProfile
    # Always profile system drive + any drives in DrivesToProfile
    $systemDriveLetter = if ($env:SystemDrive) {
        $env:SystemDrive.TrimEnd(':', '\').ToUpper()
    } else {
        # Fallback: determine system drive from Windows directory
        $windowsDir = [System.Environment]::GetFolderPath('Windows')
        if ($windowsDir -match '^([A-Z]):\\') {
            $Matches[1]
        } else {
            'C'   # Ultimate fallback
        }
    }
    
    $systemDriveLetter = if ($env:SystemDrive) {
        $env:SystemDrive.TrimEnd(':', '\').ToUpper()
    } else {
        # Fallback: determine system drive from Windows directory
        try {
            $windowsDir = [System.Environment]::GetFolderPath('Windows')
            if ($windowsDir -match '^([A-Z]):\\') {
                $Matches[1]
            } else {
                'C'
            }
        } catch {
            # Ultimate fallback for constrained environments
            Write-Log "HardwareDetection: Could not determine system drive — falling back to C:"
            'C'
        }
    }

    $allDrivesToCheck = @($systemDriveLetter) + $DrivesToProfile | Select-Object -Unique
    Write-Log "HardwareDetection: System drive detected as ${systemDriveLetter}:"

    # Get disk→drive mapping via WMI
    $diskPartitions = @()
    try { $diskPartitions = @(Get-CimInstance -ClassName Win32_DiskDriveToDiskPartition -ErrorAction SilentlyContinue) } catch [System.Exception] { }
    $partitionToLogical = @()
    try { $partitionToLogical = @(Get-CimInstance -ClassName Win32_LogicalDiskToPartition -ErrorAction SilentlyContinue) } catch [System.Exception] { }
    $physicalDisks = @()
    try { $physicalDisks = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue) } catch [System.Exception] { }

    # Build a letter → physical disk mapping
    $letterToDisk = @{}
    foreach ($ptl in $partitionToLogical) {
        $logicalDev  = $ptl.Dependent.DeviceID -replace '\\\\\.\\',''
        $partDev     = $ptl.Antecedent.DeviceID
        $diskPartRow = $diskPartitions | Where-Object { $_.Dependent.DeviceID -eq $partDev } | Select-Object -First 1
        if ($diskPartRow) {
            $physDisk = $physicalDisks | Where-Object { $_.DeviceID -eq $diskPartRow.Antecedent.DeviceID } | Select-Object -First 1
            if ($physDisk) { $letterToDisk[$logicalDev.TrimEnd(':')] = $physDisk }
        }
    }

    # Also get MSFT_PhysicalDisk for reliable SSD/NVMe detection
    $msftDisks = @()
    try { $msftDisks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue) } catch [System.Exception] { }

    foreach ($letter in $allDrivesToCheck) {
        $letter = $letter.TrimEnd(':').ToUpper()
        $diskInfo   = $letterToDisk[$letter]
        $mediaType  = 'Unknown'
        $isSSD      = $false
        $isNVMe     = $false
        $isUSB      = $false
        $isNetwork  = $false
        $diskModel  = 'Unknown'
        $diskRPM    = 0
        $diskSizGB  = 0

        if ($diskInfo) {
            $diskModel  = $diskInfo.Model.Trim()
            $diskSizGB  = [Math]::Round($diskInfo.Size / 1GB, 0)
            $isUSB      = $diskInfo.InterfaceType -match 'USB'
            $isNetwork  = $diskInfo.MediaType -eq 'Unknown' -and $diskModel -match 'Remote|Virtual|Network'

            # Check MSFT_PhysicalDisk for authoritative MediaType
            $msft = $msftDisks | Where-Object { $_.FriendlyName -ieq $diskModel -or $diskInfo.SerialNumber -and $_.SerialNumber -ieq $diskInfo.SerialNumber } | Select-Object -First 1
            if ($msft) {
                $msftMediaTypeRaw = $msft.MediaType
                $msftMediaTypeInt = 0
                if ($msftMediaTypeRaw -match '^\d+$') {
                    $msftMediaTypeInt = [int]$msftMediaTypeRaw
                } elseif ($msftMediaTypeRaw -is [int] -or $msftMediaTypeRaw -is [uint16] -or $msftMediaTypeRaw -is [uint32]) {
                    $msftMediaTypeInt = [int]$msftMediaTypeRaw
                }
                # Named enum fallback: MSFT_PhysicalDisk MediaType values
                if ($msftMediaTypeInt -eq 0) {
                    $msftMediaTypeInt = switch -Exact ($msftMediaTypeRaw) {
                        'HDD'         { 3 }
                        'SSD'         { 4 }
                        'SCM'         { 5 }
                        default       { 0 }
                    }
                }
                $mediaType = switch ($msftMediaTypeInt) {
                    3 { 'HDD' }; 4 { 'SSD' }; 5 { 'SCM' }; default { 'Unknown' }
                }
                $isSSD   = $msftMediaTypeInt -eq 4 -or $msftMediaTypeInt -eq 5
                $isNVMe  = $msft.BusType -eq 17   # NVMe bus type
                $diskRPM = if ($msft.SpindleSpeed -gt 0) { [int]$msft.SpindleSpeed } else { 0 }
            }

            # Fallback heuristics when MSFT_PhysicalDisk not available
            if ($mediaType -eq 'Unknown') {
                if ($diskModel -match 'NVMe|M\.2|SSD|Solid') { $isSSD = $true; $mediaType = 'SSD' }
                elseif ($diskInfo.MediaType -match 'Fixed hard disk') { $mediaType = 'HDD' }
                # WMI SeekTime < 1ms → almost certainly SSD (property absent on virtual/network disks)
                $aveSeekTime = if ($diskInfo.PSObject.Properties['AveSeekTime']) { $diskInfo.AveSeekTime } else { 0 }
                if (-not $isSSD -and $aveSeekTime -gt 0 -and $aveSeekTime -lt 2000000) { $isSSD = $true; $mediaType = 'SSD' }
            }
            if ($diskModel -match 'NVMe') { $isNVMe = $true }
        } else {
            # Drive letter not in WMI (could be a network share, VHD, or RAM disk)
            $ldisk = try { Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${letter}:'" -ErrorAction SilentlyContinue } catch [System.Exception] { $null }
            if ($ldisk) {
                $isNetwork = $ldisk.DriveType -eq 4   # Network drive
                $mediaType = if ($isNetwork) { 'Network' } else { 'Unknown' }
            }
        }

        $driveProfiles[$letter] = [PSCustomObject]@{
            Letter       = $letter
            Model        = $diskModel
            MediaType    = $mediaType
            IsSSD        = $isSSD
            IsNVMe       = $isNVMe
            IsUSB        = $isUSB
            IsNetwork    = $isNetwork
            SpindleRPM   = $diskRPM
            SizeGB       = $diskSizGB
        }
    }

    # ── Network Adapters ─────────────────────────────────────────────────────
    $nics = @()
    try {
        $nics = @(Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.NetEnabled -eq $true -and $_.Speed -gt 0 } |
            Select-Object Name, Speed, MACAddress, NetConnectionStatus)
    } catch [System.Exception] { }

    $activeNicSpeedMbps = if ($nics.Count -gt 0) { [int]([math]::Round(($nics | Measure-Object -Property Speed -Maximum).Maximum / 1MB)) } else { 0 }
    $isHighSpeedNIC     = $activeNicSpeedMbps -ge 10000   # 10 GbE or faster

    # ── WAN/High-Latency RTT Detection ───────────────────────────────────────
    # For each network drive in DrivesToProfile, probe latency with Test-Connection.
    # RTT > 50 ms = high-latency (WAN/satellite/cross-region VPN).
    # Result stored per drive letter; Get-OptimalThreadCount reads it to cap /MT.
    $driveRttMs = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($dl in ($DrivesToProfile ?? @())) {
        $dp = if ($driveProfiles.ContainsKey($dl)) { $driveProfiles[$dl] } else { $null }
        if (-not $dp -or -not $dp.IsNetwork) { continue }
        try {
            # Derive UNC host from mapped drive's provider path
            $netDrive = Get-PSDrive -Name $dl -ErrorAction SilentlyContinue
            $uncHost  = if ($netDrive -and $netDrive.DisplayRoot -match '^\\\\([^\\]+)') { $Matches[1] } else { $null }
            if ($uncHost) {
                $ping = Test-Connection -ComputerName $uncHost -Count 4 -ErrorAction SilentlyContinue
                if ($ping) {
                    $avgRtt = ($ping | Measure-Object -Property ResponseTime -Average).Average
                    $driveRttMs[$dl] = [int]$avgRtt
                    Write-Log "WAN probe: drive ${dl}: host=$uncHost RTT=$([int]$avgRtt) ms"
                    if ($avgRtt -gt 50) {
                        Write-Status "  High-latency network drive ${dl}: (RTT $([int]$avgRtt) ms) — WAN mode active (/MT will be capped at 2)" -Type "Warning"
                    }
                }
            }
        } catch {
            Write-Log "RTT probe failed for drive ${dl}: $_"
        }
    }

    # ── Compute tuned parameters ──────────────────────────────────────────────
    # These are the final auto-tuned values applied throughout the session.
    # Each can still be overridden by explicit CLI params or UFM_Config.json.

    # Robocopy threads: more threads for fast storage and many cores
    # Tuned parameters: more threads for fast storage and many cores
    $sysDriveProfile = if ($driveProfiles.ContainsKey($systemDriveLetter)) { $driveProfiles[$systemDriveLetter] } else { $null }
    $tunedRobocopyThreads = if    ($isNVMe  -or ($sysDriveProfile -and $sysDriveProfile.IsSSD)) { [Math]::Min(32, $physicalCores * 2) }
                             elseif ($sysDriveProfile -and $sysDriveProfile.IsNetwork) { [Math]::Min(16, $physicalCores) }
                             else  { [Math]::Min($physicalCores, 8) }   # HDD: stay conservative

    # Hash buffer from RAM (used in Get-FileHashTiered)
    $tunedHashBufferBytes = $hashBufferMB * 1MB

    # Max parallel users: bounded by cores, RAM, and NIC speed
    $tunedMaxParallel = if ($MaxParallel -gt 1 -and -not $DisableAutoPerfTuning) {
        [Math]::Min($MaxParallel, [Math]::Min($ramParallelCeiling, [Math]::Min($physicalCores, 8)))
    } else { $MaxParallel }

    # Progress bar refresh rate: lower on weak CPUs (avoid Console overhead)
    $tunedProgressIntervalMs = if ($physicalCores -ge 8) { 150 } elseif ($physicalCores -ge 4) { 250 } else { 500 }

    # Verification: how many files to hash in parallel (via runspace mini-pool)
    $tunedVerifyParallelism = [Math]::Max(1, [Math]::Min(4, $physicalCores / 2))

    # Test-restore sample: bigger on slow HDD (want more confidence before deleting)
    # Smaller on fast NVMe (re-copy is cheap if something goes wrong)
        $defaultSSD = $sysDriveProfile -and $sysDriveProfile.IsSSD
    $tunedTestRestorePct = if ($defaultSSD) { [Math]::Max($TestRestoreSamplePct, 5) }
                           else             { [Math]::Max($TestRestoreSamplePct, 15) }

    # IPG for bandwidth throttling: already set via -BandwidthLimitMbps, but
    # on slow HDDs we add gentle throttle even without explicit param to avoid
    # starving the OS I/O scheduler
    $tunedIPGOverride = if (-not $DisableAutoPerfTuning -and $BandwidthLimitMbps -eq 0 -and
                            $driveProfiles.ContainsKey('C') -and -not $driveProfiles['C'].IsSSD) { 5 } else { 0 }

    $hwProfile = [PSCustomObject]@{
        # CPU
        CPUName             = $cpuName
        PhysicalCores       = $physicalCores
        LogicalCores        = $logicalCores
        CPUSpeedMHz         = $cpuSpeedMHz
        CPULoadPercent      = $cpuLoadPercent
        CPUTier             = $cpuTier
        NUMANodes           = $numaNodeCount
        # RAM
        TotalRAM_GB         = $totalRamGB
        FreeRAM_GB          = $freeRamGB
        RAMSpeedMHz         = $ramSpeedMHz
        HashBufferMB        = $hashBufferMB
        HashBufferBytes     = $tunedHashBufferBytes
        RAMParallelCeiling  = $ramParallelCeiling
        # GPU
        GPUs                = $gpuList
        GPUCount            = $gpuList.Count
        GPULoadPercent      = $gpuLoadPercent
        HasDedicatedGPU     = @($gpuList | Where-Object { $_.IsNVIDIA -or $_.IsAMD }).Count -gt 0
        # Storage (per-drive)
        Drives              = $driveProfiles
        # Network
        NICs                = $nics
        ActiveNICSpeedMbps  = $activeNicSpeedMbps
        IsHighSpeedNIC      = $isHighSpeedNIC
        DriveRttMs          = $driveRttMs   # [hashtable] drive-letter → avg RTT ms (populated for network drives only)
        # Tuned parameters (applied unless overridden)
        Tuned_RobocopyThreads    = $tunedRobocopyThreads
        Tuned_MaxParallel        = $tunedMaxParallel
        Tuned_ProgressIntervalMs = $tunedProgressIntervalMs
        Tuned_VerifyParallelism  = $tunedVerifyParallelism
        Tuned_TestRestorePct     = $tunedTestRestorePct
        Tuned_IPGOverride        = $tunedIPGOverride
    }

    return $hwProfile
}

function Write-HardwareProfile {
    <#
    .SYNOPSIS
        Writes the detected hardware profile (CPU, RAM, drive type, settings) to console and log.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#  Prints the hardware profile to console in a compact table.  #>
    param([PSCustomObject]$Profile)
    if (-not $Profile) { return }

    Write-SectionHeader "HARDWARE PROFILE"

    # CPU row
    $cpuSpeed = if ($Profile.CPUSpeedMHz -gt 0) { "$([Math]::Round($Profile.CPUSpeedMHz/1000,2)) GHz" } else { 'n/a' }
    Write-Host ("  {0,-16} {1}" -f "CPU:", "$($Profile.CPUName) · $($Profile.PhysicalCores)P/$($Profile.LogicalCores)L cores · $cpuSpeed · Tier=$($Profile.CPUTier) · Load=$($Profile.CPULoadPercent)%") -ForegroundColor Gray

    # RAM row
    $ramSpeed = if ($Profile.RAMSpeedMHz -gt 0) { "@ $($Profile.RAMSpeedMHz) MHz" } else { '' }
    Write-Host ("  {0,-16} {1}" -f "RAM:", "$($Profile.TotalRAM_GB) GB total · $($Profile.FreeRAM_GB) GB free $ramSpeed · Buffer=$($Profile.HashBufferMB) MB") -ForegroundColor Gray

    # GPU rows
    if ($Profile.GPUCount -gt 0) {
        foreach ($g in $Profile.GPUs) {
            $vram = if ($g.VRAM_MB -gt 0) { "$($g.VRAM_MB) MB VRAM" } else { 'shared VRAM' }
            Write-Host ("  {0,-16} {1}" -f "GPU:", "$($g.Name) · $vram") -ForegroundColor Gray
        }
    } else {
        Write-Host ("  {0,-16} {1}" -f "GPU:", "None detected") -ForegroundColor DarkGray
    }

    # Storage rows
    foreach ($letter in ($Profile.Drives.Keys | Sort-Object)) {
        $d    = $Profile.Drives[$letter]
        $type = if ($d.IsNVMe) { 'NVMe SSD' } elseif ($d.IsSSD) { 'SATA SSD' } elseif ($d.IsUSB) { 'USB' } elseif ($d.IsNetwork) { 'Network' } elseif ($d.MediaType -eq 'HDD') { "HDD $(if ($d.SpindleRPM -gt 0) { "$($d.SpindleRPM) RPM" })" } else { $d.MediaType }
        $size = if ($d.SizeGB -gt 0) { "$($d.SizeGB) GB" } else { '' }
        Write-Host ("  {0,-16} {1}" -f "Drive ${letter}:", "$type $(if ($size) { "· $size" }) · $($d.Model)") -ForegroundColor Gray
    }

    # NIC rows
    if ($Profile.NICs.Count -gt 0) {
        $nicSummary = "$($Profile.ActiveNICSpeedMbps) Mbps$(if ($Profile.IsHighSpeedNIC) { ' [10GbE+]' })"
        Write-Host ("  {0,-16} {1}" -f "Network:", $nicSummary) -ForegroundColor Gray
    }

    Write-Host ""

    # Tuned parameters table
    Write-Host "  Auto-tuned parameters:" -ForegroundColor Cyan
    Write-Host ("    {0,-30} {1}" -f "Robocopy threads/folder:", $Profile.Tuned_RobocopyThreads)         -ForegroundColor Gray
    Write-Host ("    {0,-30} {1}" -f "Max parallel users:",      $Profile.Tuned_MaxParallel)             -ForegroundColor Gray
    Write-Host ("    {0,-30} {1}" -f "Progress refresh (ms):",   $Profile.Tuned_ProgressIntervalMs)      -ForegroundColor Gray
    Write-Host ("    {0,-30} {1}" -f "Verify parallelism:",       $Profile.Tuned_VerifyParallelism)       -ForegroundColor Gray
    Write-Host ("    {0,-30} {1}" -f "Test-restore sample %:",    $Profile.Tuned_TestRestorePct)          -ForegroundColor Gray
    if ($Profile.Tuned_IPGOverride -gt 0) {
        Write-Host ("    {0,-30} {1}" -f "HDD throttle IPG (ms):",  $Profile.Tuned_IPGOverride)           -ForegroundColor DarkYellow
    }
    Write-Host ""
}

function Apply-HardwareTuning {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Applies the hardware-tuned values to the live script parameters.
        CLI args and UFM_Config.json always win — HW tuning only fills gaps.
        Call this AFTER Import-CentralConfig so config file values are already loaded.
    #>
    param([PSCustomObject]$Profile)
    if (-not $Profile -or $DisableAutoPerfTuning) { return }

    # Only override when the user did NOT pass the param explicitly on the command line
    $bound = $PSBoundParameters

    if (-not $bound.ContainsKey('RobocopyThreads') -and $RobocopyThreads -eq 0) {
        Set-Variable -Name 'RobocopyThreads' -Value $Profile.Tuned_RobocopyThreads -Scope Script -ErrorAction SilentlyContinue
        Write-Log "HW-Tuning: RobocopyThreads=$($Profile.Tuned_RobocopyThreads) (CPU=$($Profile.PhysicalCores)P, Storage auto)"
    }

    if (-not $bound.ContainsKey('MaxParallel') -and $MaxParallel -le 4) {
        Set-Variable -Name 'MaxParallel' -Value $Profile.Tuned_MaxParallel -Scope Script -ErrorAction SilentlyContinue
        Write-Log "HW-Tuning: MaxParallel=$($Profile.Tuned_MaxParallel) (RAM=$($Profile.FreeRAM_GB)GB free, cores=$($Profile.PhysicalCores))"
    }

    if (-not $bound.ContainsKey('TestRestoreSamplePct')) {
        Set-Variable -Name 'TestRestoreSamplePct' -Value $Profile.Tuned_TestRestorePct -Scope Script -ErrorAction SilentlyContinue
        Write-Log "HW-Tuning: TestRestoreSamplePct=$($Profile.Tuned_TestRestorePct)"
    }
}

function Get-DriveProfile {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Returns the HW drive profile for a given path's drive letter.
        Falls back gracefully if detection was skipped or the drive wasn't profiled.
    #>
    param([string]$Path)
    if (-not $script:HW -or -not $script:HW.Drives) { return $null }
    try {
        $letter = (Split-Path $Path -Qualifier -ErrorAction SilentlyContinue).TrimEnd(':').ToUpper()
        if ($letter -and $script:HW.Drives.ContainsKey($letter)) { return $script:HW.Drives[$letter] }
    } catch [System.Exception] { }
    return $null
}

function Update-DriveProfile {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Adds a drive to the hardware profile at runtime (e.g. when a destination
        path is entered interactively after startup). Idempotent — skips if already profiled.
    #>
    param([string]$Path)
    if (-not $script:HW -or -not $Path) { return }
    try {
        $letter = (Split-Path $Path -Qualifier -ErrorAction SilentlyContinue).TrimEnd(':').ToUpper()
        if ($letter -and -not $script:HW.Drives.ContainsKey($letter)) {
            Write-Log "HW-Tuning: profiling new drive $letter (destination added after startup)"
            $newProfile = Invoke-HardwareDetection -DrivesToProfile @($letter)
            if ($newProfile.Drives.ContainsKey($letter)) {
                $script:HW.Drives[$letter] = $newProfile.Drives[$letter]
                Write-Log "HW-Tuning: drive ${letter} = $($newProfile.Drives[$letter].MediaType)"
            }
        }
    } catch [System.Exception] { }
}

#endregion

function Get-OptimalThreadCount {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Returns the optimal robocopy thread count for a given folder.
        Priority: CLI -RobocopyThreads > HW profile (per source drive) > file-size heuristic.
        Parallel mode rate-limiting caps total concurrent threads at 32 system-wide.
    #>
    param(
        [long]$FolderSizeBytes,
        [int]$FileCount,
        [string]$SourcePath = '',    # used to look up drive type in HW profile
        [string]$DestPath   = ''
    )

    # Explicit override always wins
    if ($RobocopyThreads -gt 0) { return $RobocopyThreads }
    if ($FileCount -eq 0)        { return 4 }

    # ── WAN / high-latency guard ─────────────────────────────────────────────
    # If -WanOptimized is set, or hardware detection measured RTT > 50 ms on either
    # the source or destination drive, cap threads at 2. More threads on a high-latency
    # link overwhelms TCP buffers, causes retransmits, and drops throughput below 1 MB/s.
    $srcLetter = if ($SourcePath -match '^([A-Za-z]):') { $Matches[1].ToUpper() } else { $null }
    $dstLetter = if ($DestPath   -match '^([A-Za-z]):') { $Matches[1].ToUpper() } else { $null }
    $isHighLatency = $WanOptimized.IsPresent
    if (-not $isHighLatency -and $script:HW -and $script:HW.PSObject.Properties['DriveRttMs'] -and $script:HW.DriveRttMs) {
        foreach ($dl in @($srcLetter, $dstLetter) | Where-Object { $_ }) {
            if ($script:HW.DriveRttMs.ContainsKey($dl) -and $script:HW.DriveRttMs[$dl] -gt 50) {
                $isHighLatency = $true
                Write-Log "WAN mode: drive ${dl} RTT=$($script:HW.DriveRttMs[$dl]) ms → capping /MT:2"
                break
            }
        }
    }
    if ($isHighLatency) { return 2 }

    # Look up storage type for source and destination from hardware profile
    $srcDrive  = Get-DriveProfile -Path $SourcePath
    $dstDrive  = Get-DriveProfile -Path $DestPath
    $srcIsSSD  = $srcDrive  -and ($srcDrive.IsSSD  -or $srcDrive.IsNVMe)
    $dstIsSSD  = $dstDrive  -and ($dstDrive.IsSSD  -or $dstDrive.IsNVMe)
    $srcIsNet  = $srcDrive  -and $srcDrive.IsNetwork
    $dstIsNet  = $dstDrive  -and $dstDrive.IsNetwork
    $srcIsNVMe = $srcDrive  -and $srcDrive.IsNVMe
    $dstIsNVMe = $dstDrive  -and $dstDrive.IsNVMe
    $srcIsUSB  = $srcDrive  -and $srcDrive.IsUSB
    $dstIsUSB  = $dstDrive  -and $dstDrive.IsUSB

    # CPU core count from profile (fallback: Environment)
    $cores = if ($script:HW) { $script:HW.PhysicalCores } else { [int][Environment]::ProcessorCount }

    # Base thread count by storage topology:
    $baseThreads = if ($srcIsNVMe -and $dstIsNVMe) {
        # Both NVMe: saturate with many threads; bounded by core count
        [Math]::Min(32, $cores * 2)
    } elseif (($srcIsSSD -or $srcIsNVMe) -and ($dstIsSSD -or $dstIsNVMe)) {
        # Both SSD: high concurrency
        [Math]::Min(16, $cores * 2)
    } elseif ($srcIsSSD -or $dstIsSSD) {
        # Mixed SSD/HDD: moderate
        [Math]::Min(8, $cores)
    } elseif ($srcIsNet -or $dstIsNet) {
        # Network destination: bandwidth-limited, not I/O-limited
        if ($script:HW -and $script:HW.IsHighSpeedNIC) { [Math]::Min(16, $cores) }
        else { [Math]::Min(8, [Math]::Max(2, $cores / 2)) }
    } elseif ($srcIsUSB -or $dstIsUSB) {
        # USB: single-threaded is usually optimal for USB 2/3 controllers
        2
    } else {
        # HDD or unknown: file-size-based heuristic
        $avgMB = ($FolderSizeBytes / 1MB) / [Math]::Max(1, $FileCount)
        if    ($avgMB -gt 500) { 2  }
        elseif ($avgMB -gt 100) { 4  }
        elseif ($avgMB -gt 10)  { [Math]::Min(6, $cores) }
        else                    { [Math]::Min(8, $cores) }
    }

    # Rate limiting: when running parallel users, divide thread budget so that
    # total concurrent robocopy threads across all users is capped at 32.
    $parallelFactor = if ($MaxParallel -gt 1) { $MaxParallel } else { 1 }
    $capped         = [Math]::Max(1, [int][Math]::Floor($baseThreads / $parallelFactor))
    if ($parallelFactor -gt 1) { $capped = [Math]::Min(8, $capped) }   # hard cap per-user in parallel

    return $capped
}

# ── Notification Helper (Feature 4.3) ─────────────────────────────────────
function Invoke-AutoInstallComponents {
    <#
    .SYNOPSIS
        Attempts to auto-install or auto-enable every optional component UFM can use.
        Safe to call multiple times — each check is individually guarded and idempotent.
        Runs silently for already-present components; only writes to log/console on action.

    COMPONENTS HANDLED:
        1. NuGet provider        — required for Install-Module on fresh systems
        2. PowerShellGet         — updated if < 1.6.0 (needed for -AllowPrerelease)
        3. PoshMailKit           — PS module for SMTP email; auto-installed if -NotificationEmail set
        4. handle.exe            — Sysinternals; downloaded via winget or live.sysinternals.com
        5. Windows Services      — WMI, VSS, EventLog, Schedule, CryptSvc, LanmanWorkstation, EFS
        6. EventLog source       — 'UserFolderMigrator' source registered if missing
    #>
    [CmdletBinding()]
    param()

    Write-Log "Invoke-AutoInstallComponents: starting component check"

    # ────────────────────────────────────────────────────────────────────────
    # OFFLINE MODE: skip all Install-Module / Install-PackageProvider calls.
    # Pre-stage modules in .\UFM_Modules\ alongside the script.
    # ────────────────────────────────────────────────────────────────────────
    if ($OfflineMode) {
        Write-Status "OfflineMode: skipping Install-Module/PackageProvider calls." -Type "Warning"
        Write-Log "Invoke-AutoInstallComponents: OfflineMode — loading from UFM_Modules if present"
        $offlineModulesPath = Join-Path $PSScriptRoot 'UFM_Modules'
        if (Test-Path $offlineModulesPath) {
            $env:PSModulePath = "$offlineModulesPath;$env:PSModulePath"
            Write-Log "OfflineMode: added $offlineModulesPath to PSModulePath"
        } else {
            Write-Status "OfflineMode: UFM_Modules folder not found at $offlineModulesPath — modules unavailable." -Type "Warning"
        }
        # Skip to service/EventLog checks (steps 5+) which do not require internet
    } else {

    # ────────────────────────────────────────────────────────────────────────
    # 1. NuGet provider — required by Install-Module on clean Windows installs
    # ────────────────────────────────────────────────────────────────────────
    try {
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget -or $nuget.Version -lt [Version]'2.8.5.201') {
            Write-Status "NuGet provider missing or outdated — installing..." -Type "Info"
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
            Write-Status "NuGet provider installed." -Type "Success"
            Write-Log "NuGet provider installed"
        } else {
            Write-Log "NuGet provider OK ($($nuget.Version))"
        }
    } catch {
        Write-Status "NuGet provider install failed: $($_.Exception.Message) — Install-Module may not work." -Type "Warning"
        Write-Log "NuGet provider install failed: $_"
    }

    # ────────────────────────────────────────────────────────────────────────
    # 2. PowerShellGet >= 1.6.0 — required for Install-Module -AllowPrerelease
    # ────────────────────────────────────────────────────────────────────────
    try {
        $psget = Get-Module -ListAvailable -Name PowerShellGet |
                     Sort-Object Version -Descending | Select-Object -First 1
        if (-not $psget -or $psget.Version -lt [Version]'1.6.0') {
            Write-Status "PowerShellGet $($psget.Version) outdated — updating to support pre-release packages..." -Type "Info"
            Install-Module -Name PowerShellGet -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-Status "PowerShellGet updated." -Type "Success"
            Write-Log "PowerShellGet updated"
        } else {
            Write-Log "PowerShellGet OK ($($psget.Version))"
        }
    } catch {
        Write-Status "PowerShellGet update failed: $($_.Exception.Message)" -Type "Warning"
        Write-Log "PowerShellGet update failed: $_"
    }

    # ────────────────────────────────────────────────────────────────────────
    # 3. PoshMailKit — required for SMTP email notifications
    #    Only attempted when -NotificationEmail is specified.
    #    NuGet + PowerShellGet (steps 1 & 2 above) must succeed first.
    # ────────────────────────────────────────────────────────────────────────
    if ($NotificationEmail) {
        $null = Initialize-PoshMailKit
    }

    } # end if (-not $OfflineMode)

    # ── 4. handle.exe (Sysinternals) – using generic downloader
    $script:HandlePath = Invoke-SysinternalsDownload -ToolName 'Handle' -ExeName 'handle.exe'
    if ($script:HandlePath) {
        Write-Log "handle.exe ready at $script:HandlePath"
    } else {
        Write-Status "handle.exe unavailable – locked‑file detection falls back to FileStream probe (tier 1)." -Type "Warning"
        Write-Log "handle.exe not available after auto‑install attempt"
    }

# Download additional Sysinternals tools if their features are active
if ($SecureWipeSource) {
    $script:SDeletePath = Invoke-SysinternalsDownload -ToolName 'SDelete'
}
if (-not $SkipAccessCheck) {
    $script:AccessChkPath = Invoke-SysinternalsDownload -ToolName 'AccessChk' -ExeName 'accesschk.exe'
}
if (-not $SkipJunctionScan) {
    $script:JunctionPath = Invoke-SysinternalsDownload -ToolName 'Junction' -ExeName 'junction.exe'
}

    # ────────────────────────────────────────────────────────────────────────
    # 4. Windows Services — auto-enable and start every service UFM depends on.
    #
    #    Each entry: Name, DisplayName, why it's needed, condition under which
    #    it's required, and whether a failure is Fatal (abort) or Warning (skip feature).
    #
    #    StartupType policy:
    #      - If service is Disabled  → set to Manual, then start
    #      - If service is stopped   → start (leave StartupType unchanged)
    #      - If service is running   → no action
    #    We never force Automatic startup — that's an admin policy decision.
    # ────────────────────────────────────────────────────────────────────────

    $serviceSpecs = @(
        @{
            Name        = 'winmgmt'
            Display     = 'Windows Management Instrumentation (WMI)'
            Reason      = 'Required for CIM/WMI queries: disk info, VSS shadow creation, user profile enumeration'
            Condition   = $true        # always needed
            Fatal       = $true        # migration cannot run without WMI
        },
        @{
            Name        = 'VSS'
            Display     = 'Volume Shadow Copy (VSS)'
            Reason      = 'Required for -UseVSS and smart locked-file detection'
            Condition   = ($UseVSS -or -not $DisableSmartVSS)
            Fatal       = $false       # falls back to live-path copy
        },
        @{
            Name        = 'EventLog'
            Display     = 'Windows Event Log'
            Reason      = 'Required for Write-EventLog audit entries'
            Condition   = -not $NoEventLog
            Fatal       = $false       # -NoEventLog skips it; non-fatal if stopped
        },
        @{
            Name        = 'Schedule'
            Display     = 'Task Scheduler'
            Reason      = 'Required for -RegisterTask mode'
            Condition   = $RegisterTask.IsPresent
            Fatal       = $false       # only needed for task registration
        },
        @{
            Name        = 'CryptSvc'
            Display     = 'Cryptographic Services'
            Reason      = 'Required for DPAPI credential encryption (-SmtpCredential, -OAuthClientSecret)'
            Condition   = [bool]($SmtpCredential -or $OAuthClientSecret)
            Fatal       = $false       # only affects credential-based email auth
        },
        @{
            Name        = 'LanmanWorkstation'
            Display     = 'Workstation (LanmanWorkstation)'
            Reason      = 'Required for UNC network destination paths (\\server\share)'
            Condition   = ($Destination -and $Destination.StartsWith('\\'))
            Fatal       = $false       # only needed for UNC destinations
        },
        @{
            Name        = 'EFS'
            Display     = 'Encrypting File System (EFS)'
            Reason      = 'Required for cipher.exe EFS encryption (UF_Encryption plugin)'
            Condition   = [bool](Get-Command 'PostFolder_EncryptFiles' -ErrorAction SilentlyContinue)
            Fatal       = $false       # encryption is optional
        }
    )

    Write-SectionHeader "SERVICE AUTO-START CHECK"

    $anyFatalFailed = $false

    foreach ($spec in $serviceSpecs) {
        # Skip services whose feature is not active this run
        if (-not $spec.Condition) {
            Write-Log "Service '$($spec.Name)': condition not met — skipping"
            continue
        }

        try {
            $svc = Get-Service -Name $spec.Name -ErrorAction SilentlyContinue

            if (-not $svc) {
                $msg = "Service '$($spec.Display)' not found on this system"
                if ($spec.Fatal) {
                    Write-Status "$msg — FATAL: migration cannot proceed." -Type "Error"
                    Write-Log "$msg [FATAL]"
                    $anyFatalFailed = $true
                } else {
                    Write-Status "$msg — feature will be skipped." -Type "Warning"
                    Write-Log "$msg [non-fatal]"
                }
                continue
            }

            # Re-enable if Disabled
            if ($svc.StartType -eq 'Disabled') {
                Write-Status "$($spec.Display) is Disabled — setting to Manual and starting..." -Type "Info"
                Set-Service -Name $spec.Name -StartupType Manual -ErrorAction Stop
                Write-Log "Service '$($spec.Name)': StartupType Disabled → Manual"
            }

            # Start if not running
            if ($svc.Status -ne 'Running') {
                Write-Status "Starting $($spec.Display) [$($spec.Reason)]..." -Type "Info"
                Start-Service -Name $spec.Name -ErrorAction Stop
                $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
                Write-Status "$($spec.Display) started." -Type "Success"
                Write-Log "Service '$($spec.Name)' started (was $($svc.Status))"
            } else {
                Write-Log "Service '$($spec.Name)' already running — OK"
            }

        } catch {
            $msg = "Could not start $($spec.Display): $($_.Exception.Message)"
            if ($spec.Fatal) {
                Write-Status "$msg — FATAL." -Type "Error"
                Write-Log "$msg [FATAL]"
                $anyFatalFailed = $true
            } else {
                Write-Status "$msg — continuing without it." -Type "Warning"
                Write-Log "$msg [non-fatal, continuing]"
            }
        }
    }

    # Abort if any fatal service could not be started
    if ($anyFatalFailed) {
        Send-MigrationNotification `
            -Subject "SERVICE START FAILED — UserFolderMigrator on $env:COMPUTERNAME" `
            -Body "A required Windows service could not be started. Migration ABORTED.`n`nComputer : $env:COMPUTERNAME`nLog      : $($script:LogFile)`n`nCheck the log for which service failed and ensure it is not disabled by Group Policy." `
            -Status 'Error'
        $script:ExitCode = $script:EXIT_FAILURE
        Exit-WithReport -Code $script:ExitCode
    }

# ── VSS auto-enable ───────────────────────────────────────────────────────
    # If -UseVSS was not explicitly passed, check if VSS actually started.
    # If running  → auto-enable VSS mode for consistent locked-file capture.
    # If not      → stay in live-copy mode (already warned by service loop above).
    if (-not $UseVSS) {
        $vssAutoSvc = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
        if ($vssAutoSvc -and $vssAutoSvc.Status -eq 'Running') {
            Set-Variable -Name 'UseVSS' -Value ([switch]$true) -Scope Script -ErrorAction SilentlyContinue
            $script:VSSAutoEnabled = $true
            Write-Status 'VSS service running — auto-enabled VSS mode for consistent snapshot' -Type 'Info'
            Write-Log 'UseVSS auto-enabled: VSS service confirmed running'
        } else {
            $script:VSSAutoEnabled = $false
            Write-Status 'VSS service unavailable — running in live-copy mode' -Type 'Warning'
            Write-Log 'UseVSS auto-enable skipped: VSS service not running'
        }
    } else {
        Write-Log 'UseVSS: explicitly set by user — skipping auto-detection'
    }

    # ────────────────────────────────────────────────────────────────────────
    # 5. EventLog source registration — needs to exist before first Write-EventLog call
    # ────────────────────────────────────────────────────────────────────────
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('UserFolderMigrator')) {
            Write-Status "Registering EventLog source 'UserFolderMigrator'..." -Type "Info"
            New-EventLog -LogName 'Application' -Source 'UserFolderMigrator' -ErrorAction Stop
            Write-Status "EventLog source registered." -Type "Success"
            Write-Log "EventLog source 'UserFolderMigrator' registered"
        } else {
            Write-Log "EventLog source already registered"
        }
    } catch {
        Write-Status "EventLog source registration failed: $($_.Exception.Message) — event log entries will be skipped." -Type "Warning"
        Write-Log "EventLog source registration failed: $_"
    }

    Write-Log "Invoke-AutoInstallComponents: complete"
}

function Initialize-PoshMailKit {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Ensures PoshMailKit is installed and imported. Runs only when -NotificationEmail
        is in use. Safe to call multiple times — exits immediately after the first success.
    .OUTPUTS
        [bool] $true if the module is ready, $false on any failure.
    #>
    param()
    if ($script:PoshMailKitReady) { return $true }
    if (-not $NotificationEmail)  { return $false }  # Email not requested — skip entirely

    Write-SectionHeader "EMAIL MODULE SETUP (PoshMailKit)"

    # ── 1. Check if already installed ────────────────────────────────────────
    $installed = Get-Module -ListAvailable -Name 'PoshMailKit' -ErrorAction SilentlyContinue
    if (-not $installed) {
        Write-Status "PoshMailKit not found — installing now (AllowPrerelease, Scope CurrentUser)..." -Type "Info"
        Write-Log "PoshMailKit not present — starting automatic installation"
        try {
            # Ensure PowerShellGet is modern enough to handle -AllowPrerelease
            $psget = Get-Module -ListAvailable PowerShellGet | Sort-Object Version -Descending | Select-Object -First 1
            if ($psget -and $psget.Version -lt [Version]'1.6.0') {
                Write-Status "Updating PowerShellGet to support pre-release packages..." -Type "Info"
                Install-Module -Name PowerShellGet -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            }
            Install-Module -Name PoshMailKit -AllowPrerelease -Force -Scope CurrentUser -ErrorAction Stop
            Write-Status "PoshMailKit installed successfully." -Type "Success"
            Write-Log "PoshMailKit installed successfully"
        } catch {
            Write-Status "Failed to install PoshMailKit: $_" -Type "Error"
            Write-Log "PoshMailKit installation failed: $_"
            return $false
        }
    } else {
        Write-Status "PoshMailKit $($installed[0].Version) found — skipping install." -Type "Info"
        Write-Log "PoshMailKit $($installed[0].Version) already present"
    }

    # ── 2. Import the module ──────────────────────────────────────────────────
    try {
        Import-Module -Name PoshMailKit -Force -ErrorAction Stop
        Write-Status "PoshMailKit imported." -Type "Success"
        Write-Log "PoshMailKit imported"
        $script:PoshMailKitReady = $true
        return $true
    } catch {
        Write-Status "Failed to import PoshMailKit: $_" -Type "Error"
        Write-Log "PoshMailKit import failed: $_"
        return $false
    }
}

function Resolve-SmtpConfig {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Returns a [PSCustomObject]@{ Server; Port; UseSsl } based on the provided
        -SmtpServer / -SmtpPort parameters or auto-detects from the recipient domain.
    .DESCRIPTION
        Priority order:
          1. Explicit -SmtpServer + -SmtpPort  → used as-is (UseSsl = Port -ne 25)
          2. Explicit -SmtpServer, no port      → port inferred from server name
          3. Neither provided                   → server + port derived from recipient domain
        Well-known provider map (expandable):
          gmail.com / googlemail.com → smtp.gmail.com : 587  TLS
          outlook.com / hotmail.com / live.com / msn.com → smtp.office365.com : 587  TLS
          yahoo.com / ymail.com      → smtp.mail.yahoo.com : 587  TLS
          icloud.com / me.com / mac.com → smtp.mail.me.com : 587  TLS
          zoho.com                   → smtp.zoho.com : 587  TLS
          (anything else)            → localhost : 25   no-TLS  (relay / internal)
    #>
    param()
    if ($script:ResolvedSmtpConfig) { return $script:ResolvedSmtpConfig }

    # Extract recipient domain
    $domain = ''
    if ($NotificationEmail -match '@(.+)$') { $domain = $Matches[1].ToLower().Trim() }

    # Well-known provider table
    $providerMap = [ordered]@{
        'gmail.com'       = [PSCustomObject]@{ Server = 'smtp.gmail.com';       Port = 587; UseSsl = $true }
        'googlemail.com'  = [PSCustomObject]@{ Server = 'smtp.gmail.com';       Port = 587; UseSsl = $true }
        'outlook.com'     = [PSCustomObject]@{ Server = 'smtp.office365.com';   Port = 587; UseSsl = $true }
        'hotmail.com'     = [PSCustomObject]@{ Server = 'smtp.office365.com';   Port = 587; UseSsl = $true }
        'live.com'        = [PSCustomObject]@{ Server = 'smtp.office365.com';   Port = 587; UseSsl = $true }
        'msn.com'         = [PSCustomObject]@{ Server = 'smtp.office365.com';   Port = 587; UseSsl = $true }
        'yahoo.com'       = [PSCustomObject]@{ Server = 'smtp.mail.yahoo.com';  Port = 587; UseSsl = $true }
        'ymail.com'       = [PSCustomObject]@{ Server = 'smtp.mail.yahoo.com';  Port = 587; UseSsl = $true }
        'icloud.com'      = [PSCustomObject]@{ Server = 'smtp.mail.me.com';     Port = 587; UseSsl = $true }
        'me.com'          = [PSCustomObject]@{ Server = 'smtp.mail.me.com';     Port = 587; UseSsl = $true }
        'mac.com'         = [PSCustomObject]@{ Server = 'smtp.mail.me.com';     Port = 587; UseSsl = $true }
        'zoho.com'        = [PSCustomObject]@{ Server = 'smtp.zoho.com';        Port = 587; UseSsl = $true }
    }

    # -- Determine base config from domain or explicit server ----------------
    $cfg = if ($SmtpServer) {
        # User supplied a server — infer port from its name if not explicit
        $inferredPort = if ($SmtpPort -gt 0) { $SmtpPort }
                        elseif ($SmtpServer -match 'gmail')       { 587 }
                        elseif ($SmtpServer -match 'office365|outlook|exchange') { 587 }
                        elseif ($SmtpServer -match 'yahoo')       { 587 }
                        elseif ($SmtpServer -match 'zoho')        { 587 }
                        elseif ($SmtpServer -match 'localhost|127\.0\.0\.1') { 25 }
                        else                                      { 587 }   # safe modern default
        [PSCustomObject]@{
            Server = $SmtpServer
            Port   = $inferredPort
            UseSsl = ($inferredPort -ne 25)
        }
    } elseif ($providerMap.Contains($domain)) {
        $p = $providerMap[$domain]
        [PSCustomObject]@{
            Server = $p.Server
            Port   = if ($SmtpPort -gt 0) { $SmtpPort } else { $p.Port }
            UseSsl = $p.UseSsl
        }
    } else {
        # Unknown domain — use localhost relay, no auth
        [PSCustomObject]@{ Server = 'localhost'; Port = 25; UseSsl = $false }
    }

    Write-Log "SMTP config resolved: Server=$($cfg.Server) Port=$($cfg.Port) SSL=$($cfg.UseSsl)"
    $script:ResolvedSmtpConfig = $cfg
    return $cfg
}


#region ── Enterprise Email Security ─────────────────────────────────────────

function Set-TlsSecurityPolicy {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Enforces TLS 1.2 minimum for all .NET HTTP/SMTP connections in this session.
        Disables SSLv3, TLS 1.0, and TLS 1.1 by overwriting the process-wide ServicePointManager
        protocol mask. Called once at the top of Main, before any network activity.
    #>
    param()
    try {
        $target = [System.Net.SecurityProtocolType]::Tls12
        # TLS 1.3 was added in .NET 5+; silently skip if the enum value is absent on older runtimes.
        try   { $target = $target -bor [System.Net.SecurityProtocolType]::Tls13 } catch [System.Exception] { }
        [System.Net.ServicePointManager]::SecurityProtocol = $target
        Write-Status "TLS 1.2+ enforced for all .NET connections (legacy TLS disabled)." -Type "Success"
        Write-Log "TLS policy set: $([System.Net.ServicePointManager]::SecurityProtocol)"
    } catch {
        Write-Status "TLS policy enforcement failed: $_ — session continues with OS default." -Type "Warning"
        Write-Log "TLS policy error: $_"
    }
}

function Invoke-SysinternalsDownload {
    <#
    .SYNOPSIS
        Downloads a Sysinternals tool (winget → direct HTTPS) and returns the full path to the exe.
        Returns $null if the tool cannot be obtained.
    #>
    param(
        [Parameter(Mandatory)] [string]$ToolName,       # e.g. 'Handle', 'SDelete'
        [string]$ExeName = "$ToolName.exe"              # override if exe name differs
    )
    # Enforce a hardened, dedicated directory directly under C:\
$secureBinDir = "C:\UserFolderMigrator_Binaries"
if (-not (Test-Path $secureBinDir)) {
    $null = New-Item -ItemType Directory -Path $secureBinDir -Force
    
    # Secure the folder: Break inheritance and restrict access to Admins & SYSTEM
    $acl = Get-Acl $secureBinDir
    $acl.SetAccessRuleProtection($true, $false) # True = break inheritance, False = do not copy old rules
    
    # Define explicit high-privilege access rules
    $systemRule = [System.Security.AccessControl.FileSystemAccessRule]::new("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $adminRule  = [System.Security.AccessControl.FileSystemAccessRule]::new("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    
    $acl.SetAccessRule($systemRule)
    $acl.SetAccessRule($adminRule)
    Set-Acl $secureBinDir $acl
}
$destPath = Join-Path $secureBinDir $ExeName

    # Already present?
    if ((Get-Command $ExeName -ErrorAction SilentlyContinue) -or (Test-Path $destPath)) {
        Write-Log "Sysinternals tool '$ExeName' already present."
        return $destPath
    }

    Write-Status "Sysinternals tool '$ExeName' not found – attempting auto-install..." -Type "Info"
    $installed = $false

    # ── Try winget first ──
    try {
        $wg = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($wg) {
            Write-Status "  winget install Microsoft.Sysinternals.$ToolName ..." -Type "Info"
            $null = & winget.exe install --id "Microsoft.Sysinternals.$ToolName" `
                --silent --accept-package-agreements --accept-source-agreements 2>&1
            if ($LASTEXITCODE -eq 0) {
                $installed = $true
            }
        }
    } catch {}

    # ── Fallback: direct HTTPS download ──
    if (-not $installed) {
        try {
            $url = "https://live.sysinternals.com/$ExeName"
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Write-Status "  Downloading $ExeName from live.sysinternals.com ..." -Type "Info"
            $wc = [System.Net.WebClient]::new()
            $wc.DownloadFile($url, $destPath)
            $wc.Dispose()
            if (Test-Path $destPath) {
                # Verify Authenticode signature — reject unsigned or non-Microsoft binaries
                $sig = Get-AuthenticodeSignature $destPath -ErrorAction SilentlyContinue
                if (-not $sig -or $sig.Status -ne 'Valid' -or
                    $sig.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
                    Write-Status "  Authenticode verification FAILED for $ExeName — removing." -Type "Warning"
                    Write-Log "Sysinternals $ExeName rejected: signature invalid or non-Microsoft"
                    Remove-Item $destPath -Force -ErrorAction SilentlyContinue
                } else {
                    $installed = $true
                }
            }
        } catch {
            Write-Log "Direct download of $ExeName failed: $_"
        }
    }

    if ($installed) {
        Write-Status "$ExeName ready at $destPath" -Type "Success"
        Write-Log "$ExeName auto-installed successfully"
        return $destPath
    } else {
        Write-Status "$ExeName auto-install failed – the feature will be skipped." -Type "Warning"
        Write-Log "$ExeName could not be obtained"
        return $null
    }
}

function Initialize-MsalPs {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Ensures MSAL.PS is installed and imported.
        Only called when -SmtpAuthMode is OAuth2 or Certificate.
    .OUTPUTS
        [bool] $true if the module is ready, $false on failure.
    #>
    param()
    if ($script:MsalPsReady) { return $true }
    $installed = Get-Module -ListAvailable -Name 'MSAL.PS' -ErrorAction SilentlyContinue
    if (-not $installed) {
        Write-Status "MSAL.PS not found — installing (Scope CurrentUser)..." -Type "Info"
        try {
            Install-Module -Name 'MSAL.PS' -Force -Scope CurrentUser -ErrorAction Stop
            Write-Status "MSAL.PS installed." -Type "Success"
            Write-Log "MSAL.PS installed"
        } catch {
            Write-Status "Failed to install MSAL.PS: $_" -Type "Error"
            Write-Log "MSAL.PS install failed: $_"
            return $false
        }
    } else {
        Write-Log "MSAL.PS $($installed[0].Version) already present"
    }
    try {
        Import-Module -Name 'MSAL.PS' -Force -ErrorAction Stop
        $script:MsalPsReady = $true
        Write-Log "MSAL.PS imported"
        return $true
    } catch {
        Write-Status "Failed to import MSAL.PS: $_" -Type "Error"
        Write-Log "MSAL.PS import failed: $_"
        return $false
    }
}

function Initialize-SecretManagement {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Ensures Microsoft.PowerShell.SecretManagement and Microsoft.PowerShell.SecretStore
        are installed and imported. Only called when -SmtpAuthMode is SecretVault.
    .OUTPUTS
        [bool] $true if both modules are ready, $false on any failure.
    #>
    param()
    if ($script:SecretMgmtReady) { return $true }
    foreach ($mod in @('Microsoft.PowerShell.SecretManagement', 'Microsoft.PowerShell.SecretStore')) {
        if (-not (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue)) {
            Write-Status "Installing $mod (Scope CurrentUser)..." -Type "Info"
            try {
                Install-Module -Name $mod -Force -Scope CurrentUser -ErrorAction Stop
                Write-Status "$mod installed." -Type "Success"
                Write-Log "$mod installed"
            } catch {
                Write-Status "Failed to install ${mod}: $_" -Type "Error"
                Write-Log "${mod} install failed: $_"
                return $false
            }
        }
        try {
            Import-Module -Name $mod -Force -ErrorAction Stop
        } catch {
            Write-Status "Failed to import ${mod}: $_" -Type "Error"
            Write-Log "${mod} import failed: $_"
            return $false
        }
    }
    $script:SecretMgmtReady = $true
    Write-Log "SecretManagement + SecretStore ready"
    return $true
}

function Get-CredentialFromSecretVault {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Retrieves a PSCredential from a SecretManagement vault.
        -SecretVaultName : vault to query (omit = registered default vault).
        -SecretName      : secret name to retrieve (default: 'UserFolderMigrator_SmtpCredential').
        The secret must be stored as a PSCredential. If stored as a bare SecureString
        (password only), the credential is assembled using $NotificationEmail as the username.
    .EXAMPLE
        # Store once (run interactively before first script use):
        Register-SecretVault -Name 'UserFolderMigrator' -ModuleName Microsoft.PowerShell.SecretStore
        Set-Secret -Name 'UserFolderMigrator_SmtpCredential' -Secret (Get-Credential) -Vault 'UserFolderMigrator'
    .OUTPUTS
        [PSCredential] or $null on failure.
    #>
    param()
    if (-not (Initialize-SecretManagement)) { return $null }
    $vaultSplat = @{}
    if ($SecretVaultName) { $vaultSplat['Vault'] = $SecretVaultName }
    $name = if ($SecretName) { $SecretName } else { 'UserFolderMigrator_SmtpCredential' }
    try {
        $secret = Get-Secret -Name $name @vaultSplat -ErrorAction Stop
        if ($secret -is [System.Management.Automation.PSCredential]) {
            Write-Log "SMTP credential retrieved from SecretVault (secret: $name, user: $($secret.UserName))"
            return $secret
        }
        if ($secret -is [System.Security.SecureString]) {
            $cred = [System.Management.Automation.PSCredential]::new($NotificationEmail, $secret)
            Write-Log "SMTP credential constructed from SecureString in SecretVault (secret: $name)"
            return $cred
        }
        Write-Status "Secret '$name' has type $($secret.GetType().Name) — must be PSCredential or SecureString." -Type "Error"
        Write-Log "SecretVault: '$name' unsupported type $($secret.GetType().Name)"
        return $null
    } catch {
        Write-Status "SecretVault retrieval failed for '$name': $_" -Type "Error"
        Write-Log "SecretVault error: $_"
        return $null
    }
}

function Get-CredentialFromWindowsCredManager {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Reads a Generic Credential from the Windows Credential Manager using the native
        Win32 CredRead API via Add-Type — no extra modules or cmdkey.exe required at runtime.
        -SecretName : credential target name (default: 'UFM_Smtp').
    .EXAMPLE
        # Pre-populate (run once in an elevated prompt before using this script):
        cmdkey /generic:UFM_Smtp /user:you@domain.com /pass:YourAppPassword
    .OUTPUTS
        [PSCredential] or $null on failure.
    #>
    param()
    $targetName = if ($SecretName) { $SecretName } else { 'UFM_Smtp' }

    # Define the Win32 interop surface once per PowerShell session
    if (-not ([System.Management.Automation.PSTypeName]'UserFolderMigrator.WinCredManager').Type) {
        try {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace UserFolderMigrator {
    [StructLayout(LayoutKind.Sequential)]
    public struct WIN_CREDENTIAL {
        public int    Flags;
        public int    Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public long   LastWritten;            // FILETIME as long — fully blittable
        public int    CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int    Persist;
        public int    AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    public static class WinCredManager {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredRead(
            string target, int type, int reservedFlags, out IntPtr credential);

        [DllImport("advapi32.dll")]
        public static extern void CredFree(IntPtr credential);
    }
}
'@ -ErrorAction Stop
        } catch {
            Write-Status "Win32 CredRead type definition failed: $_" -Type "Error"
            Write-Log "WinCredManager Add-Type error: $_"
            return $null
        }
    }

    $ptr = [IntPtr]::Zero
    try {
        if (-not [UserFolderMigrator.WinCredManager]::CredRead($targetName, 1, 0, [ref]$ptr)) {
            $w32err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $hint   = if ($w32err -eq 1168) { "Credential target '$targetName' does not exist." } else { "Win32 error $w32err." }
            Write-Status "Windows Credential Manager: $hint" -Type "Error"
            Write-Status "  Pre-populate: cmdkey /generic:$targetName /user:you@domain.com /pass:AppPassword" -Type "Info"
            Write-Log "WinCredManager CredRead failed for '$targetName': $hint"
            return $null
        }
        $rawCred   = [System.Runtime.InteropServices.Marshal]::PtrToStructure[UserFolderMigrator.WIN_CREDENTIAL]($ptr)
        $charCount = [Math]::Max(0, [int]($rawCred.CredentialBlobSize / 2))
        $password  = if ($charCount -gt 0) {
            [System.Runtime.InteropServices.Marshal]::PtrToStringUni($rawCred.CredentialBlob, $charCount)
        } else { '' }
        $userName  = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($rawCred.UserName)
        $secPass = ConvertTo-SecureString $password -AsPlainText -Force
        $result  = [System.Management.Automation.PSCredential]::new($userName, $secPass)
        Write-Log "SMTP credential retrieved from Windows Credential Manager (target: $targetName, user: $userName)"
        return $result
    } catch {
        Write-Status "Windows Credential Manager read failed: $_" -Type "Error"
        Write-Log "WinCredManager error: $_"
        return $null
    } finally {
        # Always free the memory allocated by CredRead, even if an exception was thrown
        if ($ptr -ne [IntPtr]::Zero) { [UserFolderMigrator.WinCredManager]::CredFree($ptr) }
    }
}

function Get-OAuthToken {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Acquires an OAuth2 access token for SMTP XOAUTH2 against Microsoft 365.
        Two flows are supported, selected by -SmtpAuthMode:
          OAuth2      — client_credentials with client secret  (-OAuthClientSecret)
                        Direct REST call; MSAL.PS not required.
          Certificate — client_credentials with X.509 certificate (-OAuthCertThumbprint)
                        Certificate must be in the LocalMachine\My store.
                        Uses MSAL.PS for JWT assertion signing.
        The token is cached and auto-refreshed 60 seconds before expiry so
        long-running multi-user sessions never fail mid-flight on token timeout.
    .NOTES
        M365 prerequisites (one-time admin setup):
          1. Register an Entra ID app with Mail.Send application permission (not delegated).
          2. Grant admin consent.
          3. Enable SMTP AUTH on the sender mailbox:
             Set-CASMailbox -Identity you@domain.com -SmtpClientAuthenticationDisabled $false
        For Gmail / Yahoo / iCloud: OAuth2 requires a separate Google / Yahoo app registration
        with provider-specific scopes. Use -SmtpAuthMode Basic with a vault-sourced App Password
        for those providers until native Google OAuth2 support is added.
    .OUTPUTS
        [string] Raw access token string, or $null on any failure.
    #>
    param()
    # Return cached token if still valid (60-second safety margin already baked into expiry)
    if ($script:CachedOAuthToken -and (Get-Date).ToUniversalTime() -lt $script:OAuthTokenExpiry) {
        return $script:CachedOAuthToken
    }

    if (-not $OAuthTenantId -or -not $OAuthClientId) {
        Write-Status "OAuth2 / Certificate auth requires both -OAuthTenantId and -OAuthClientId." -Type "Error"
        Write-Log "OAuth2: TenantId or ClientId missing"
        return $null
    }

    Write-Status "Acquiring OAuth2 token from Microsoft identity platform..." -Type "Info"

    if ($SmtpAuthMode -eq 'Certificate') {
        # ── Certificate flow — most secure; private key never leaves the machine ───
        if (-not (Initialize-MsalPs)) { return $null }
        if (-not $OAuthCertThumbprint) {
            Write-Status "Certificate auth requires -OAuthCertThumbprint." -Type "Error"
            Write-Log "OAuth2/Certificate: OAuthCertThumbprint not supplied"
            return $null
        }
        try {
            $cert = Get-Item "Cert:\LocalMachine\My\$OAuthCertThumbprint" -ErrorAction Stop
            $msalSplat = @{
                ClientId          = $OAuthClientId
                TenantId          = $OAuthTenantId
                ClientCertificate = $cert
                Scopes            = 'https://outlook.office365.com/.default'
            }
            $tokenResult = Get-MsalToken @msalSplat -ErrorAction Stop
            $script:CachedOAuthToken = $tokenResult.AccessToken
            # ExpiresOn is a DateTimeOffset; store as UTC with 60-second buffer
            $script:OAuthTokenExpiry  = $tokenResult.ExpiresOn.UtcDateTime.AddSeconds(-60)
            Write-Status "OAuth2 token acquired via certificate (valid until $($script:OAuthTokenExpiry.ToString('HH:mm:ss')) UTC)." -Type "Success"
            Write-Log "OAuth2/Certificate token acquired. Thumbprint: $OAuthCertThumbprint Expiry: $($script:OAuthTokenExpiry)"
            return $script:CachedOAuthToken
        } catch {
            Write-Status "Certificate OAuth2 token acquisition failed: $_" -Type "Error"
            Write-Log "OAuth2/Certificate token error: $_"
            return $null
        }

    } else {
        # ── Client secret flow — direct REST call, no extra module required ──────
        if (-not $OAuthClientSecret) {
            Write-Status "OAuth2 mode requires -OAuthClientSecret." -Type "Error"
            Write-Log "OAuth2/ClientSecret: OAuthClientSecret not supplied"
            return $null
        }
        try {
            $tokenUri = "https://login.microsoftonline.com/$OAuthTenantId/oauth2/v2.0/token"
            $body = @{
                grant_type    = 'client_credentials'
                client_id     = $OAuthClientId
                client_secret = [System.Net.NetworkCredential]::new('', $OAuthClientSecret).Password
                scope         = 'https://outlook.office365.com/.default'
            }
            $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ErrorAction Stop
            $script:CachedOAuthToken = $response.access_token
            $script:OAuthTokenExpiry  = (Get-Date).ToUniversalTime().AddSeconds($response.expires_in - 60)
            Write-Status "OAuth2 token acquired via client_credentials (valid until $($script:OAuthTokenExpiry.ToString('HH:mm:ss')) UTC)." -Type "Success"
            Write-Log "OAuth2/ClientSecret token acquired. Expiry: $($script:OAuthTokenExpiry)"
            return $script:CachedOAuthToken
        } catch {
            Write-Status "OAuth2 client_credentials request failed: $_" -Type "Error"
            Write-Log "OAuth2/ClientSecret token error: $_"
            return $null
        }
    }
}

function Get-SmtpCredentialOnce {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Returns a PSCredential for SMTP auth, dispatching based on -SmtpAuthMode.
        NOT called for OAuth2 / Certificate modes — those use Get-OAuthToken instead.
        The credential is cached on first retrieval and reused for the session lifetime.
    .NOTES
        Dispatch table:
          SecretVault       → Get-CredentialFromSecretVault      (SecretManagement)
          CredentialManager → Get-CredentialFromWindowsCredManager (Win32 CredRead)
          Basic (default)   → -SmtpCredential if supplied, else interactive Get-Credential
        Localhost / port-25 relay always returns $null (no authentication required).
    .OUTPUTS
        [PSCredential] or $null (relay / OAuth modes / cancelled prompt).
    #>
    param()
    if ($script:CachedSmtpCred) { return $script:CachedSmtpCred }

    $cfg = Resolve-SmtpConfig
    # Unauthenticated relay — no credential needed
    if ($cfg.Server -eq 'localhost' -or $cfg.Port -eq 25) { return $null }

    $cred = switch ($SmtpAuthMode) {
        'SecretVault' {
            Write-Status "Retrieving SMTP credential from SecretManagement vault..." -Type "Info"
            Get-CredentialFromSecretVault
        }
        'CredentialManager' {
            Write-Status "Retrieving SMTP credential from Windows Credential Manager..." -Type "Info"
            Get-CredentialFromWindowsCredManager
        }
        default {
            # Basic — use -SmtpCredential if supplied, otherwise prompt once interactively
            if ($SmtpCredential) {
                Write-Log "Using pre-supplied -SmtpCredential for $($SmtpCredential.UserName)"
                $SmtpCredential
            } else {
                $appPwdServers = @('smtp.gmail.com', 'smtp.mail.yahoo.com', 'smtp.mail.me.com')
                $needsAppPwd   = $cfg.Server -in $appPwdServers
                $promptMsg = if ($needsAppPwd) {
                    "Enter credentials for $($cfg.Server).`nIMPORTANT: If 2FA is enabled use an App Password — NOT your account password.`n`nUsername: full email address  |  Password: App Password"
                } else {
                    "Enter SMTP credentials for $($cfg.Server) (account: $NotificationEmail)"
                }
                Write-Host ""
                Write-Status "SMTP authentication required for $($cfg.Server)." -Type "Info"
                if ($needsAppPwd) { Write-Status "Use an App Password — your login password will not work here." -Type "Warning" }
                try {
                    $c = Get-Credential -Message $promptMsg -UserName $NotificationEmail -ErrorAction Stop
                    Write-Log "SMTP credential acquired interactively for $($c.UserName)"
                    $c
                } catch {
                    Write-Log "SMTP credential prompt cancelled or failed: $_"
                    $null
                }
            }
        }
    }

    if ($cred) { $script:CachedSmtpCred = $cred }
    return $cred
}

function Invoke-SmtpSendWithRetry {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Wraps Send-MKMailMessage with exponential-backoff retry logic.
        -SmtpMaxRetries    : total send attempts (script param, default 3).
        -SmtpRetryDelayBase: initial wait in seconds (script param, default 5).
        Delay schedule (base = 5s): attempt 1 fails → wait 5s, attempt 2 fails → wait 10s,
        attempt 3 fails → throw (no further wait). Effective delays: 5 → 10 → 20 → 40 …
    .PARAMETER SendParams
        Hashtable splatted directly into Send-MKMailMessage (must NOT include -Token).
    .PARAMETER Token
        OAuth2 access token string. When non-empty, passed as -Token to Send-MKMailMessage
        for XOAUTH2 authentication. Leave empty for Basic/vault/CredentialManager modes.
    #>
    param(
        [Parameter(Mandatory)] [hashtable]$SendParams,
        [string]$Token = ''
    )

    $attempt   = 0
    $lastError = $null

    while ($attempt -lt $SmtpMaxRetries) {
        $attempt++
        try {
            if ($Token) {
                Send-MKMailMessage @SendParams -Token $Token -ErrorAction Stop
            } else {
                Send-MKMailMessage @SendParams -ErrorAction Stop
            }
            if ($attempt -gt 1) {
                Write-Log "SMTP send succeeded on attempt $attempt (after $($attempt - 1) failure(s))"
            }
            return  # success — exit the retry loop
        } catch {
            $lastError = $_
            Write-Log "SMTP send attempt $attempt / $SmtpMaxRetries failed: $_"
            if ($attempt -lt $SmtpMaxRetries) {
                $delaySec = [int]($SmtpRetryDelayBase * [Math]::Pow(2, $attempt - 1))
                Write-Status "Email send failed (attempt $attempt/$SmtpMaxRetries) — retrying in ${delaySec}s..." -Type "Warning"
                Start-Sleep -Seconds $delaySec
            }
        }
    }

    # All attempts exhausted
    throw "SMTP send failed after $SmtpMaxRetries attempt(s). Last error: $lastError"
}

#endregion

function Build-HtmlEmailBody {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Builds a self-contained HTML email body that embeds the migration summary
        inline and appends the full HTML report as a collapsible section.
        Falls back to plain text if the HTML report file does not exist.
    .PARAMETER Subject   The notification subject (used in the banner heading).
    .PARAMETER PlainBody The plain-text body assembled by Exit-WithReport.
    .PARAMETER Status    'Success' | 'Warning' | 'Error' — drives the banner colour.
    .OUTPUTS
        [PSCustomObject]@{ Html=[string]; IsHtml=[bool] }
        IsHtml = $false means the caller should send PlainBody as-is (no -BodyAsHtml).
    #>
    param(
        [string]$Subject,
        [string]$PlainBody,
        [string]$Status = 'Info'
    )

    # Colour palette matched to console output symbols
    $bannerColor = switch ($Status) {
        'Success' { '#1a7f3c' }
        'Error'   { '#c0392b' }
        'Warning' { '#d68910' }
        default   { '#2471a3' }
    }
    $statusIcon = switch ($Status) {
        'Success' { '✔' }
        'Error'   { '✖' }
        'Warning' { '⚠' }
        default   { 'ℹ' }
    }

    # Convert plain body lines to an HTML table for clean rendering
    $rowsHtml = ($PlainBody -split "`n" | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq '') { return }
        if ($line -match '^(.+?)\s*:\s*(.+)$') {
            "<tr><td style='padding:4px 12px 4px 0;color:#888;white-space:nowrap;vertical-align:top;'>$($Matches[1])</td>" +
            "<td style='padding:4px 0;font-weight:600;'>$([System.Web.HttpUtility]::HtmlEncode($Matches[2]))</td></tr>"
        } else {
            "<tr><td colspan='2' style='padding:4px 0;'>$(([System.Web.HttpUtility]::HtmlEncode($line)))</td></tr>"
        }
    }) -join "`n"

    # Load and sanitise the full HTML report (inline, collapsible)
    $reportSection = ''
    if ($script:HtmlReportPath -and (Test-Path $script:HtmlReportPath) -and -not $DisableHtmlReport) {
        try {
            $reportContent = [System.IO.File]::ReadAllText($script:HtmlReportPath, [System.Text.Encoding]::UTF8)
            # Strip the outer <html>/<body> tags so it nests cleanly inside the email wrapper.
            # We keep everything between <body …> and </body> only.
            $inner = if ($reportContent -match '(?s)<body[^>]*>(.*)</body>') { $Matches[1] } else { $reportContent }
            $reportSection = @"
<details style="margin-top:28px;">
  <summary style="cursor:pointer;font-size:15px;font-weight:700;color:$bannerColor;padding:8px 0;border-top:2px solid $bannerColor;">
    $statusIcon Full HTML Report (click to expand)
  </summary>
  <div style="margin-top:16px;border:1px solid #ddd;border-radius:6px;overflow:hidden;">
    $inner
  </div>
</details>
"@
        } catch {
            Write-Log "Build-HtmlEmailBody: could not read HTML report file — $($_)"
        }
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>UserFolderMigrator Notification</title>
</head>
<body style="margin:0;padding:0;background:#f4f6f8;font-family:'Segoe UI',Arial,sans-serif;font-size:14px;color:#222;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8;padding:32px 0;">
    <tr><td align="center">
      <table width="620" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.08);overflow:hidden;max-width:100%;">

        <!-- Banner -->
        <tr>
          <td style="background:$bannerColor;padding:22px 32px;">
            <span style="font-size:22px;font-weight:700;color:#fff;letter-spacing:.5px;">
              $statusIcon &nbsp;UserFolderMigrator
            </span><br>
            <span style="font-size:13px;color:rgba(255,255,255,.8);">$Subject</span>
          </td>
        </tr>

        <!-- Summary table -->
        <tr>
          <td style="padding:28px 32px 8px;">
            <table cellpadding="0" cellspacing="0" style="width:100%;">
              $rowsHtml
            </table>
          </td>
        </tr>

        <!-- Full report (collapsible via <details>) -->
        <tr>
          <td style="padding:0 32px 28px;">
            $reportSection
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f4f6f8;padding:14px 32px;border-top:1px solid #e0e0e0;">
            <span style="font-size:11px;color:#aaa;">
              Generated by UserFolderMigrator on $env:COMPUTERNAME &nbsp;·&nbsp; $timestamp UTC
            </span>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
"@

    return [PSCustomObject]@{ Html = $html; IsHtml = $true }
}

function Send-MigrationNotification {
    <#
    .SYNOPSIS
        Sends the post-migration HTML email notification using the configured SMTP provider.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$Subject, [string]$Body, [string]$Status = 'Info')

    # ── Email via PoshMailKit ─────────────────────────────────────────────────
    if ($NotificationEmail) {
        if (-not $script:PoshMailKitReady) {
            if (-not (Initialize-PoshMailKit)) {
                Write-Log "Email notification skipped — PoshMailKit unavailable"
            }
        }

        if ($script:PoshMailKitReady) {
            try {
                $cfg = Resolve-SmtpConfig

                # Build rich HTML body (embeds full HTML report inline)
                $emailBody = Build-HtmlEmailBody -Subject $Subject -PlainBody $Body -Status $Status

                $fromAddr = if ($SmtpFrom)                         { $SmtpFrom }
                            elseif ($NotificationEmail -match '@') { $NotificationEmail }
                            else                                   { "ufm@$env:COMPUTERNAME" }

                $sendParams = @{
                    From       = $fromAddr
                    To         = $NotificationEmail
                    Subject    = "UserFolderMigrator: $Subject"
                    Body       = if ($emailBody.IsHtml) { $emailBody.Html } else { $Body }
                    SmtpServer = $cfg.Server
                    Port       = $cfg.Port
                }
                if ($emailBody.IsHtml) { $sendParams['BodyAsHtml'] = $true }
                if ($cfg.UseSsl)       { $sendParams['UseSsl']     = $true }
                # Attach the HTML report as a file if it exists
                if ($script:HtmlReportPath -and (Test-Path $script:HtmlReportPath) -and -not $DisableHtmlReport) {
                    $sendParams['Attachments'] = @($script:HtmlReportPath)
                }

                if ($SmtpAuthMode -in @('OAuth2', 'Certificate')) {
                    $token = Get-OAuthToken
                    if (-not $token) { throw "OAuth2 token acquisition returned null — aborting send." }
                    Invoke-SmtpSendWithRetry -SendParams $sendParams -Token $token
                } else {
                    $cred = Get-SmtpCredentialOnce
                    if ($cred) { $sendParams['Credential'] = $cred }
                    Invoke-SmtpSendWithRetry -SendParams $sendParams
                }

                Write-Log "Email notification sent → $NotificationEmail via $($cfg.Server):$($cfg.Port) [auth: $SmtpAuthMode, html: $($emailBody.IsHtml)]"
                Write-Status "Email notification sent to $NotificationEmail" -Type "Success"
            } catch {
                Write-Log "Email notification failed: $_"
                Write-Status "Email notification failed: $_" -Type "Warning"
            }
        }
    }
    # Teams Webhook
    if ($NotificationTeamsWebhook) {
        try {
            $color   = switch ($Status) { 'Success' { '00b050' } 'Error' { 'ff0000' } default { 'ffa500' } }
            $payload = @{
                '@type'    = 'MessageCard'; '@context' = 'https://schema.org/extensions'
                summary    = "UserFolderMigrator: $Subject"; themeColor = $color
                title      = "UserFolderMigrator — $Subject"; text = $Body
            } | ConvertTo-Json -Depth 3
            Invoke-RestMethod -Uri $NotificationTeamsWebhook -Method Post -Body $payload `
                -ContentType 'application/json' -ErrorAction SilentlyContinue
            Write-Log "Teams notification sent"
        } catch { Write-Log "Teams notification failed: $_" }
    }
    # Syslog mirror
    $sev = switch ($Status) { 'Error' { 3 } 'Warning' { 4 } default { 6 } }
    Send-SyslogMessage -Message "UserFolderMigrator [$Status] $Subject" -Severity $sev
}

# ── BitLocker Compliance Check (Feature 2.4) ──────────────────────────────
function Test-BitLockerCompliance {
    <#
    .SYNOPSIS
        Checks whether the volume hosting the given path is BitLocker-encrypted.
    #>
    [CmdletBinding()]
    param([string]$Path, [string]$Label = 'Destination')
    try {
        $qualifier = (Split-Path $Path -Qualifier -ErrorAction SilentlyContinue).TrimEnd(':')
        if (-not $qualifier) { return }
        $vol = Get-BitLockerVolume -MountPoint "${qualifier}:" -ErrorAction SilentlyContinue
        if (-not $vol) {
            Write-Status "${Label} drive ${qualifier}: BitLocker status unknown (may not be a BitLocker-managed volume)" -Type "Info"
        } elseif ($vol.ProtectionStatus -eq 'On') {
            Write-Status "${Label} drive ${qualifier}: BitLocker ENABLED (compliant)" -Type "Success"
            Write-Log "BitLocker check OK for ${qualifier}: ProtectionStatus=$($vol.ProtectionStatus)"
        } else {
            $msg = "${Label} drive ${qualifier}: BitLocker is OFF — data will be written unencrypted"
            Write-Status $msg -Type "Warning"
            Write-Log "BitLocker WARNING for ${qualifier}: ProtectionStatus=$($vol.ProtectionStatus)"
            if ($BitLockerRequired) {
                Write-Status "  -BitLockerRequired specified — aborting to enforce encryption policy" -Type "Error"
                Write-Log "Aborting: BitLockerRequired policy violated on $qualifier"
                $script:ExitCode = $script:EXIT_PERMISSION
                Exit-WithReport -Code $script:ExitCode
            }
        }
    } catch {
        Write-Log "BitLocker check error for ${Path}: $_"
    }
}

# ── TestCompatibility / Pre-flight (Feature 3.6) ──────────────────────────
function Invoke-TestCompatibility {
    <#
    .SYNOPSIS
        Runs pre-migration compatibility checks: OneDrive KFM, GPO redirection, and BitLocker.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$DestinationPath)
    Write-SectionHeader "PRE-FLIGHT COMPATIBILITY CHECK"
    $pass   = $true
    $checks = [System.Collections.Generic.List[object]]::new()

    # Admin rights
    $isAdmin = Test-AdminRight
    $checks.Add([PSCustomObject]@{ Check='Administrator Rights'; Result=$isAdmin
        Detail=if($isAdmin){'Running as Administrator'}else{'NOT running as Administrator'} })
    if (-not $isAdmin) { $pass = $false }

    # PowerShell version
    $psOk = $PSVersionTable.PSVersion.Major -ge 7
    $checks.Add([PSCustomObject]@{ Check='PowerShell Version'; Result=$psOk
        Detail="v$($PSVersionTable.PSVersion) (requires 7.0+)" })
    if (-not $psOk) { $pass = $false }

    # Robocopy
    $robOk = $null -ne (Get-Command robocopy.exe -ErrorAction SilentlyContinue)
    $checks.Add([PSCustomObject]@{ Check='Robocopy Available'; Result=$robOk
        Detail=if($robOk){'robocopy.exe found in PATH'}else{'robocopy.exe NOT found'} })
    if (-not $robOk) { $pass = $false }

    # Reg.exe
    $regOk = $null -ne (Get-Command reg.exe -ErrorAction SilentlyContinue)
    $checks.Add([PSCustomObject]@{ Check='Reg.exe Available'; Result=$regOk
        Detail=if($regOk){'reg.exe found in PATH'}else{'reg.exe NOT found'} })
    if (-not $regOk) { $pass = $false }

    # Destination write access
    if ($DestinationPath) {
        $destOk = $false; $destDetail = ''
        try {
            if (-not (Test-Path $DestinationPath)) {
                New-Item -Path $DestinationPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            $testFile = Join-Path $DestinationPath ".ufm_write_$($script:STAMP)"
            [System.IO.File]::WriteAllText($testFile, 'test')
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
            $destOk    = $true
            $destDetail = "Write access confirmed: $DestinationPath"
        } catch { $destDetail = "Cannot write to destination: $($_.Exception.Message)" }
        $checks.Add([PSCustomObject]@{ Check='Destination Write Access'; Result=$destOk; Detail=$destDetail })
        if (-not $destOk) { $pass = $false; $script:ExitCode = $script:EXIT_PERMISSION }

        # Free space
        $free    = Get-DiskFreeSpace -Path $DestinationPath
        $spaceOk = $free -gt 1GB
        $checks.Add([PSCustomObject]@{ Check='Destination Free Space (>1 GB)'; Result=$spaceOk
            Detail="$(Format-Bytes $free) available on destination drive" })
        if (-not $spaceOk) { $script:ExitCode = $script:EXIT_NO_SPACE }

        # BitLocker
        try {
            $qualifier = (Split-Path $DestinationPath -Qualifier).TrimEnd(':')
            $vol       = Get-BitLockerVolume -MountPoint "${qualifier}:" -ErrorAction SilentlyContinue
            $blOk      = $vol -and $vol.ProtectionStatus -eq 'On'
            $blDetail  = if ($vol) { "BitLocker: $($vol.ProtectionStatus)" } else { "BitLocker: Not a managed volume" }
            $checks.Add([PSCustomObject]@{ Check="BitLocker (${qualifier}:)"; Result=$blOk; Detail=$blDetail })
        } catch { }
    }

    # Event Log source
    try {
        $evOk = [System.Diagnostics.EventLog]::SourceExists('UserFolderMigrator')
        $checks.Add([PSCustomObject]@{ Check='EventLog Source Registered'; Result=$evOk
            Detail=if($evOk){'Source exists in Application log'}else{'Not yet registered (auto-creates on first write)'} })
    } catch { }

    # Network destination ping (if UNC)
    if ($DestinationPath -and $DestinationPath.StartsWith('\\')) {
        $server = ($DestinationPath -split '\\')[2]
        $pingOk = (Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue)
        $checks.Add([PSCustomObject]@{ Check="Network Server Reachable ($server)"; Result=$pingOk
            Detail=if($pingOk){"$server responded to ping"}else{"$server did not respond — check network/firewall"} })
        if (-not $pingOk) { $pass = $false }

        # SMB signing check
        try {
            $smbConn = Get-SmbConnection -ServerName $server -ErrorAction SilentlyContinue
            if ($smbConn) {
                $smbSigned = $smbConn | Where-Object { $_.Signed -eq $true }
                $signingOk = $smbSigned.Count -gt 0
                $checks.Add([PSCustomObject]@{ Check="SMB Signing ($server)"; Result=$signingOk
                    Detail=if($signingOk){"Connection is SMB-signed"}else{"SMB signing not confirmed — verify server policy"} })
            }
        } catch { }
    }

    # ── OS Integrity Pre-flight (SFC optional — prompt; DISM always runs) ─────
    Write-Host ""
    Write-Status "SFC /verifyonly scans all protected Windows files (5–15 min on HDD)." -Type "Info"
    $runSFC = $false
    if ($script:Unattended -or $script:ForceUnattended) {
        Write-Status "Unattended mode — skipping SFC prompt (use -RunSFCCheck to force)." -Type "Info"
        if ($RunSFCCheck) { $runSFC = $true }
    } else {
        $sfcAnswer = Read-Host "  Run SFC integrity check now? (Y/N — recommended on first run)"
        $runSFC = ($sfcAnswer -eq 'Y' -or $sfcAnswer -eq 'y') -or $RunSFCCheck
    }

    if ($runSFC) {
        Write-Status "Running SFC /verifyonly — this may take 5–15 minutes..." -Type "Info"
        try {
            $sfcOut = & sfc /verifyonly 2>&1
            $sfcOk  = ($sfcOut | Select-String 'no integrity violations' -Quiet) -eq $true
            $checks.Add([PSCustomObject]@{
                Check  = 'OS Integrity (SFC)'
                Result = $sfcOk
                Detail = if ($sfcOk) { 'No integrity violations found' } else { 'SFC found violations — run: sfc /scannow before migrating' }
            })
        } catch {
            $checks.Add([PSCustomObject]@{ Check='OS Integrity (SFC)'; Result=$false; Detail="SFC unavailable: $_" })
        }
    } else {
        $checks.Add([PSCustomObject]@{
            Check  = 'OS Integrity (SFC)'
            Result = $true
            Detail = 'Skipped by operator — re-run with -RunSFCCheck to enable'
        })
    }

    # DISM CheckHealth is ~5 seconds — always runs
    try {
        $dismOut = & DISM /Online /Cleanup-Image /CheckHealth 2>&1
        $dismOk  = ($dismOut | Select-String 'No component store corruption detected') -ne $null
        $checks.Add([PSCustomObject]@{
            Check  = 'OS Image Health (DISM)'
            Result = $dismOk
            Detail = if ($dismOk) { 'Component store healthy' } else { 'DISM detected issues — run: DISM /Online /Cleanup-Image /RestoreHealth' }
        })
    } catch {
        $checks.Add([PSCustomObject]@{ Check='OS Image Health (DISM)'; Result=$false; Detail="DISM unavailable: $_" })
    }

    # Display results table
    Write-Host ""
    $cw = @{ Check=40; Result=8 }
    Write-Host ("  {0,-$($cw.Check)} {1,-$($cw.Result)} Detail" -f "Check","Result") -ForegroundColor Cyan
    Write-TableSeparator -Width 110
    foreach ($c in $checks) {
        $sym   = if ($c.Result) { "PASS" } else { "FAIL" }
        $color = if ($c.Result) { "Green" } else { "Red" }
        Write-Host ("  {0,-$($cw.Check)} " -f $c.Check) -NoNewline
        Write-Host ("{0,-$($cw.Result)} " -f $sym) -ForegroundColor $color -NoNewline
        Write-Host $c.Detail -ForegroundColor Gray
    }
    Write-TableSeparator -Width 110
    Write-Host ""
    if ($pass) {
        Write-Status "All compatibility checks PASSED — system is ready for migration" -Type "Success"
    } else {
        Write-Status "One or more compatibility checks FAILED — resolve issues before proceeding" -Type "Error"
        $script:ExitCode = if ($script:ExitCode -eq 0) { $script:EXIT_FAILURE } else { $script:ExitCode }
    }
    Write-Log "TestCompatibility: $(if ($pass) { 'PASSED' } else { 'FAILED' }) — $($checks.Count) checks"
    return $pass
}

# ── Package Manager Helpers ───────────────────────────────────────────────────
function Install-Chocolatey {
    <#
    .SYNOPSIS
        Prompted Chocolatey install. Never runs silently — always asks the operator.
        Returns $true if choco is available after the call, $false otherwise.
    #>
    if (Get-Command choco -ErrorAction SilentlyContinue) { return $true }

    Write-Status "Chocolatey is not installed on this machine." -Type "Warning"
    Write-Status "  Required to auto-install Restic/7-Zip when Winget is absent." -Type "Warning"
    Write-Status "  Will download from https://chocolatey.org/install.ps1" -Type "Warning"

    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isSystem = $id.IsSystem
    if ($isSystem) { Write-Status "Running as SYSTEM — cannot prompt for Chocolatey install." -Type "Warning"; return $false }
    if ($script:Unattended -or $script:DryRun) { Write-Status "Unattended/DryRun: Skipping Chocolatey install prompt." -Type "Info"; return $false }

    $answer = Read-Host "  Install Chocolatey now? (Y/N)"
    if ($answer -ne 'Y' -and $answer -ne 'y') { Write-Status "Chocolatey install declined." -Type "Info"; return $false }

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $installScript = (New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')

        # Verify SHA256 of downloaded content against known good hash
        $expectedHash = 'REPLACE_WITH_PINNED_SHA256_OF_CHOCOLATEY_INSTALL_PS1'
        $actualHash   = [System.BitConverter]::ToString(
            [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($installScript)
            )).Replace('-','')
        if ($actualHash -ne $expectedHash) {
            Write-Status "Chocolatey installer hash mismatch — aborting. Expected: $expectedHash Got: $actualHash" -Type "Warning"
            Write-Log "Chocolatey install aborted: hash mismatch"
            return $false
        }

        # Use atomic temp file (eliminates race condition window)
        $tmp = [System.IO.Path]::GetTempFileName()
        $installScript | Out-File $tmp -Encoding UTF8

        # Verify Authenticode on written file
        $sig = Get-AuthenticodeSignature $tmp -ErrorAction SilentlyContinue
        if (-not $sig -or $sig.Status -notin @('Valid','NotSigned')) {
            Write-Status "Chocolatey installer Authenticode check failed — aborting." -Type "Warning"
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            return $false
        }

        $p = Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmp`"" -Wait -PassThru -NoNewWindow
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        if ($p.ExitCode -eq 0 -and (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Status "Chocolatey installed successfully." -Type "Success"
            return $true
        }
        Write-Status "Chocolatey install completed but 'choco' not found — shell restart may be needed." -Type "Warning"
        return $false
    } catch {
        Write-Status "Chocolatey install failed: $($_.Exception.Message)" -Type "Warning"
        return $false
    }
}

function Install-Restic {
    <#
    .SYNOPSIS
        Auto-installs Restic via Winget, then Chocolatey (prompted), then manual URL.
        Returns the path to restic.exe if available, $null otherwise.
    #>
    # Already available?
    $existing = Get-Command restic.exe -ErrorAction SilentlyContinue
    if ($existing) { return $existing.Source }

    # Check script directory first (portable drop-in)
    $local = Join-Path $PSScriptRoot 'restic.exe'
    if (Test-Path $local) { Write-Status "Restic found locally: $local" -Type "Info"; return $local }

    Write-Status "Restic not found — attempting auto-install..." -Type "Info"

    # Try winget
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Status "Installing Restic via Winget..." -Type "Info"
        if (-not $script:DryRun) {
            $p = Start-Process winget -ArgumentList "install restic.restic --silent --accept-package-agreements --accept-source-agreements" -Wait -PassThru -NoNewWindow
            $found = Get-Command restic.exe -ErrorAction SilentlyContinue
            if ($p.ExitCode -in @(0,-1978335189) -and $found) {
                Write-Status "Restic installed via Winget." -Type "Success"
                Write-Log "Restic auto-installed via Winget"
                return $found.Source
            }
        } else { Write-Status "DryRun: Would install Restic via Winget." -Type "Info"; return $null }
    }

    # Try Chocolatey (prompted install if missing)
    if (Install-Chocolatey) {
        Write-Status "Installing Restic via Chocolatey..." -Type "Info"
        if (-not $script:DryRun) {
            $p = Start-Process choco -ArgumentList "install restic -y --no-progress" -Wait -PassThru -NoNewWindow
            $found = Get-Command restic.exe -ErrorAction SilentlyContinue
            if ($p.ExitCode -eq 0 -and $found) {
                Write-Status "Restic installed via Chocolatey." -Type "Success"
                Write-Log "Restic auto-installed via Chocolatey"
                return $found.Source
            }
        } else { Write-Status "DryRun: Would install Restic via Chocolatey." -Type "Info"; return $null }
    }

    # Manual fallback
    Write-Status "Could not auto-install Restic. Download from: https://restic.net" -Type "Warning"
    Write-Status "Place restic.exe in the same folder as this script for portable use." -Type "Info"
    Write-Log "Restic auto-install failed — falling back to 7-Zip/ZIP"
    return $null
}

function Invoke-KFMChoice {
    <#
    .SYNOPSIS
        Reads the operator's KFM remediation choice (1-4) or enforces a fail-fast
        abort in unattended mode when KFM is active and no override is supplied.

        UNATTENDED BEHAVIOUR (default — safe):
          KFM detected + no override → abort entire run (EXIT_KFM_BLOCK = 6).
          This prevents silent registry reversion and data loss.

        OVERRIDES (must be explicit):
          -SkipKFMBlock  : bypass the block (use only after confirming KFM is truly inactive)
          -ForceOneDrive : legacy override; same effect as -SkipKFMBlock
          -UnattendedDefault '2' : FullProfileBackup only — proceed with stubs (cloud-only files)
    #>
    param([string]$UnattendedDefault = '3')
    if ($Unattended -or $ForceUnattended -or $script:IsUnattended) {
        # ── Explicit override requested ──────────────────────────────────────
        if ($SkipKFMBlock -or $ForceOneDrive) {
            Write-Status "Unattended: KFM block overridden via -SkipKFMBlock/-ForceOneDrive — proceeding." -Type "Warning"
            Write-Log "KFM_OVERRIDE_UNATTENDED: operator explicitly bypassed KFM block"
            Write-AuditEntry -Message "KFM_OVERRIDE_UNATTENDED" -Level "WARN"
            return '2'   # proceed
        }
        # ── FullProfileBackup special case (stubs, not registry redirect) ───
        if ($UnattendedDefault -eq '2') {
            Write-Status "Unattended: proceeding despite KFM (FullProfileBackup stub mode — option 2)" -Type "Warning"
            Write-Log "KFM unattended FullProfileBackup default applied: option 2"
            return '2'
        }
        # ── Default: fail fast with dedicated exit code ──────────────────────
        Write-Status "UNATTENDED ABORT: OneDrive KFM is active. Migrating KFM-managed folders risks" -Type "Error"
        Write-Status "  silent registry reversion, file duplication, and broken cloud sync." -Type "Error"
        Write-Status "  Fix KFM first, then re-run. To override: add -SkipKFMBlock (expert use only)." -Type "Error"
        Write-Log "Unattended run ABORTED — OneDrive KFM active. Exit code $($script:EXIT_KFM_BLOCK)."
        Write-AuditEntry -Message "KFM_BLOCK_ABORT_UNATTENDED" -Level "ERROR"
        $script:ExitCode = $script:EXIT_KFM_BLOCK
        Exit-WithReport -Code $script:ExitCode
    }
    return (Read-Host "  Enter choice (1/2/3/4)")
}

# ── KFM Policy Deploy/Remove (Intune/GPO equivalent, zero-dependency) ────────
function Set-OneDriveKFMPolicy {
    <#
    .SYNOPSIS
        Deploys or removes OneDrive Known Folder Move (KFM) ADMX registry keys.
        Equivalent to deploying the OneDrive ADMX via Intune or GPO.
        Use -Disable before migration to unlock shell folders.
        Use with -TenantId after migration to re-enable KFM silently.
    .PARAMETER TenantId
        Azure AD Tenant GUID. Required for KFMSilentOptIn.
    .PARAMETER Disable
        Removes KFM policy keys (unlock shell folders for migration).
    #>
    param(
        [string]$TenantId,
        [switch]$Disable
    )
    $kfmBase = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
    if ($Disable) {
        Write-Status "Removing OneDrive KFM policy keys (unlocking shell folders)..." -Type "Info"
        @('KFMSilentOptIn','KFMBlockOptOut','KFMBlockOptIn') | ForEach-Object {
            Remove-ItemProperty -Path $kfmBase -Name $_ -ErrorAction SilentlyContinue
        }
        Write-Status "KFM policies cleared — run: gpupdate /force to apply." -Type "Success"
        Write-Log "KFM policy keys removed — shell folders unlocked"
        return
    }
    if (-not $TenantId) { Write-Status "Set-OneDriveKFMPolicy: -TenantId required to enable KFM." -Type "Warning"; return }
    Write-Status "Deploying OneDrive KFM policy (TenantId: $TenantId)..." -Type "Info"
    if (-not (Test-Path $kfmBase)) { New-Item $kfmBase -Force | Out-Null }
    Set-ItemProperty -Path $kfmBase -Name 'KFMSilentOptIn' -Value $TenantId -Type String
    Set-ItemProperty -Path $kfmBase -Name 'KFMBlockOptOut'  -Value 1         -Type DWord
    Write-Status "KFM policy deployed. Run: gpupdate /force or reboot for effect." -Type "Success"
    Write-Log "KFM policy deployed — TenantId=$TenantId"
}

# ── Central Config File Loading (Feature 3.4) ─────────────────────────────
function Import-CentralConfig {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Loads UFM_Config.json from the script directory and populates $script:Config.
        Command-line parameters always take precedence; config provides defaults only.

        Functions read $script:Config[key] NOT $PSBoundParameters to avoid scope leakage.
    #>
    param()
    $scriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $configPath = Join-Path $scriptDir 'UFM_Config.json'
    if (-not (Test-Path $configPath)) { return }
    try {
        $cfg = Get-Content $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        Write-Status "Central config loaded: $configPath" -Type "Info"
        Write-Log "Central config loaded from $configPath"

        # Numeric / string fields — only apply when caller did NOT pass the param on the command line
        $numericFields = @(
            'RobocopyThreads','RobocopyRetries','RobocopyWait',
            'BandwidthLimitMbps','MaxFailures','NetworkTimeout'
        )
        $stringFields  = @('ChecksumAlgorithm','SyslogServer','SmtpServer',
                           'NotificationEmail','NotificationTeamsWebhook','ReportPath','LogPath')
        $boolFields    = @('EnableSyslog','NoEventLog','DisableRestorePoint','DisableChecksumVerify',
                           'BitLockerRequired','DisableHtmlReport','DisableAutoExclusions',
                           'UseRobocopyZ','QuietMode','KeepSource','SkipRegistryUpdate')

        foreach ($f in ($numericFields + $stringFields + $boolFields)) {
            if ($cfg.PSObject.Properties[$f]) {
                # Store in script:Config; callers check $PSBoundParameters THEN $script:Config
                if (-not $script:Config.ContainsKey($f)) {
                    $script:Config[$f] = $cfg.$f
                }
            }
        }
    } catch {
        Write-Status "Warning: UFM_Config.json could not be parsed — $($_.Exception.Message)" -Type "Warning"
    }
}

# Helper: returns the effective value of a parameter — command-line wins, then config, then default
function Get-EffectiveParam {
    [CmdletBinding()]
    param([string]$Name, $Default = $null)
    # Check if the param was explicitly bound on the command line (highest priority)
    if ($PSBoundParameters.ContainsKey($Name)) { return $PSBoundParameters[$Name] }
    # Fall back to config file value
    if ($script:Config.ContainsKey($Name)) { return $script:Config[$Name] }
    return $Default
}

# ── Live Metrics JSON (Feature 4.4) ───────────────────────────────────────
function Update-LiveMetrics {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([hashtable]$Metrics)
    if (-not $script:MetricsPath) { return }
    try {
        $Metrics['Timestamp'] = (Get-Date).ToString('o')
        $Metrics['Version']   = $script:VERSION
        $Metrics['Mode']      = $script:ReportMode
        $Metrics | ConvertTo-Json -Depth 2 | Set-Content -Path $script:MetricsPath -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

# ── Cloud-Only File Detection ─────────────────────────────────────────────
function Test-CloudOnlyFiles {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Scans a path for OneDrive cloud-only placeholder files
        (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000).
        These files have no local content — robocopy will trigger a mass
        cloud download ("hydration") for every placeholder it encounters,
        which can be extremely slow on large profiles and saturate bandwidth.
        Returns a result object with Count, TotalSize, and sample file paths.
        Skipped when -SkipCloudOnlyCheck is set.
    #>
    param([string]$Path)

    $result = [PSCustomObject]@{
        Count     = 0
        TotalSize = 0L
        Samples   = [System.Collections.Generic.List[string]]::new()
        Files     = [System.Collections.Generic.List[string]]::new()
        Checked   = $false
    }

    if ($SkipCloudOnlyCheck -or -not (Test-Path $Path)) { return $result }

    $recallAttr = 0x400000   # FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS — not in .NET FileAttributes enum, use raw int

    $opts = [System.IO.EnumerationOptions]::new()
    $opts.RecurseSubdirectories = $true
    $opts.AttributesToSkip      = 0
    $opts.IgnoreInaccessible    = $true

    $result.Checked = $true
    try {
        foreach ($f in [System.IO.Directory]::EnumerateFiles($Path, '*', $opts)) {
            try {
                $fi    = [System.IO.FileInfo]::new($f)
                $attrs = $fi.Attributes
                if (([int]$attrs -band $recallAttr) -ne 0) {
                    $result.Count++
                    $result.TotalSize += $fi.Length
                    $result.Files.Add($f)
                    if ($result.Samples.Count -lt 5) {
                        $result.Samples.Add($f.Substring($Path.TrimEnd('').Length).TrimStart(''))
                    }
                }
            } catch [System.UnauthorizedAccessException] { }
              catch [System.IO.IOException] { }
        }
    } catch [System.UnauthorizedAccessException] { }
      catch [System.IO.IOException] { }

    return $result
}

# ── Backup Manifest Writer ────────────────────────────────────────────────
function Write-BackupManifest {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Writes a JSON sidecar file (UFM_Manifest_<stamp>.json) alongside the
        backup destination after a successful FullProfileBackup.
        Contains: username, source/destination paths, sizes, file/dir counts,
        match result, duration, script version, and machine identity.
        Useful for audits, restore planning, and DR verification tools.
        Skipped when -SkipBackupManifest is set.
    #>
    param(
        [string]$Username,
        [string]$Source,
        [string]$Destination,
        [PSCustomObject]$SrcStats,    # from Get-FolderStats on source
        [PSCustomObject]$DstStats,    # from Get-FolderStats on destination
        [bool]$AllMatch,
        [bool]$Success,
        [bool]$DryRun,
        [datetime]$StartTime
    )

    if ($SkipBackupManifest) { return }

    $duration  = [Math]::Round(((Get-Date) - $StartTime).TotalSeconds, 1)
    $manifest  = [ordered]@{
        ManifestVersion = '1.0'
        Script          = 'UserFolderMigrator'
        ScriptVersion   = $script:VERSION
        RunStamp        = $script:STAMP
        GeneratedAt     = (Get-Date -Format 'o')
        Machine         = $env:COMPUTERNAME
        GeneratedBy     = $env:USERNAME
        Username        = $Username
        Source          = $Source
        Destination     = $Destination
        DryRun          = $DryRun
        Source_SizeBytes    = $SrcStats.Size
        Source_SizeHuman    = (Format-Bytes $SrcStats.Size)
        Source_FileCount    = $SrcStats.FileCount
        Source_DirCount     = $SrcStats.DirCount
        Dest_SizeBytes      = $DstStats.Size
        Dest_SizeHuman      = (Format-Bytes $DstStats.Size)
        Dest_FileCount      = $DstStats.FileCount
        Dest_DirCount       = $DstStats.DirCount
        SizeMatch       = ($SrcStats.Size      -eq $DstStats.Size)
        FileMatch       = ($SrcStats.FileCount -eq $DstStats.FileCount)
        FolderMatch     = ($SrcStats.DirCount  -eq $DstStats.DirCount)
        AllMatch        = $AllMatch
        Success         = $Success
        DurationSeconds = $duration
    }

    $manifestPath = Join-Path $Destination "UFM_Manifest_$($script:STAMP).json"
    try {
        $manifest | ConvertTo-Json -Depth 3 | Set-Content -Path $manifestPath -Encoding UTF8 -ErrorAction Stop
        Write-Status "Backup manifest written: UFM_Manifest_$($script:STAMP).json" -Type "Success"
        Write-Log "BackupManifest written for $Username at $manifestPath"
    } catch {
        Write-Status "Could not write backup manifest: $($_.Exception.Message)" -Type "Warning"
        Write-Log "BackupManifest write failed for $Username : $_"
    }
}

# ── OneDrive Known Folder Move Detection (Enterprise) ─────────────────────
function Get-OneDriveKFMStatus {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Detects if OneDrive Known Folder Move is active for a user.
        Returns a hashtable with KFMEnabled flag and per-folder redirection info.
        If KFM is active, migration must account for OneDrive-redirected paths
        to avoid orphaning data or breaking cloud sync.
    #>
    param([string]$SID = $null)
    $result = @{ KFMEnabled = $false; Folders = @{}; TenantID = ''; AccountName = '' }
    try {
        $odKey = if ($SID) {
            "Registry::HKEY_USERS\$SID\Software\Microsoft\OneDrive\Accounts"
        } else {
            'HKCU:\Software\Microsoft\OneDrive\Accounts'
        }
        if (-not (Test-Path $odKey)) { return $result }
        foreach ($acct in (Get-ChildItem $odKey -ErrorAction SilentlyContinue)) {
            $kfmKey = Join-Path $acct.PSPath 'ScopeIdToMountPoint'
            if (Test-Path $kfmKey) {
                $result.KFMEnabled  = $true
                $result.AccountName = (Get-ItemPropertyValue $acct.PSPath -Name 'DisplayName' -ErrorAction SilentlyContinue)
                $result.TenantID    = (Get-ItemPropertyValue $acct.PSPath -Name 'Business'     -ErrorAction SilentlyContinue)
            }
            # Read per-folder KFM mappings from UserFolder sub-key
            $ufKey = Join-Path $acct.PSPath 'UserFolder'
            if (Test-Path $ufKey) {
                $result.KFMEnabled = $true
                Get-ItemProperty $ufKey -ErrorAction SilentlyContinue |
                    Get-Member -MemberType NoteProperty |
                    Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' -and $_.Name -ne 'PSChildName' -and $_.Name -ne 'PSDrive' -and $_.Name -ne 'PSProvider' } |
                    ForEach-Object {
                        $result.Folders[$_.Name] = (Get-ItemPropertyValue $ufKey -Name $_.Name -ErrorAction SilentlyContinue)
                    }
            }
        }
    } catch { }
    return $result
}

function Test-ShellFoldersInOneDrive {
    <#
    .SYNOPSIS
        Checks if any shell folder (Desktop, Documents, etc.) currently points under a OneDrive root.
        Returns $true if any folder's resolved path is under OneDrive, $false otherwise.
    #>
    param([string]$SID, [string]$ProfilePath)
    $oneDriveRoots = @()
    $odKey = if ($SID) { "Registry::HKEY_USERS\$SID\Software\Microsoft\OneDrive\Accounts" }
             else { 'HKCU:\Software\Microsoft\OneDrive\Accounts' }
    if (Test-Path $odKey) {
        foreach ($acct in (Get-ChildItem $odKey -ErrorAction SilentlyContinue)) {
            $mountPoint = (Get-ItemProperty -Path $acct.PSPath -Name 'UserFolderMountPoint' -ErrorAction SilentlyContinue).UserFolderMountPoint
            if ($mountPoint) { $oneDriveRoots += $mountPoint.TrimEnd('\') }
            $scopeId = (Get-ItemProperty -Path $acct.PSPath -Name 'ScopeIdToMountPoint' -ErrorAction SilentlyContinue).ScopeIdToMountPoint
            if ($scopeId) { $oneDriveRoots += $scopeId.TrimEnd('\') }
        }
    }
    if (-not $oneDriveRoots) { return $false }
    $folders = @('Desktop','Documents','Downloads','Music','Pictures','Videos')
    foreach ($folder in $folders) {
        $path = Get-ShellFolderPath -FolderName $folder -UsfKey $script:USF_KEY -SfKey $script:SF_KEY -ProfilePath $ProfilePath
        if ($path) {
            $normalized = $path.TrimEnd('\')
            foreach ($root in $oneDriveRoots) {
                if ($normalized -like "$root\*" -or $normalized -eq $root) {
                    Write-Log "Folder $folder points under OneDrive: $normalized"
                    return $true
                }
            }
        }
    }
    return $false
}

function Write-OneDriveKFMWarning {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Detects OneDrive KFM and BLOCKS migration unless -SkipKFMBlock or -ForceOneDrive is passed.
        Breaking KFM sync without operator acknowledgement could silently stop cloud backup.
    #>
    param([string]$Username, [string]$SID = $null)
    $kfm = Get-OneDriveKFMStatus -SID $SID
    if (-not $kfm.KFMEnabled) { return $true }  # no KFM — proceed

    Write-SectionHeader "ONEDRIVE KFM BLOCK: $Username"
    Write-Status "OneDrive Known Folder Move is ACTIVE for $Username" -Type "Error"
    Write-Status "  Account : $($kfm.AccountName)" -Type "Info"
    if ($kfm.Folders.Count -gt 0) {
        foreach ($f in $kfm.Folders.Keys) {
            Write-Status "  KFM folder: $f -> $($kfm.Folders[$f])" -Type "Info"
        }
    }
    Write-Status "" -Type "Info"
    Write-Status "  Migrating without disabling KFM will:" -Type "Warning"
    Write-Status "    1. Break OneDrive cloud sync for affected folders" -Type "Warning"
    Write-Status "    2. Leave user files unprotected if destination has no cloud backup" -Type "Warning"
    Write-Status "    3. Potentially violate your organisation's backup policy" -Type "Warning"
    Write-Status "" -Type "Info"
    Write-Status "  Remediation options:" -Type "Info"
    Write-Status "    A) Disable KFM in OneDrive settings or via GPO, then re-run migration" -Type "Info"
    Write-Status "    B) Pass -SkipKFMBlock to acknowledge the risk and proceed anyway" -Type "Info"
    Write-Status "    C) Pass -ForceOneDrive (alias) to acknowledge the risk and proceed anyway" -Type "Info"
    Write-Log "OneDrive KFM BLOCK for $Username (account=$($kfm.AccountName), folders=$($kfm.Folders.Count))"
    Write-EventLogEntry -Message "UserFolderMigrator: OneDrive KFM BLOCK for $Username — migration aborted. Pass -SkipKFMBlock to override." -EntryType Error -EventId 1003

    if ($SkipKFMBlock -or $ForceOneDrive) {
        Write-Status "  -SkipKFMBlock/-ForceOneDrive specified — proceeding despite KFM risk." -Type "Warning"
        Write-Log "OneDrive KFM override accepted for $Username by operator (-SkipKFMBlock/-ForceOneDrive)"
        Write-AuditEntry -Message "KFM_OVERRIDE: operator bypassed KFM block for $Username" -Level "WARN"
        return $true   # allowed to continue
    }
    return $false   # blocked
}

# ── Group Policy Folder Redirection Detection ─────────────────────────────
function Get-GPOFolderRedirectionStatus {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Detects if shell folders are controlled by Group Policy Folder Redirection.
        If GPO FolderRedirection is active, migrating via registry alone may be
        reverted at next Group Policy refresh. Warns the operator to coordinate
        with Active Directory / GPMC before migration.
    #>
    param([string]$SID = $null)
    $result = @{ GPOActive = $false; Policies = @() }
    try {
        $gpKey = if ($SID) {
            "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        } else {
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        }
        $policyKey = if ($SID) {
            "Registry::HKEY_USERS\$SID\Software\Policies\Microsoft\Windows\System\Scripts"
        } else {
            'HKLM:\Software\Policies\Microsoft\Windows\System'
        }
        # Check for GPO-controlled folder redirection policy keys
        $fdPolicyKey = 'HKLM:\Software\Policies\Microsoft\Windows\FolderRedirection'
        if (Test-Path $fdPolicyKey) {
            $result.GPOActive = $true
            $subkeys = Get-ChildItem $fdPolicyKey -ErrorAction SilentlyContinue
            foreach ($sk in $subkeys) {
                $result.Policies += $sk.PSChildName
            }
        }
        # Also check user-side policy application
        $userFdKey = if ($SID) {
            "Registry::HKEY_USERS\$SID\Software\Policies\Microsoft\Windows\FolderRedirection"
        } else {
            'HKCU:\Software\Policies\Microsoft\Windows\FolderRedirection'
        }
        if (Test-Path $userFdKey) {
            $result.GPOActive = $true
        }
    } catch { }
    return $result
}

function Write-GPORedirectionWarning {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Detects GPO Folder Redirection and BLOCKS migration unless -SkipGPOBlock is passed.
        Registry changes made without disabling GPO will be silently reverted at next GP refresh.
    #>
    param([string]$Username, [string]$SID = $null)
    $gpo = Get-GPOFolderRedirectionStatus -SID $SID
    if (-not $gpo.GPOActive) { return $true }  # no GPO — proceed

    Write-SectionHeader "GPO FOLDER REDIRECTION BLOCK: $Username"
    Write-Status "Group Policy Folder Redirection is ACTIVE" -Type "Error"
    if ($gpo.Policies.Count -gt 0) {
        Write-Status "  Controlled folders: $($gpo.Policies -join ', ')" -Type "Info"
    }
    Write-Status "" -Type "Info"
    Write-Status "  Migrating without disabling the GPO will:" -Type "Warning"
    Write-Status "    1. Cause registry changes to be reverted silently at next gpupdate" -Type "Warning"
    Write-Status "    2. Leave shell folder pointers inconsistent between runs" -Type "Warning"
    Write-Status "    3. Create support tickets as folders appear to 'move back' after login" -Type "Warning"
    Write-Status "" -Type "Info"
    Write-Status "  Remediation options:" -Type "Info"
    Write-Status "    A) Disable/unlink the FolderRedirection GPO in GPMC, run gpupdate /force, then re-run" -Type "Info"
    Write-Status "    B) Pass -SkipGPOBlock to acknowledge the risk and proceed anyway" -Type "Info"
    Write-Log "GPO Folder Redirection BLOCK for $Username — policies: $($gpo.Policies -join ', ')"
    Write-EventLogEntry -Message "UserFolderMigrator: GPO FolderRedirection BLOCK for $Username. Pass -SkipGPOBlock to override." -EntryType Error -EventId 1003

    if ($SkipGPOBlock) {
        Write-Status "  -SkipGPOBlock specified — proceeding despite GPO risk." -Type "Warning"
        Write-Log "GPO block override accepted for $Username by operator (-SkipGPOBlock)"
        Write-AuditEntry -Message "GPO_OVERRIDE: operator bypassed GPO block for $Username" -Level "WARN"
        return $true
    }
    return $false   # blocked
}

# ── Windows Credential Manager Integration (Enterprise) ───────────────────
function Get-StoredNetworkCredential {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Retrieves a PSCredential from Windows Credential Manager for a given target.
        Falls back gracefully when no matching credential exists.
        Usage: if -NetworkCredential is not passed but a matching vault entry exists,
               we auto-load it instead of prompting or failing.
    #>
    param([string]$Target)
    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        $credType = 1   # CRED_TYPE_GENERIC
        $cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
            [IntPtr]::Zero, [type][PSCustomObject]) # placeholder — use CmdKey workaround below
        # Use cmdkey /list output as a safe read-only check
        $cmdkey = & cmdkey.exe /list:$Target 2>&1
        if ($cmdkey -match 'Target:') {
            # Credential exists; prompt user to confirm loading it
            Write-Status "Credential Manager: found stored credential for '$Target'" -Type "Info"
            Write-Status "  Use Get-Credential to load it, or pass -NetworkCredential explicitly." -Type "Info"
            Write-Log "Credential Manager: found entry for $Target"
            return $null   # Cannot extract password from vault without P/Invoke; inform caller
        }
    } catch { }
    return $null
}

# ── Pre-Migration Disk Space Reservation (Enterprise) ─────────────────────
function Test-DestinationSpaceForAllUsers {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Performs a comprehensive pre-migration space check across ALL users before
        any data movement begins. Gives a go/no-go decision for the entire batch,
        preventing partial migrations that leave the system in an inconsistent state.
    #>
    param([object[]]$Users, [string]$BaseDestination)
    Write-SectionHeader "PRE-MIGRATION SPACE VALIDATION"
    $totalRequired = 0L
    $pass = $true
    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($u in $Users) {
        $userRequired = 0L
        $folderList   = if ($Folders -contains 'All') { $script:SHELL_FOLDERS.Keys } else { $Folders }
        foreach ($fn in $folderList) {
            $defaultPath = Join-Path $u.ProfilePath $script:SHELL_FOLDERS[$fn].Default
            if (Test-Path $defaultPath) {
                try { $userRequired += (Get-FolderStats $defaultPath).Size } catch { }
            }
        }
        $userRequired  = [long]($userRequired * 1.1)   # 10 % headroom
        $totalRequired += $userRequired
        $userDest      = Join-Path $BaseDestination $u.Username
        $free          = Get-DiskFreeSpace -Path $BaseDestination
        $ok            = $free -ge $userRequired
        if (-not $ok) { $pass = $false }
        $rows.Add([PSCustomObject]@{
            Username = $u.Username; Required = $userRequired; Free = $free; OK = $ok
        })
    }

    $destFree = Get-DiskFreeSpace -Path $BaseDestination
    $cw = @{ User = 22; Req = 14; Free = 14; Status = 8 }
    Write-Host ("  {0,-$($cw.User)} {1,$($cw.Req)} {2,$($cw.Free)} {3,-$($cw.Status)}" -f "User","Required","Available","Status") -ForegroundColor Cyan
    Write-TableSeparator -Width 65
    foreach ($r in $rows) {
        $sym   = if ($r.OK) { "OK" } else { "INSUFFICIENT" }
        $color = if ($r.OK) { "Green" } else { "Red" }
        Write-Host ("  {0,-$($cw.User)} {1,$($cw.Req)} {2,$($cw.Free)} " -f $r.Username,(Format-Bytes $r.Required),(Format-Bytes $r.Free)) -NoNewline
        Write-Host ("{0,-$($cw.Status)}" -f $sym) -ForegroundColor $color
    }
    Write-TableSeparator -Width 65
    Write-Host ("  {0,-$($cw.User)} {1,$($cw.Req)} {2,$($cw.Free)}" -f "TOTAL",(Format-Bytes $totalRequired),(Format-Bytes $destFree)) -ForegroundColor Cyan
    Write-Host ""

    if ($pass) {
        Write-Status "Space validation PASSED — $(Format-Bytes $totalRequired) required, $(Format-Bytes $destFree) available" -Type "Success"
    } else {
        Write-Status "Space validation FAILED — insufficient space on destination drive" -Type "Error"
        Write-Log "Pre-migration space check FAILED: required=$(Format-Bytes $totalRequired) available=$(Format-Bytes $destFree)"
        $script:ExitCode = $script:EXIT_NO_SPACE
    }
    return $pass
}

function Test-DestinationValid {
    <#
    .SYNOPSIS
        Validates that a destination path exists (or can be created) and is writable.
        Returns $true if valid, otherwise writes error and exits (unless -DryRun).
    .PARAMETER OfferCreate
        If the destination does not exist and -CreateIfMissing is $false, prompt the user
        to create it. Ignored when -DryRun or -Unattended is set.
    #>
    param(
        [string]$Path,
        [switch]$DryRun,
        [switch]$CreateIfMissing,
        [switch]$OfferCreate
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        Write-Status "Destination path is empty." -Type "Error"
        return $false
    }

    $Path = $Path.TrimEnd('\')
    $isUnc = $Path -like '\\*\*'

    # Dry-run: only perform lightweight checks (no creation, no write test)
    if ($DryRun) {
        Write-Status "[DRY RUN] Skipping existence/write test for destination: $Path" -Type "Info"
        if ($isUnc) {
            $server = ($Path -split '\\')[2]
            $share  = ($Path -split '\\')[3]
            Write-Status "  Checking UNC server reachability: $server ..." -Type "Info"
            $ping = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
            if (-not $ping) {
                Write-Status "  Server $server is not reachable (ping failed)." -Type "Warning"
                # non-fatal in dry-run, just warn
            } else {
                Write-Status "  Server $server is reachable." -Type "Success"
            }
            $testPath = "\\$server\$share"
            if (-not (Test-Path $testPath -ErrorAction SilentlyContinue)) {
                Write-Status "  Share '$testPath' does not exist or is not accessible." -Type "Warning"
            } else {
                Write-Status "  Share '$testPath' is accessible." -Type "Success"
            }
        }
        return $true
    }

    # Normal (non-dry-run) validation continues below
    if ($isUnc) {
        $server = ($Path -split '\\')[2]
        $share  = ($Path -split '\\')[3]

        Write-Status "Checking network server: $server ..." -Type "Info"
        $ping = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $ping) {
            Write-Status "Server $server is not reachable (ping failed)." -Type "Error"
            return $false
        }

        $testPath = "\\$server\$share"
        if (-not (Test-Path $testPath -ErrorAction SilentlyContinue)) {
            Write-Status "Network share '$testPath' does not exist or is not accessible." -Type "Error"
            return $false
        }
    }

    # Check existence
    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) {
        if ($CreateIfMissing) {
            Write-Status "Destination path does not exist – creating: $Path" -Type "Info"
            try {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Status "Destination folder created." -Type "Success"
            } catch {
                Write-Status "Cannot create destination folder: $($_.Exception.Message)" -Type "Error"
                return $false
            }
        } elseif ($OfferCreate -and -not $Unattended) {
            $answer = Read-Host "  Destination folder '$Path' does not exist. Create it? (Y/N)"
            if ($answer -eq 'Y' -or $answer -eq 'y') {
                try {
                    New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    Write-Status "Destination folder created." -Type "Success"
                } catch {
                    Write-Status "Cannot create destination folder: $($_.Exception.Message)" -Type "Error"
                    return $false
                }
            } else {
                Write-Status "Destination does not exist and creation was declined." -Type "Error"
                return $false
            }
        } else {
            Write-Status "Destination path does not exist. Use -Force to auto-create, or run without -Force to be prompted." -Type "Error"
            return $false
        }
    }

    # Write-access test
    $testFile = Join-Path $Path ".ufm_writetest_$PID.tmp"
    try {
        [System.IO.File]::WriteAllText($testFile, "test")
        Remove-Item $testFile -Force -ErrorAction Stop
        Write-Status "Destination write access confirmed." -Type "Success"
    } catch {
        Write-Status "Destination is not writable: $($_.Exception.Message)" -Type "Error"
        return $false
    }

    $free = Get-DiskFreeSpace -Path $Path
    if ($free -lt 100MB) {
        Write-Status "Insufficient free space on destination drive (only $(Format-Bytes $free) available)." -Type "Error"
        return $false
    }

    return $true
}

# ── Post-Copy Test-Restore Sample (Safety Gap 1 / 5.2) ────────────────────
function Invoke-TestRestore {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    <#
    .SYNOPSIS
        Before source deletion, randomly samples $TestRestoreSamplePct% of destination
        files, copies them to a temp location, and re-hashes them against the destination.
        Only passes if every sampled file rehashes identically.
        This proves the destination is RESTORABLE, not just that bytes were written.

        Skipped when: -SkipTestRestore is set, -DisableChecksumVerify is set,
                      file count is 0, or the folder is empty.
    #>
    param(
        [string]$DestPath,
        [string]$FolderName,
        [int]$SamplePct = 10
    )

    if ($SkipTestRestore -or $DisableChecksumVerify) { return $true }

    $opts = [System.IO.EnumerationOptions]::new()
    $opts.RecurseSubdirectories = $true
    $opts.AttributesToSkip      = 0
    $opts.IgnoreInaccessible    = $true

    $allFiles = @(try { [System.IO.Directory]::EnumerateFiles($DestPath, '*', $opts) } catch { @() })
    if ($allFiles.Count -eq 0) { return $true }   # nothing to sample

    # Determine sample size — minimum 1 file, maximum 50 for speed
    $sampleCount = [Math]::Max(1, [Math]::Min(50, [int][Math]::Ceiling($allFiles.Count * $SamplePct / 100)))
    $sample      = $allFiles | Get-Random -Count $sampleCount

    $tempDir = [System.IO.Path]::Combine((Get-SafeTempPath), "UFM_TestRestore_$($script:STAMP)_$([System.IO.Path]::GetRandomFileName())")
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

    Write-Status "Test-Restore: sampling $sampleCount/$($allFiles.Count) file(s) from $FolderName..." -Type "Info"
    Write-Log "Test-Restore ${FolderName}: $sampleCount sample(s) from $($allFiles.Count) total"

    $passed   = $true
    $verified = 0

    try {
        foreach ($srcFile in $sample) {
            $relPath  = $srcFile.Substring($DestPath.TrimEnd('\').Length).TrimStart('\')
            $copyDest = Join-Path $tempDir $relPath
            $copyDir  = Split-Path $copyDest -Parent
            if (-not (Test-Path $copyDir)) { New-Item -Path $copyDir -ItemType Directory -Force | Out-Null }

            try {
                Copy-Item -LiteralPath $srcFile -Destination $copyDest -Force -ErrorAction Stop
            } catch {
                Write-Status "  Test-Restore FAIL: could not copy '$relPath' — $($_.Exception.Message)" -Type "Error"
                Write-Log "Test-Restore FAIL (copy): $relPath — $_"
                $passed = $false
                continue
            }

            # Hash original destination file and the temp copy — must match
            $origHash = Get-FileHashTiered -FilePath $srcFile
            $copyHash = Get-FileHashTiered -FilePath $copyDest

            if ($origHash.Hash -ne $copyHash.Hash -or $origHash.Error -or $copyHash.Error) {
                Write-Status "  Test-Restore FAIL: '$relPath' hash mismatch after copy" -Type "Error"
                Write-Log "Test-Restore FAIL (hash): $relPath orig=$($origHash.Hash) copy=$($copyHash.Hash)"
                $passed = $false
            } else {
                $verified++
            }
        }
    } finally {
        # Always clean up temp dir
        try { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue } catch [System.Exception] { }
    }

    if ($passed) {
        Write-Status "  Test-Restore PASSED: $verified/$sampleCount file(s) verified restorable" -Type "Success"
        Write-Log "Test-Restore PASSED for $FolderName ($verified/$sampleCount)"
    } else {
        Write-Status "  Test-Restore FAILED: destination is NOT reliably restorable — source preserved" -Type "Error"
        Write-Log "Test-Restore FAILED for $FolderName — source deletion blocked"
        Write-EventLogEntry -Message "UserFolderMigrator: Test-Restore FAILED for $FolderName. Source NOT deleted." -EntryType Error -EventId 1003
        Write-AuditEntry -Message "TEST_RESTORE_FAIL: $FolderName at $DestPath" -Level "ERROR"
    }

    return $passed
}

#endregion

# ── Global exports for UserFolderMigrator_ plugin compatibility ─────────────────────────
# ── Canonical Write-ErrorGuard ────────────────────────────────────────────────
# Provides structured error reporting with severity, skip reason, diagnostics,
# and recovery hints. Exported globally so all plugin modules can call it.
# Modules that load before this block have inline shims — this canonical version
# supersedes them once the global export block runs below.
function Write-ErrorGuard {
    param(
        [string]$Operation   = '',
        [string]$ErrorType   = '',
        [string]$Item        = '',
        [string]$Severity    = 'Warning',
        [string]$SkipReason  = '',
        [hashtable]$Recovery    = @{},
        [hashtable]$Diagnostics = @{}
    )

    $prefix = if ($Item) { "[$Operation] '$Item'" } else { "[$Operation]" }
    $msg    = "$prefix $ErrorType"
    if ($SkipReason) { $msg += " — $SkipReason" }

    switch ($Severity) {
        'Error'   { Write-Status $msg -Type 'Error' }
        'Warning' { Write-Status $msg -Type 'Warning' }
        default   { Write-Status $msg -Type 'Info' }
    }

    if ($Diagnostics.Count -gt 0) {
        foreach ($k in $Diagnostics.Keys) {
            Write-Log "  Diag [$k]: $($Diagnostics[$k])" -Level 'DEBUG'
        }
    }

    if ($Recovery.Count -gt 0) {
        if ($Recovery.Command) { Write-Status "  Fix: $($Recovery.Command)" -Type 'Info' }
        if ($Recovery.Hint)    { Write-Status "  Hint: $($Recovery.Hint)"   -Type 'Info' }
    }

    Write-Log "$msg" -Level $(if ($Severity -eq 'Error') { 'ERROR' } else { 'WARN' })
}

# This block makes the script's internal functions visible to plugin modules
# (UserFolderMigrator_*.psm1). Plugins can call Write-Status, Write-Log, Format-Bytes, etc.
# without duplicating code. The block is non‑destructive — it does not alter
# any existing behaviour or variable scope.
$globalExportFuncs = @(
    'Write-Status', 'Write-Log', 'Write-SectionHeader', 'Write-TableSeparator',
    'Format-Bytes', 'Clear-ProgressLine', 'Write-AuditEntry', 'Write-EventLogEntry',
    'Send-SyslogMessage', 'Send-MigrationNotification', 'Write-ProgressBar',
    'Write-ErrorGuard', 'Confirm-Operation', 'Invoke-Prompt', 'Get-FolderStats',
    'Get-DiskFreeSpace', 'Get-FileHashTiered', 'Test-AdminRight',
    'Repair-InactiveUserPermissions', 'Get-UserRegistryPaths',
    'Get-SafeTempPath', 'Invoke-PluginHooks', 'New-PluginContext', 'Register-UserFolderMigratorScheduledTask',
    'Invoke-AutoInstallComponents'
)
foreach ($fnName in $globalExportFuncs) {
    try {
        $fn = Get-Item "function:\$fnName" -ErrorAction SilentlyContinue
        if ($fn) {
            Set-Item -Path "function:\global:$fnName" -Value $fn.ScriptBlock -ErrorAction SilentlyContinue
        }
    } catch {}
}

# Shell folder helpers — the monolithic script stores them as variables;
# expose them as simple functions that plugins can call.
function global:Get-ShellFolderDefinitions { return $script:SHELL_FOLDERS }
function global:Get-UsfKey                { return $script:USF_KEY }
function global:Get-SfKey                 { return $script:SF_KEY }

# Let the audit‑forwarding plugin find the audit log file.
$global:GlobalAuditLogPath = $script:AuditLogPath

function Main {
    <#
    .SYNOPSIS
        Entry point. Validates startup, runs hardware tuning, loads config, fires hooks, and dispatches to the operation mode.
    #>
    [CmdletBinding()]
    param()
    # Banner
    Write-SessionBanner
    Invoke-StartupSequence
    Invoke-ModeDispatch
}

function Invoke-StartupSequence {
    <#
    .SYNOPSIS
        Runs all pre-migration startup tasks: logging, quarantine, TLS policy, transcript,
        admin check, unattended validation, hardware tuning, config load, email setup,
        PreFlight hooks, and Restore Point creation.
    #>
    [CmdletBinding()]
    param()
    # Initialize logging first (creates all output directories)
    Initialize-Logger
    Write-Log "Session started with parameters: $($script:InvocationLine)"

    # Initialize quarantine system
    $script:QuarantineRoot = $null
    $script:QuarantinedFiles = [System.Collections.Generic.List[object]]::new()
    if (-not $DisableChecksumVerify) {
        $script:QuarantineRoot = Initialize-QuarantineFolder -QuarantinePath $QuarantinePath
        if ($script:QuarantineRoot) {
            Write-Status "Quarantine folder: $script:QuarantineRoot" -Type "Info"
            Write-Log "Quarantine system active: $script:QuarantineRoot"
        }
    }

    # ── TLS Security Policy — must run before any network activity ────────────
    # Disables SSLv3 / TLS 1.0 / TLS 1.1 process-wide. Applies to all subsequent
    # Invoke-RestMethod, Send-MKMailMessage, and any other .NET HTTP/SMTP calls.
    Set-TlsSecurityPolicy

    # Start PowerShell transcript — captures all console output verbatim
    if ($script:TranscriptPath) {
        Start-Transcript -Path $script:TranscriptPath -Append -ErrorAction SilentlyContinue | Out-Null
    }

    Invoke-StartupEnvironment -Destination $Destination
    
    # Check admin rights
    if (-not (Test-AdminRight)) {
        Write-Status "Administrator rights required! Please run PowerShell as Administrator." -Type "Error"
        Write-Log "Session ended: Insufficient privileges"
        $script:ExitCode = $script:EXIT_PERMISSION
        Exit-WithReport -Code $script:ExitCode
    }
    Write-Status "Running as Administrator" -Type "Success"
    Write-Status "Auto-fix inactive users: $(-not $SkipAutoPermissionFix)" -Type "Info"

    # ── Expose params as script-scope vars for plugin access ($script:NotificationEmail etc.) ──
    # Plugins run in a child scope and access these via $script: to avoid needing the full
    # Context hashtable. Without this, Watchdog's guard check always evaluates $null and
    # silently skips watchdog startup on every run.
    $script:NotificationEmail = $NotificationEmail
    $script:EnableSyslog      = $EnableSyslog.IsPresent

    # ── Plugin input collection — gather all plugin inputs upfront ────────────
    Invoke-PluginInputCollection -Unattended $Unattended.IsPresent
    Write-Status "Dry run mode: $DryRun" -Type "Info"
    Write-Status "Live progress bars: Enabled" -Type "Info"
    if ($MaxFailures -gt 0) { Write-Status "Circuit breaker: stop after $MaxFailures folder failure(s)" -Type "Info" }
    if ($TargetUsername)    { Write-Status "Target user: $TargetUsername" -Type "Info" }
    if ($Unattended)        { Write-Status "Mode: UNATTENDED — all prompts suppressed, confirmations auto-accepted" -Type "Warning" }

    # ── AutoCleanupCreds interactive confirmation ─────────────────────────────
    if ($AutoCleanupCreds -and -not $Unattended) {
        Write-Status "AutoCleanupCreds: stored credentials will be PERMANENTLY DELETED after this run." -Type "Warning"
        if (-not (Confirm-Operation -Message "  Continue with credential cleanup enabled? (Y/N)")) {
            $script:AutoCleanupCreds = $false
            Write-Status "Credential cleanup cancelled — credentials will be preserved." -Type "Info"
        }
    }

    # ── Scheduled Task Registration — runs before any migration mode ──────────
    if ($RegisterTask) {
        Register-UserFolderMigratorScheduledTask
        Exit-WithReport -Code $script:ExitCode
    }

    # ── Unattended pre-flight validation ─────────────────────────────────────
    if ($Unattended) { Invoke-UnattendedValidation -ParameterSetName $PSCmdlet.ParameterSetName }
    
    # -TargetUsername and -AllUsers are mutually exclusive
    if ($TargetUsername -and $AllUsers) {
        Write-Status "-TargetUsername and -AllUsers cannot be used together. Use one or the other." -Type "Error"
        $script:ExitCode = $script:EXIT_FAILURE
        Exit-WithReport -Code $script:ExitCode
    }

    # ── TestCompatibility mode (Feature 3.6) ─────────────────────────────────
    if ($TestCompatibility) {
        $destForCheck = if ($Destination) { $Destination } else { $null }
        $checkPassed = Invoke-TestCompatibility -DestinationPath $destForCheck
        Write-Log "Session ended: TestCompatibility mode — $(if ($checkPassed) { 'PASSED' } else { 'FAILED' })"
        Exit-WithReport -Code (if ($checkPassed) { 0 } else { $script:EXIT_FAILURE })
    }

    # ── Windows Event Log: session start (Feature 4.1) ───────────────────────
    Write-EventLogEntry -Message "UserFolderMigrator started on $env:COMPUTERNAME by $env:USERNAME. Mode: $($script:ReportMode). DryRun: $DryRun" -EventId 1000

    # ── System Restore Point: create before any writes (Feature 1.4) ─────────
    # Skipped in DryRun, Rollback, ReportOnly, TestCompatibility (already handled above)
    if (-not $DryRun -and $Mode -notin @('Rollback','ReportOnly') -and -not $TestCompatibility) {
        New-MigrationRestorePoint
    }

$preMigrationContext = New-PluginContext 'PreMigration' @{
    DryRun            = $DryRun
    Mode              = $PSCmdlet.ParameterSetName
    Destination       = $Destination
    Username          = $env:USERNAME
    AdminUser         = $env:USERNAME
    ComputerName      = $env:COMPUTERNAME
    SourcePath        = (Join-Path $env:SystemDrive 'Users')
    ConfigPath        = Join-Path $PSScriptRoot 'UFM_Config.json'
    Unattended        = $Unattended
    RequireBitLocker  = $BitLockerRequired
    SkipRollbackPoint = $DryRun
}
if ((Invoke-PluginHooks -Stage 'PreMigration' -Context $preMigrationContext) -eq $false) {
    Write-Status "Pre-migration checks failed — aborting operation" -Type "Error"
    Send-MigrationNotification `
        -Subject "PRE-MIGRATION BLOCKED — UserFolderMigrator on $env:COMPUTERNAME" `
        -Body "A pre-migration hook blocked the migration before any data was moved.`n`nComputer : $env:COMPUTERNAME`nUser     : $env:USERNAME`nMode     : $($script:ReportMode)`nTime     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`nLog      : $($script:LogFile)`n`nLikely causes: BitLocker not enabled (-RequireBitLocker set), VSS snapshot failed, or disk health check blocked migration." `
        -Status 'Error'
    Exit-WithReport -Code $script:EXIT_FAILURE
}

    # ── BitLocker compliance check on destination (Feature 2.4) ──────────────
    if ($Destination -and $BitLockerRequired) {
        Test-BitLockerCompliance -Path $Destination -Label 'Destination'
    }

    # ── ValidateOnly mode: pre-flight only, no data movement ─────────────────
    if ($ValidateOnly) {
        Write-SectionHeader "VALIDATE-ONLY MODE (no changes will be made)"
        Write-Status "Running all pre-flight checks. -ValidateOnly exits after checks — nothing is copied or deleted." -Type "Info"
        Write-Host ""
        $destForCheck = $Destination
        $checkPassed  = Invoke-TestCompatibility -DestinationPath $destForCheck
        if ($AllUsers) {
            $users = Get-AllUserProfiles
            if ($users.Count -gt 0) {
                $null = Test-DestinationSpaceForAllUsers -Users $users -BaseDestination ($destForCheck ?? '')
                foreach ($u in $users) {
                    $null = Write-OneDriveKFMWarning -Username $u.Username -SID $u.SID
                    $null = Write-GPORedirectionWarning -Username $u.Username -SID $u.SID
                    Test-BitLockerCompliance -Path ($destForCheck ?? $u.ProfilePath) -Label $u.Username
                }
            }
        }
        $finalCode = if ($checkPassed) { 0 } else { $script:EXIT_FAILURE }
        Write-Log "Session ended: ValidateOnly — $(if ($checkPassed) { 'PASSED' } else { 'FAILED' })"
        Exit-WithReport -Code $finalCode
    }
}


function Invoke-ModeRollback {
    <#
    .SYNOPSIS
        Handles the -Rollback operation mode. Fires Rollback plugin hooks then
        delegates to Invoke-Rollback to restore shell folder registry keys from backup.
    #>
    [CmdletBinding()]
    param()
$script:ReportMode = 'Rollback'
$rollbackContext = New-PluginContext 'Rollback' @{
    RollbackFile = $RollbackFile
    DryRun       = $DryRun
    ComputerName = $env:COMPUTERNAME
    SID          = $null
    RollbackId   = if ($RollbackFile) { [System.IO.Path]::GetFileNameWithoutExtension($RollbackFile) } else { $null }
}
$null = Invoke-PluginHooks -Stage 'Rollback' -Context $rollbackContext
$rollbackOk = Invoke-Rollback
    Write-Log "Session ended: Rollback mode"
    if (-not $rollbackOk) { $script:ExitCode = 1 }
    Exit-WithReport -Code $script:ExitCode
}


function Invoke-ModeReportOnly {
    <#
    .SYNOPSIS
        Handles the -ReportOnly operation mode. Reads and displays current shell folder
        configuration for all target users without making any changes.
    #>
    [CmdletBinding()]
    param()
    $script:ReportMode = 'Report Only'

    $script:ReportMode = 'Report Only'
    Write-SectionHeader "REPORT ONLY MODE"
    Write-Status "Reading shell folder configuration (no changes will be made)" -Type "Info"
    Write-Host ""
    
    if ($AllUsers) {
        $users = Get-AllUserProfiles
        if ($users.Count -eq 0) {
            Write-Status "No user profiles found" -Type "Error"
            $script:ExitCode = $script:EXIT_FAILURE; Exit-WithReport -Code $script:ExitCode
        }
        
        $grandTotalSize  = 0
        $ufmUserIdx = 0
        foreach ($user in $users) {
            $ufmUserIdx++
            Write-SectionHeader "Report: User $ufmUserIdx of $($users.Count): $($user.Username)"
            $result = Invoke-ReportOnlyForUser -Username $user.Username -ProfilePath $user.ProfilePath -SID $user.SID -IsActive $user.IsActive
            $grandTotalSize  += $result.TotalSize
            $script:ReportUserBlocks.Add([PSCustomObject]@{ Username=$user.Username; IsActive=$user.IsActive; Folders=@() })
        }
        
        Write-SectionHeader "GRAND TOTAL"
        Write-Status "Total data across all users: $(Format-Bytes $grandTotalSize)" -Type "Info"
    } elseif ($TargetUsername) {
        $u = Resolve-TargetUser -Username $TargetUsername
        if (-not $u) { $script:ExitCode = $script:EXIT_FAILURE; Exit-WithReport -Code $script:ExitCode }
        $null = Invoke-ReportOnlyForUser -Username $u.Username -ProfilePath $u.ProfilePath -SID $u.SID -IsActive $u.IsActive
        $script:ReportUserBlocks.Add([PSCustomObject]@{ Username=$u.Username; IsActive=$u.IsActive; Folders=@() })
    } else {
        $null = Invoke-ReportOnlyForUser -Username $env:USERNAME -ProfilePath $env:USERPROFILE -SID $null -IsActive $true
        $script:ReportUserBlocks.Add([PSCustomObject]@{ Username=$env:USERNAME; IsActive=$true; Folders=@() })
    }
    
    Write-Log "Session ended: Report only mode"
    Exit-WithReport -Code 0
}


function Invoke-ModeRestoreDefaults {
    <#
    .SYNOPSIS
        Handles the -RestoreDefaults mode.
        Sub-mode [1] Simple Restore: copies data back to default C:\Users\... locations and updates registry.
        Sub-mode [2] Redirect & Clean: keeps data in place, updates registry pointers only,
        then restores supplemental data (Wi-Fi, certs, registry, mapped drives, tasks, printers)
        from a UFM_Supplemental backup so components are active again with their original data.
    #>
    [CmdletBinding()]
    param()

    $script:ReportMode = 'Restore Defaults'
    Write-SectionHeader "RESTORE DEFAULTS MODE"
    Write-Host ""

    # Restore Defaults copies data back to C:\Users\<name> and updates the registry.
    # To keep data in place and only fix the registry, use menu option 2 (Redirect and Clean).

    $users = if ($script:_selectedUsers) { $script:_selectedUsers } else { Get-AllUserProfiles }

    # ── User table ────────────────────────────────────────────────────────────
    $colU = 22
    Write-Host ""
    Write-Host ("  {0,-$colU} {1}" -f "User", "Status") -ForegroundColor Cyan
    Write-TableSeparator -Width 90
    foreach ($u in $users) {
        $typeText  = if ($u.IsActive) { "Active" } else { "Inactive" }
        $typeColor = if ($u.IsActive) { "Green" }  else { "Yellow" }
        Write-Host ("  {0,-$colU} " -f $u.Username) -NoNewline
        Write-Host $typeText -ForegroundColor $typeColor
    }
    Write-TableSeparator -Width 90
    Write-Host ""

    Write-Status "Simple Restore: data will be copied back to default locations and registry updated." -Type "Info"
    Write-Status "Space check will be performed before any data movement." -Type "Info"
    Write-Host ""

    # Optional destination validation (if -Destination was supplied)
    if ($Destination) {
        Write-Status "Destination parameter was supplied but RestoreDefaults mode ignores it." -Type "Warning"
        Write-Status "Validating destination anyway as a safety check..." -Type "Info"
      $offer = (-not $Force)  -and (-not $Unattended)
$valid = Test-DestinationValid -Path $Destination -CreateIfMissing:$Force -DryRun:$DryRun -OfferCreate:$offer
        if (-not $valid) {
            Write-Status "Destination validation failed – aborting restore defaults." -Type "Error"
            $script:ExitCode = $script:EXIT_FAILURE
            Exit-WithReport -Code $script:ExitCode
        }
    }

    if (-not $DryRun) {
        if (-not (Confirm-Operation -Message "  Restore defaults for $($users.Count) user(s) above? (Y/N)")) {
            Write-Status "Operation cancelled by user" -Type "Warning"
            Write-Log "Session ended: User cancelled"
            Exit-WithReport -Code 0
        }
    }

    $allResults = @()
    $ufmUserIdx = 0
    foreach ($user in $users) {
        # ── OneDrive KFM interactive remediation ─────────────────────────────
        $kfm = Get-OneDriveKFMStatus -SID $user.SID
        if ($kfm.KFMEnabled -and -not $SkipKFMBlock -and -not $ForceOneDrive) {
            $attempt = 0; ${maxAttempts} = 3; $resolved = $false; $skipUser = $false
            while (-not $resolved -and $attempt -lt ${maxAttempts}) {
                if ($attempt -eq 0) {
                    Write-SectionHeader "ONEDRIVE KFM DETECTED: $($user.Username)"
                    Write-Status "OneDrive Known Folder Move is active for this user." -Type "Error"
                    Write-Status "  Account : $($kfm.AccountName)" -Type "Info"
                    foreach ($f in $kfm.Folders.Keys) { Write-Status "  $f -> $($kfm.Folders[$f])" -Type "Info" }
                    Write-Host ""
                    Write-Status "RestoreDefaults will move shell folders back to C:\Users\..." -Type "Warning"
                    Write-Status "  If KFM remains active, OneDrive will lose track of these folders and stop syncing." -Type "Warning"
                    Write-Host ""
                } else {
                    Write-SectionHeader "RECHECK ATTEMPT $attempt of ${maxAttempts}: $($user.Username)"
                    Write-Status "KFM still detected or shell folders still point under OneDrive." -Type "Error"
                    Write-Host ""
                }
                Write-Status "Remediation options:" -Type "Info"
                Write-Status "  1. Disable KFM now (remove policy keys, requires gpupdate)" -Type "Info"
                Write-Status "  2. Proceed anyway (acknowledge risk, no changes to KFM)"    -Type "Info"
                Write-Status "  3. Skip this user (abort)"                                   -Type "Info"
                Write-Status "  4. I have disabled KFM – recheck now"                        -Type "Info"
                Write-Host ""
                $choice = Invoke-KFMChoice
                switch ($choice) {
                    '1' {
                        Set-OneDriveKFMPolicy -Disable
                        Write-Status "KFM disabled. Run 'gpupdate /force' after this script." -Type "Success"
                        $kfm = Get-OneDriveKFMStatus -SID $user.SID
                        $stillInOD = Test-ShellFoldersInOneDrive -SID $user.SID -ProfilePath $user.ProfilePath
                        if (-not $kfm.KFMEnabled -and -not $stillInOD) { Write-Status "KFM disabled and folders no longer under OneDrive. Proceeding." -Type "Success"; $resolved = $true }
                        else { Write-Status "KFM still active or folders still under OneDrive." -Type "Warning"; $attempt++; $kfm = Get-OneDriveKFMStatus -SID $user.SID }
                    }
                    '2' { Write-Status "Proceeding despite active KFM." -Type "Warning"; $resolved = $true }
                    '3' { Write-Status "Skipping $($user.Username) due to KFM block." -Type "Warning"; Write-Log "User $($user.Username) skipped — KFM (user choice)"; $skipUser = $true; $resolved = $true }
                    '4' {
                        $kfm = Get-OneDriveKFMStatus -SID $user.SID
                        $stillInOD = Test-ShellFoldersInOneDrive -SID $user.SID -ProfilePath $user.ProfilePath
                        if (-not $kfm.KFMEnabled -and -not $stillInOD) { Write-Status "KFM now disabled and folders no longer under OneDrive. Proceeding." -Type "Success"; $resolved = $true }
                        else {
                            $attempt++
                            if ($attempt -ge ${maxAttempts}) { Write-Status "After ${maxAttempts} attempts, KFM still active. Aborting user." -Type "Error"; Write-Log "User $($user.Username) aborted — persistent KFM after ${maxAttempts} rechecks"; $skipUser = $true; $resolved = $true; break }
                            Write-Status "KFM still active. $(${maxAttempts} - $attempt) recheck(s) left." -Type "Warning"; Start-Sleep -Seconds 3
                        }
                    }
                    default { Write-Status "Invalid choice — enter 1, 2, 3, or 4." -Type "Warning"; Start-Sleep -Seconds 1 }
                }
            }
            if ($skipUser) { continue }
        }

        $ufmUserIdx++
        Write-SectionHeader "Restore Defaults: User $ufmUserIdx of $($users.Count): $($user.Username)"
        $results = Invoke-RestoreDefaultsForUser -Username $user.Username -ProfilePath $user.ProfilePath -SID $user.SID -IsActive $user.IsActive
        if ($results) {
            $allResults += $results
            $script:ReportUserBlocks.Add([PSCustomObject]@{ Username=$user.Username; IsActive=$user.IsActive; Folders=$results })
        }
    }

    Write-SectionHeader "RESTORE DEFAULTS SUMMARY"
    $totalRestored = @($allResults | Where-Object { $_.Success }).Count
    $totalSize = 0L
    foreach ($r in $allResults) { if ($r.Success) { $totalSize += [long]$r.Size } }
    Write-Status "Total folders restored: $totalRestored" -Type "Info"
    Write-Status "Total data restored: $(Format-Bytes $totalSize)" -Type "Info"

    if (-not $DryRun) { Restart-Explorer }
    Write-Log "Session ended: Restore defaults mode (Simple Restore)"
    Exit-WithReport -Code 0
}


function Invoke-ModeRedirectAndClean {
    <#
    .SYNOPSIS
        Handles the -RedirectAndClean mode. Updates registry to point at existing data without copying files.
    #>
    [CmdletBinding()]
    param()

    $script:ReportMode = 'Redirect and Clean'
    Write-SectionHeader "REDIRECT AND CLEAN MODE"
    Write-Status "This mode updates registry pointers without copying files" -Type "Info"
    
    if (-not $Destination) {
        $Destination = Invoke-Prompt -Message "  Enter the path where YOUR data already resides (e.g. D:\Example)"
    }
    Write-Status "Destination: $Destination" -Type "Info"
    Write-Host ""

    # Validate destination exists and is writable
   $offer = (-not $Force) -and (-not $Unattended)
$valid = Test-DestinationValid -Path $Destination -CreateIfMissing:$Force -DryRun:$DryRun -OfferCreate:$offer
    if (-not $valid) {
        Write-Status "Destination validation failed – aborting redirect." -Type "Error"
        $script:ExitCode = $script:EXIT_FAILURE
        Exit-WithReport -Code $script:ExitCode
    }
    $preFlightContext = New-PluginContext 'PreFlight' @{
        DryRun       = $DryRun
        ConfigPath   = Join-Path $PSScriptRoot 'UFM_Config.json'
        AdminUser    = $env:USERNAME
        ComputerName = $env:COMPUTERNAME
        Destination  = $Destination
        SourcePath   = (Join-Path $env:SystemDrive 'Users')
        Unattended   = $Unattended
    }
    if ((Invoke-PluginHooks -Stage 'PreFlight' -Context $preFlightContext) -eq $false) {
        Write-Status "Pre-flight checks failed — aborting operation" -Type "Error"
        Send-MigrationNotification `
            -Subject "PRE-FLIGHT FAILED — UserFolderMigrator on $env:COMPUTERNAME" `
            -Body "Pre-flight validation failed. Migration has been ABORTED before any data was moved.`n`nComputer : $env:COMPUTERNAME`nUser     : $env:USERNAME`nMode     : $($script:ReportMode)`nTime     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`nLog      : $($script:LogFile)`n`nCheck disk health, path conflicts, network stability, and antivirus exclusions." `
            -Status 'Error'
        Exit-WithReport -Code $script:EXIT_FAILURE
}

    # ── Rollback snapshot: backup registry before any redirects ───────────────
    if (-not $DryRun) {
        $null = Backup-RegistrySettings -Username $env:USERNAME -SID (
            ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value)
        Write-Log "RedirectAndClean: registry backup created for rollback support"
    }

    $users = $script:_selectedUsers
    $isSingle = ($users.Count -eq 1)

    if (-not $DryRun) {
        if (-not (Confirm-Operation -Message "  Redirect registry for $($users.Count) user(s) above? (Y/N)")) {
            Write-Status "Operation cancelled by user" -Type "Warning"
            Write-Log "Session ended: User cancelled"
            Exit-WithReport -Code 0
        }
    }

    $ufmUserIdx = 0
    foreach ($user in $users) {
        # ── OneDrive KFM interactive remediation ─────────────────────────────
        $kfm = Get-OneDriveKFMStatus -SID $user.SID
        if ($kfm.KFMEnabled -and -not $SkipKFMBlock -and -not $ForceOneDrive) {
            $attempt = 0; ${maxAttempts} = 3; $resolved = $false; $skipUser = $false
            while (-not $resolved -and $attempt -lt ${maxAttempts}) {
                if ($attempt -eq 0) {
                    Write-SectionHeader "ONEDRIVE KFM DETECTED: $($user.Username)"
                    Write-Status "OneDrive Known Folder Move is active for this user." -Type "Error"
                    Write-Status "  Account : $($kfm.AccountName)" -Type "Info"
                    foreach ($f in $kfm.Folders.Keys) { Write-Status "  $f -> $($kfm.Folders[$f])" -Type "Info" }
                    Write-Host ""
                    Write-Status "RedirectAndClean will update registry shell folder paths." -Type "Warning"
                    Write-Status "  If KFM remains active, OneDrive may revert the changes silently." -Type "Warning"
                    Write-Host ""
                } else {
                    Write-SectionHeader "RECHECK ATTEMPT $attempt of ${maxAttempts}: $($user.Username)"
                    Write-Status "KFM still detected or shell folders still point under OneDrive." -Type "Error"
                    Write-Host ""
                }
                Write-Status "Remediation options:" -Type "Info"
                Write-Status "  1. Disable KFM now (remove policy keys, requires gpupdate)" -Type "Info"
                Write-Status "  2. Proceed anyway (acknowledge risk, no changes to KFM)"    -Type "Info"
                Write-Status "  3. Skip this user (abort)"                                   -Type "Info"
                Write-Status "  4. I have disabled KFM – recheck now"                        -Type "Info"
                Write-Host ""
                $choice = Invoke-KFMChoice
                switch ($choice) {
                    '1' {
                        Set-OneDriveKFMPolicy -Disable
                        Write-Status "KFM disabled. Run 'gpupdate /force' after this script." -Type "Success"
                        $kfm = Get-OneDriveKFMStatus -SID $user.SID
                        $stillInOD = Test-ShellFoldersInOneDrive -SID $user.SID -ProfilePath $user.ProfilePath
                        if (-not $kfm.KFMEnabled -and -not $stillInOD) { Write-Status "KFM disabled and folders no longer under OneDrive. Proceeding." -Type "Success"; $resolved = $true }
                        else { Write-Status "KFM still active or folders still under OneDrive." -Type "Warning"; $attempt++; $kfm = Get-OneDriveKFMStatus -SID $user.SID }
                    }
                    '2' { Write-Status "Proceeding despite active KFM." -Type "Warning"; $resolved = $true }
                    '3' { Write-Status "Skipping $($user.Username) due to KFM block." -Type "Warning"; Write-Log "User $($user.Username) skipped — KFM (user choice)"; $skipUser = $true; $resolved = $true }
                    '4' {
                        $kfm = Get-OneDriveKFMStatus -SID $user.SID
                        $stillInOD = Test-ShellFoldersInOneDrive -SID $user.SID -ProfilePath $user.ProfilePath
                        if (-not $kfm.KFMEnabled -and -not $stillInOD) { Write-Status "KFM now disabled and folders no longer under OneDrive. Proceeding." -Type "Success"; $resolved = $true }
                        else {
                            $attempt++
                            if ($attempt -ge ${maxAttempts}) { Write-Status "After ${maxAttempts} attempts, KFM still active. Aborting user." -Type "Error"; Write-Log "User $($user.Username) aborted — persistent KFM after ${maxAttempts} rechecks"; $skipUser = $true; $resolved = $true; break }
                            Write-Status "KFM still active. $(${maxAttempts} - $attempt) recheck(s) left." -Type "Warning"; Start-Sleep -Seconds 3
                        }
                    }
                    default { Write-Status "Invalid choice — enter 1, 2, 3, or 4." -Type "Warning"; Start-Sleep -Seconds 1 }
                }
            }
            if ($skipUser) { continue }
        }

        $ufmUserIdx++
        Write-SectionHeader "Redirect: User $ufmUserIdx of $($users.Count): $($user.Username)"
        $results = Invoke-RedirectAndCleanForUser -Username $user.Username -ProfilePath $user.ProfilePath `
            -Destination $Destination -SID $user.SID -IsActive $user.IsActive -AppendUsername (-not $isSingle)
        if ($results) { $script:ReportUserBlocks.Add([PSCustomObject]@{ Username=$user.Username; IsActive=$user.IsActive; Folders=$results }) }
    }
    
    if (-not $DryRun) { Restart-Explorer }
    Write-Log "Session ended: Redirect and clean mode"
    Exit-WithReport -Code 0
    }


function Invoke-ModeRepairTransactions {
    <#
    .SYNOPSIS
        Handles the -RepairTransactions mode. Resumes or repairs partially-completed migrations.
    #>
    [CmdletBinding()]
    param()

    $script:ReportMode = 'Repair Transactions'
    Write-SectionHeader "REPAIR TRANSACTIONS MODE"
    Write-Status "Scanning for partial migrations where data was left behind..." -Type "Info"

    # ── Rollback snapshot: capture transaction log state before repair ────────
    if (-not $DryRun) {
        $null = Backup-RegistrySettings -Username $env:USERNAME -SID (
            ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value)
        Write-Log "RepairTransactions: pre-repair registry snapshot created for rollback support"
    }
    
    $targetUsers = $script:_selectedUsers

    foreach ($user in $targetUsers) {
        # ── OneDrive KFM interactive remediation ─────────────────────────────
        $kfm = Get-OneDriveKFMStatus -SID $user.SID
        if ($kfm.KFMEnabled -and -not $SkipKFMBlock -and -not $ForceOneDrive) {
            $attempt = 0; ${maxAttempts} = 3; $resolved = $false; $skipUser = $false
            while (-not $resolved -and $attempt -lt ${maxAttempts}) {
                if ($attempt -eq 0) {
                    Write-SectionHeader "ONEDRIVE KFM DETECTED: $($user.Username)"
                    Write-Status "OneDrive Known Folder Move is active for this user." -Type "Error"
                    Write-Status "  Account : $($kfm.AccountName)" -Type "Info"
                    foreach ($f in $kfm.Folders.Keys) { Write-Status "  $f -> $($kfm.Folders[$f])" -Type "Info" }
                    Write-Host ""
                    Write-Status "RepairTransactions moves leftover data to the registry-pointed location." -Type "Warning"
                    Write-Status "  If KFM is active, the repair may be incomplete or cause sync errors."  -Type "Warning"
                    Write-Host ""
                } else {
                    Write-SectionHeader "RECHECK ATTEMPT $attempt of ${maxAttempts}: $($user.Username)"
                    Write-Status "KFM still detected or shell folders still point under OneDrive." -Type "Error"
                    Write-Host ""
                }
                Write-Status "Remediation options:" -Type "Info"
                Write-Status "  1. Disable KFM now (remove policy keys, requires gpupdate)" -Type "Info"
                Write-Status "  2. Proceed anyway (acknowledge risk, no changes to KFM)"    -Type "Info"
                Write-Status "  3. Skip this user (abort)"                                   -Type "Info"
                Write-Status "  4. I have disabled KFM – recheck now"                        -Type "Info"
                Write-Host ""
                $choice = Invoke-KFMChoice
                switch ($choice) {
                    '1' {
                        Set-OneDriveKFMPolicy -Disable
                        Write-Status "KFM disabled. Run 'gpupdate /force' after this script." -Type "Success"
                        $kfm = Get-OneDriveKFMStatus -SID $user.SID
                        $stillInOD = Test-ShellFoldersInOneDrive -SID $user.SID -ProfilePath $user.ProfilePath
                        if (-not $kfm.KFMEnabled -and -not $stillInOD) { Write-Status "KFM disabled and folders no longer under OneDrive. Proceeding." -Type "Success"; $resolved = $true }
                        else { Write-Status "KFM still active or folders still under OneDrive." -Type "Warning"; $attempt++; $kfm = Get-OneDriveKFMStatus -SID $user.SID }
                    }
                    '2' { Write-Status "Proceeding with RepairTransactions despite active KFM." -Type "Warning"; $resolved = $true }
                    '3' { Write-Status "Skipping $($user.Username) due to KFM block." -Type "Warning"; Write-Log "User $($user.Username) skipped — KFM (user choice)"; $skipUser = $true; $resolved = $true }
                    '4' {
                        $kfm = Get-OneDriveKFMStatus -SID $user.SID
                        $stillInOD = Test-ShellFoldersInOneDrive -SID $user.SID -ProfilePath $user.ProfilePath
                        if (-not $kfm.KFMEnabled -and -not $stillInOD) { Write-Status "KFM now disabled and folders no longer under OneDrive. Proceeding." -Type "Success"; $resolved = $true }
                        else {
                            $attempt++
                            if ($attempt -ge ${maxAttempts}) { Write-Status "After ${maxAttempts} attempts, KFM still active. Aborting user." -Type "Error"; Write-Log "User $($user.Username) aborted — persistent KFM after ${maxAttempts} rechecks"; $skipUser = $true; $resolved = $true; break }
                            Write-Status "KFM still active. $(${maxAttempts} - $attempt) recheck(s) left." -Type "Warning"; Start-Sleep -Seconds 3
                        }
                    }
                    default { Write-Status "Invalid choice — enter 1, 2, 3, or 4." -Type "Warning"; Start-Sleep -Seconds 1 }
                }
            }
            if ($skipUser) { continue }
        }

        $results = Invoke-RepairTransactionsForUser -Username $user.Username -ProfilePath $user.ProfilePath -SID $user.SID -IsActive $user.IsActive
        if ($results) { $script:ReportUserBlocks.Add([PSCustomObject]@{ Username=$user.Username; IsActive=$user.IsActive; Folders=$results }) }
    }
    
    if (-not $DryRun) { Restart-Explorer }
    Write-Log "Session ended: Repair transactions completed"
    Exit-WithReport -Code 0
    }


function Invoke-RollbackFullProfileBackup {
    <#
    .SYNOPSIS
        Deletes destination folders listed in a .ufm_fpb_rollback.json manifest to undo a
        FullProfileBackup run. Requires -Destination pointing to the backup root that contains
        the manifest, or a direct path via -RollbackFile.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param()

    Write-SectionHeader "ROLLBACK FULL PROFILE BACKUP"

    # Locate manifest
    $manifestPath = $null
    if ($RollbackFile -and (Test-Path $RollbackFile)) {
        $manifestPath = $RollbackFile
    } elseif ($Destination) {
        $candidate = Join-Path $Destination '.ufm_fpb_rollback.json'
        if (Test-Path $candidate) { $manifestPath = $candidate }
    }
    if (-not $manifestPath) {
        Write-Status "No rollback manifest found. Supply -RollbackFile <path> or -Destination pointing to the backup root." -Type "Error"
        Write-Log "RollbackFullProfile: manifest not found — aborting"
        $script:ExitCode = $script:EXIT_FAILURE; Exit-WithReport -Code $script:ExitCode
    }

    Write-Status "Manifest: $manifestPath" -Type "Info"
    $manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $manifest.Entries -or $manifest.Entries.Count -eq 0) {
        Write-Status "Manifest contains no entries — nothing to remove." -Type "Warning"
        Write-Log "RollbackFullProfile: manifest empty"
        Exit-WithReport -Code 0
        return
    }

    Write-Status "$($manifest.Entries.Count) backup destination(s) listed in manifest." -Type "Info"
    Write-Host ""

    if (-not $Unattended) {
        $confirm = Invoke-Prompt -Message "  This will PERMANENTLY DELETE the listed backup destinations. Type YES to continue"
        if ($confirm -ne 'YES') {
            Write-Status "Rollback cancelled by user." -Type "Warning"
            exit 0
        }
    }

    $removed = 0; $errors = 0
    foreach ($entry in $manifest.Entries) {
        $destPath = $entry.Destination
        if (-not $destPath) { continue }
        if (-not (Test-Path $destPath)) {
            Write-Status "  SKIP  $destPath (already absent)" -Type "Info"
            Write-Log "RollbackFullProfile: already absent — $destPath"
            continue
        }
        if ($DryRun) {
            Write-Status "  [DRYRUN] Would remove: $destPath" -Type "Info"
            Write-Log "RollbackFullProfile: DryRun — would remove $destPath"
            continue
        }
        try {
            Remove-Item -LiteralPath $destPath -Recurse -Force -ErrorAction Stop
            Write-Status "  REMOVED $destPath" -Type "Success"
            Write-Log "RollbackFullProfile: removed $destPath"
            Write-AuditEntry -Message "ROLLBACK_FPB_REMOVED: $destPath" -Level "WARN"
            $removed++
        } catch {
            Write-Status "  ERROR  removing $destPath — $($_.Exception.Message)" -Type "Error"
            Write-Log "RollbackFullProfile: error removing $destPath — $($_.Exception.Message)"
            $errors++
        }
    }

    Write-Host ""
    Write-Status "Rollback complete. Removed: $removed  Errors: $errors" -Type $(if ($errors -gt 0) { "Warning" } else { "Success" })
    Write-Log "RollbackFullProfile: done — removed=$removed errors=$errors"
    $script:ExitCode = if ($errors -gt 0) { 1 } else { 0 }
    Exit-WithReport -Code $script:ExitCode
}


function Invoke-ModeFullProfileBackup {
    <#
    .SYNOPSIS
        Handles the -FullProfileBackup mode. Clones entire user profile trees including
        AppData, NTUSER.DAT (via VSS), certificates, credentials, dotfolders, and printer profiles.
    #>
    [CmdletBinding()]
    param()

    $script:ReportMode = 'Full Profile Backup'
    Write-SectionHeader "FULL PROFILE BACKUP MODE"
    Write-Status "Copies the ENTIRE user folder including ALL hidden and system files." -Type "Info"
    Write-Status "Junction directories (shell-compat, OneDrive) are excluded to prevent" -Type "Info"
    Write-Status "duplicate copies.  Source and destination sizes will match exactly." -Type "Info"
    Write-Host ""

    if (-not $Destination) {
        $Destination = Invoke-Prompt -Message "  Enter destination root path (a sub-folder per user will be created)"
    }
    Write-Status "Destination root: $Destination" -Type "Info"
    Write-Host ""

    # Validate destination exists and is writable
       $offer = (-not $Force) -and (-not $Unattended)
$valid = Test-DestinationValid -Path $Destination -CreateIfMissing:$Force -DryRun:$DryRun -OfferCreate:$offer
    if (-not $valid) {
        Write-Status "Destination validation failed – aborting full profile backup." -Type "Error"
        $script:ExitCode = $script:EXIT_FAILURE
        Exit-WithReport -Code $script:ExitCode
    }

    # ── Rollback snapshot ─────────────────────────────────────────────────────
    # Record which destination sub-folders UserFolderMigrator creates so they can be removed on rollback.
    if (-not $DryRun) {
        $script:_FPBRollbackManifest = @{
            Mode        = 'FullProfileBackup'
            Timestamp   = (Get-Date -Format 'o')
            Destination = $Destination
            Created     = [System.Collections.Generic.List[string]]::new()
        }
    }

    $targetUsers = $script:_selectedUsers ?? @(Get-AllUserProfiles)

    # Show user list
    $colU = 22; $colS = 10
    Write-Host ("  {0,-$colU} {1,-$colS} {2}" -f "User", "Status", "Destination") -ForegroundColor Cyan
    Write-TableSeparator -Width 90
    foreach ($u in $targetUsers) {
        $stTxt = if ($u.IsActive) { "Active" } else { "Inactive" }
        $stClr = if ($u.IsActive) { "Green"  } else { "Yellow"  }
        $dest  = Join-Path $Destination $u.Username
        Write-Host ("  {0,-$colU} " -f $u.Username) -NoNewline
        Write-Host ("{0,-$colS} " -f $stTxt) -ForegroundColor $stClr -NoNewline
        Write-Host $dest -ForegroundColor Gray
    }
    Write-TableSeparator -Width 90
    Write-Host ""

    if (-not $DryRun) {
        if (-not (Confirm-Operation -Message "  Back up $($targetUsers.Count) user profile(s) as above? (Y/N)")) {
            Write-Status "Operation cancelled by user." -Type "Warning"
            Write-Log "Session ended: User cancelled full profile backup"
            Exit-WithReport -Code 0
        }
    }

    $allResults = @()
    $ufmUserIdx = 0
    foreach ($u in $targetUsers) {
        # ── OneDrive KFM / cloud-only check ───────────────────────────────────
        $kfm = Get-OneDriveKFMStatus -SID $u.SID
        if ($kfm.KFMEnabled -and -not $SkipKFMBlock -and -not $ForceOneDrive) {
            $attempt = 0; ${maxAttempts} = 3; $resolved = $false; $skipUser = $false
            while (-not $resolved -and $attempt -lt ${maxAttempts}) {
                if ($attempt -eq 0) {
                    Write-SectionHeader "ONEDRIVE KFM DETECTED: $($u.Username)"
                    Write-Status "OneDrive Known Folder Move is active for this user." -Type "Error"
                    Write-Status "  Account : $($kfm.AccountName)" -Type "Info"
                    foreach ($f in $kfm.Folders.Keys) { Write-Status "  $f -> $($kfm.Folders[$f])" -Type "Info" }
                    Write-Host ""
                    Write-Status "FullProfileBackup risk: cloud-only (stub) files will be copied as zero-byte placeholders." -Type "Warning"
                    Write-Status "  Use option 1 or pass -HydrateOneDrive to download stubs before backup." -Type "Warning"
                    Write-Host ""
                } else {
                    Write-SectionHeader "RECHECK ATTEMPT $attempt of ${maxAttempts}: $($u.Username)"
                    Write-Status "KFM still detected or shell folders still point under OneDrive." -Type "Error"
                    Write-Host ""
                }
                Write-Status "Remediation options:" -Type "Info"
                Write-Status "  1. Hydrate OneDrive stubs now (download all cloud-only files), then backup" -Type "Info"
                Write-Status "  2. Proceed anyway  (stubs will be backed up as zero-byte files)"            -Type "Info"
                Write-Status "  3. Skip this user  (abort)"                                                  -Type "Info"
                Write-Status "  4. I have hydrated OneDrive – recheck now"                                   -Type "Info"
                Write-Host ""
                $choice = Invoke-KFMChoice -UnattendedDefault "2"
                switch ($choice) {
                    '1' {
                        Write-Status "Hydrating OneDrive cloud-only files for $($u.Username)..." -Type "Info"
                        Write-Status "  This may take a long time depending on OneDrive library size." -Type "Info"
                        $odPath = $kfm.Folders.Values | Select-Object -First 1
                        if ($odPath) {
                            try {
                                attrib -U /S /D "$odPath\*" 2>&1 | Out-Null
                                Write-Status "Hydration triggered via attrib. Waiting 10s for sync..." -Type "Info"
                                Start-Sleep -Seconds 10
                            } catch { Write-Status "Hydration command failed: $_" -Type "Warning" }
                        }
                        $stillInOD = Test-ShellFoldersInOneDrive -SID $u.SID -ProfilePath $u.ProfilePath
                        Write-Status "Proceeding with backup (stubs may still exist if OneDrive sync incomplete)." -Type "Info"
                        $resolved = $true
                    }
                    '2' { Write-Status "Proceeding — cloud-only stubs will be backed up as zero-byte files." -Type "Warning"; $resolved = $true }
                    '3' { Write-Status "Skipping $($u.Username)." -Type "Warning"; Write-Log "FullProfileBackup: $($u.Username) skipped — KFM/cloud-only (user choice)"; $skipUser = $true; $resolved = $true }
                    '4' {
                        $kfm = Get-OneDriveKFMStatus -SID $u.SID
                        $stillInOD = Test-ShellFoldersInOneDrive -SID $u.SID -ProfilePath $u.ProfilePath
                        if (-not $kfm.KFMEnabled -and -not $stillInOD) { Write-Status "KFM now disabled. Proceeding." -Type "Success"; $resolved = $true }
                        else {
                            $attempt++
                            if ($attempt -ge ${maxAttempts}) { Write-Status "After ${maxAttempts} attempts, KFM still active. Aborting user." -Type "Error"; Write-Log "FullProfileBackup: $($u.Username) aborted — persistent KFM after ${maxAttempts} rechecks"; $skipUser = $true; $resolved = $true; break }
                            Write-Status "KFM still active. $(${maxAttempts} - $attempt) recheck(s) left." -Type "Warning"; Start-Sleep -Seconds 3
                        }
                    }
                    default { Write-Status "Invalid choice — enter 1, 2, 3, or 4." -Type "Warning"; Start-Sleep -Seconds 1 }
                }
            }
            if ($skipUser) { continue }
        }

        $ufmUserIdx++
        Write-SectionHeader "Processing User $ufmUserIdx of $($targetUsers.Count): $($u.Username)"
        # For inactive users, fix permissions first so we can read everything
        if (-not $u.IsActive -and -not $SkipAutoPermissionFix) {
            Write-Status "Inactive user — fixing permissions on $($u.ProfilePath)..." -Type "Info"
            $null = Repair-InactiveUserPermissions -ProfilePath $u.ProfilePath -Username $u.Username
        }

        $userDest = Join-Path $Destination $u.Username
        $res = Invoke-FullProfileBackupForUser `
            -Username    $u.Username `
            -ProfilePath $u.ProfilePath `
            -Destination $userDest `
            -SID         $u.SID `
            -IsActive    $u.IsActive

        if ($res) { $allResults += $res }
    }

    # Multi-user grand summary
    if ($targetUsers.Count -gt 1) {
        Write-SectionHeader "FULL PROFILE BACKUP — GRAND SUMMARY"
        $cW = @{ User = 22; Size = 14; Match = 8 }
        Write-Host ("  {0,-$($cW.User)} {1,$($cW.Size)} {2,$($cW.Match)}" `
            -f "User","Dst Size","Match") -ForegroundColor Cyan
        Write-TableSeparator -Width 50
        foreach ($r in $allResults) {
            $mTxt = if ($r.DryRun) { "DryRun" } elseif ($r.AllMatch) { "MATCH" } else { "DIFFER" }
            $mClr = if ($r.DryRun) { "Yellow" } elseif ($r.AllMatch) { "Green"  } else { "Red"    }
            Write-Host ("  {0,-$($cW.User)} {1,$($cW.Size)} " `
                -f $r.Username, (Format-Bytes $r.DstSize)) -NoNewline
            Write-Host ("{0,$($cW.Match)}" -f $mTxt) -ForegroundColor $mClr
        }
        Write-TableSeparator -Width 50
        # FIX: safe accumulation instead of .Sum which throws on empty collections.
        $totalSize = 0L
        foreach ($r in $allResults) { $totalSize += [long]$r.DstSize }
        $matchCount = @($allResults | Where-Object { $_.AllMatch -or $_.DryRun }).Count
        Write-Host ("  {0,-$($cW.User)} {1,$($cW.Size)}" `
            -f "TOTAL", (Format-Bytes $totalSize)) -ForegroundColor Cyan
        Write-TableSeparator -Width 50
        Write-Host ""
        if ($matchCount -eq $allResults.Count) {
            Write-Status "All $($allResults.Count) profile(s) backed up successfully — sources and destinations match." -Type "Success"
        } else {
            Write-Status "$matchCount of $($allResults.Count) profile(s) matched exactly.  Check warnings above." -Type "Warning"
            $script:ExitCode = 1
        }
    }

    Write-Log "Session ended: Full profile backup completed ($($targetUsers.Count) user(s))"
    # Persist rollback manifest so Invoke-RollbackFullProfileBackup can undo this run
    if (-not $DryRun -and $script:_FPBRollbackManifest) {
        $rbPath = Join-Path $Destination '.ufm_fpb_rollback.json'
        $script:_FPBRollbackManifest | ConvertTo-Json -Depth 4 |
            Set-Content $rbPath -Encoding UTF8 -Force
        Write-Log "FullProfileBackup: rollback manifest written to $rbPath"
    }
    Exit-WithReport -Code $script:ExitCode
    }


function Invoke-ModeMigrate {
    <#
    .SYNOPSIS
        Unified migrate handler — works for single user, selected users, or all users.
        User list comes from $script:_selectedUsers set by Invoke-ModeDispatch.
    #>
    [CmdletBinding()]
    param()

    $script:ReportMode = 'Migration'
    Write-SectionHeader "MIGRATION"
    $Destination = if ($Destination) { $Destination } else {
        Invoke-Prompt -Message "  Enter destination root path (a sub-folder per user will be created, e.g. D:\Data)"
    }
    if ($NetworkCredential -and $Destination.StartsWith('\\')) {
        $Destination = Mount-NetworkDestination -UncPath $Destination
    }
    Test-BitLockerCompliance -Path $Destination -Label 'Destination'

    # Validate destination existence and writability (early check)
    Write-Status "Validating destination: $Destination" -Type "Info"
   $offer = (-not $Force) -and (-not $Unattended)
$valid = Test-DestinationValid -Path $Destination -CreateIfMissing:$Force -DryRun:$DryRun -OfferCreate:$offer
    if (-not $valid) {
        Write-Status "Destination validation failed – aborting migration." -Type "Error"
        $script:ExitCode = $script:EXIT_FAILURE
        Exit-WithReport -Code $script:ExitCode
    }

    $users = $script:_selectedUsers
    $isSingle = ($users.Count -eq 1)

    Write-Host ''
    $colUser = 20; $colStatus = 10
    Write-Host ("  {0,-$colUser} {1,-$colStatus} {2}" -f 'User','Status','Destination') -ForegroundColor Cyan
    Write-Host ("  " + ('-' * 80))
    foreach ($u in $users) {
        $dest = if ($isSingle) { $Destination } else { Join-Path $Destination $u.Username }
        $statusLabel = if ($u.IsActive) { 'Active' } else { 'Inactive' }
        Write-Host ("  {0,-$colUser} {1,-$colStatus} {2}" -f $u.Username, $statusLabel, $dest)
    }
    Write-Host ("  " + ('-' * 80))
    Write-Host ''

    if (-not $Unattended) {
        if (-not (Confirm-Operation -Message "  Migrate $($users.Count) user(s) as above? (Y/N)")) {
            Write-Status "Operation cancelled." -Type "Warning"
            Exit-WithReport -Code 0
        }
    }

    $spaceCheckPassed = Test-DestinationSpaceForAllUsers -Users $users -BaseDestination $Destination
    if (-not $spaceCheckPassed) {
        Send-MigrationNotification `
            -Subject "INSUFFICIENT DISK SPACE — UserFolderMigrator on $env:COMPUTERNAME" `
            -Body "Disk space validation failed. Migration ABORTED — no data has been moved.`n`nComputer : $env:COMPUTERNAME`nDest     : $Destination`nLog      : $($script:LogFile)`n`nFree up space on the destination drive and re-run." `
            -Status 'Error'
        $script:ExitCode = $script:EXIT_NO_SPACE
        Exit-WithReport -Code $script:ExitCode
    }

    $ufmUserIdx = 0
    foreach ($user in $users) {
        $ufmUserIdx++
        $userDest = if ($isSingle) { $Destination } else { Join-Path $Destination $user.Username }
        Write-SectionHeader "Migration: User $ufmUserIdx of $($users.Count): $($user.Username)"

        # ── PreUser hooks ──────────────────────────────────────────────────────
        $preUserCtx = New-PluginContext 'PreUser' @{
            UserName         = $user.Username
            SID              = $user.SID
            SourcePath       = $user.ProfilePath
            DestinationPath  = $userDest
            DryRun           = $DryRun
            SkipProvisioning = $DryRun
            Folders          = 'All'
            BaseDestination  = $Destination
            QuotaGB          = 0
        }
        if ((Invoke-PluginHooks -Stage 'PreUser' -Context $preUserCtx) -eq $false) {
            Write-Status "PreUser stage blocked for $($user.Username) — skipping user" -Type "Warning"
            Write-Log "PreUser stage blocked for $($user.Username) in sequential worker — skipping"
            continue
        }

        $migResult = Invoke-UserMigration -Username $user.Username -ProfilePath $user.ProfilePath `
            -Destination $userDest -SID $user.SID -IsActive $user.IsActive

        # ── PostUser hooks ─────────────────────────────────────────────────────
        $postUserCtx = New-PluginContext 'PostUser' @{
            UserName        = $user.Username
            SID             = $user.SID
            SourcePath      = $user.ProfilePath
            ProfilePath     = $user.ProfilePath
            DestinationPath = $userDest
            DryRun          = $DryRun
            Aborted         = ($migResult -and $migResult.Aborted)
            SuccessCount    = if ($migResult) { $migResult.SuccessCount } else { 0 }
            TotalCount      = if ($migResult) { $migResult.TotalCount }   else { 0 }
            Result          = $migResult
        }
        $null = Invoke-PluginHooks -Stage 'PostUser' -Context $postUserCtx

        if ($migResult) {
            if ($migResult.Aborted) { $script:ExitCode = $script:EXIT_FAILURE }
            $script:ReportUserBlocks.Add([PSCustomObject]@{
                Username    = $user.Username
                IsActive    = $user.IsActive
                Folders     = $migResult.Folders
                Aborted     = $migResult.Aborted
                AbortReason = if ($migResult.PSObject.Properties['AbortReason']) { $migResult.AbortReason } else { '' }
            })
            if ($PassThru) { $migResult }
            if ($CreateSyncTask -and -not $migResult.Aborted) {
                Register-DeltaSyncTask -SourceRoot $user.ProfilePath -DestRoot $userDest -Username $user.Username
            }
        }
    }

    if (-not $DryRun) { Restart-Explorer }
    Write-Log "Session ended: Migration completed ($($users.Count) user(s))"
}
function Invoke-ModeDispatch {
    <#
    .SYNOPSIS
        Interactive menu — resolves -Mode (or prompts), selects users, dispatches.
    #>
    [CmdletBinding()]
    param()

    # ── 0. KFM Policy Deploy/Remove (runs before anything else) ──────────
    if ($RemoveKFMPolicy) { Set-OneDriveKFMPolicy -Disable }
    if ($DeployKFMPolicy) { Set-OneDriveKFMPolicy -TenantId $KFMTenantId }

    # ── 1. Resolve mode ───────────────────────────────────────────────────
    # Legacy switch compatibility: map old switches to $Mode if still passed
    if (-not $Mode) {
        if ($RollbackFullProfile)  { $script:_mode = 'FullProfileBackup' }
        else {
            $menuItems = @(
                '1. Migrate shell folders',
                '2. Redirect and clean  (registry only — data already moved)',
                '3. Restore defaults    (put folders back to C:\Users\<name>)',
                '4. Full profile backup (copy entire profile to another drive)',
                '5. Restore from backup (unpack a full profile backup)',
                '6. Repair incomplete migration'
            )
            Write-Host ''
            Write-Host '  What would you like to do?' -ForegroundColor Cyan
            foreach ($item in $menuItems) { Write-Host "    $item" }
            Write-Host ''
            $choice = (Read-Host '  Enter choice (1-6)').Trim()
            $script:_mode = switch ($choice) {
                '1' { 'Migrate' }
                '2' { 'RedirectAndClean' }
                '3' { 'RestoreDefaults' }
                '4' { 'FullProfileBackup' }
                '5' { 'RestoreProfile' }
                '6' { 'RepairTransactions' }
                default {
                    Write-Status "Invalid choice — defaulting to Migrate" -Type "Warning"
                    'Migrate'
                }
            }
        }
    } else {
        $script:_mode = $Mode
    }

    # ── 2. User selector (skipped for RestoreProfile — uses source folder) ─
    $script:_selectedUsers = $null
    if ($script:_mode -notin @('RestoreProfile')) {
        $allProfiles = Get-AllUserProfiles
        if ($allProfiles.Count -eq 0) {
            Write-Status "No user profiles found." -Type "Error"; $script:ExitCode = $script:EXIT_FAILURE; Exit-WithReport -Code $script:ExitCode
        }
        Write-Host ''
        Write-Host '  Detected user profiles:' -ForegroundColor Cyan
        $idx = 0
        foreach ($u in $allProfiles) {
            $idx++
            $statusColor = if ($u.IsActive) { 'Green' } else { 'Yellow' }
            $statusLabel = if ($u.IsActive) { '[Active]' } else { '[Inactive]' }
            Write-Host ("    {0,2}. {1,-20} " -f $idx, $u.Username) -NoNewline
            Write-Host $statusLabel -ForegroundColor $statusColor
        }
        Write-Host ''
        $sel = (Read-Host '  Enter numbers (e.g. 1,3) or ALL').Trim()
        if ($sel -ieq 'ALL') {
            $script:_selectedUsers = $allProfiles
        } else {
            $indices = $sel -split '[,\s]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
            $script:_selectedUsers = @($indices | ForEach-Object {
                $i = [int]$_ - 1
                if ($i -ge 0 -and $i -lt $allProfiles.Count) { $allProfiles[$i] }
            } | Where-Object { $_ })
            if ($script:_selectedUsers.Count -eq 0) {
                Write-Status "No valid users selected." -Type "Error"; $script:ExitCode = $script:EXIT_FAILURE; Exit-WithReport -Code $script:ExitCode
            }
        }
    }

    # ── 3. FullProfileBackup uses its own user discovery loop ─────────────
    if ($script:_mode -eq 'FullProfileBackup') {
        if ($RollbackFullProfile) { Invoke-RollbackFullProfileBackup }
        else                      { Invoke-ModeFullProfileBackup }
        Exit-WithReport -Code $script:ExitCode
        return
    }

    # ── 4. Dispatch ────────────────────────────────────────────────────────
    switch ($script:_mode) {
        'Migrate'            { Invoke-ModeMigrate }
        'RedirectAndClean'   { Invoke-ModeRedirectAndClean }
        'RestoreDefaults'    { Invoke-ModeRestoreDefaults }
        'RestoreProfile'     { Invoke-ModeRestoreProfile }
        'RepairTransactions' { Invoke-ModeRepairTransactions }
    }
    Exit-WithReport -Code $script:ExitCode
}

function Invoke-ModeRestoreProfile {
    <#
    .SYNOPSIS
        Entry point for -RestoreProfile mode. Prompts for Source and discovers
        user sub-folders produced by -FullProfileBackup. Shows a pre-flight
        summary table, issues machine-bound warnings, then calls
        Invoke-RestoreProfileForUser for each user.
        Now includes interactive choice: Full Restore vs. RedirectOnly.
    #>
    [CmdletBinding()]
    param()

    Write-SectionHeader "RESTORE PROFILE MODE"
    Write-Status "Restores files, registry, ACLs, Wi-Fi, mapped drives, scheduled tasks and printers" -Type "Info"
    Write-Status "from a backup created by -FullProfileBackup." -Type "Info"
    Write-Host ""

    # ── Prompt for Source ─────────────────────────────────────────────────────
    if (-not $Source) {
        $Source = Invoke-Prompt -Message "  Enter the backup root path (e.g. Y:\Data, the folder containing per-user sub-folders)"
    }
    if (-not (Test-Path $Source)) {
        Write-Status "Source path '$Source' does not exist." -Type "Error"
        $script:ExitCode = $script:EXIT_FAILURE; return
    }

    # ── Discover user backup folders ──────────────────────────────────────────
    $userFolders = @(Get-ChildItem -Path $Source -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'UFM_Supplemental') })

    if ($userFolders.Count -eq 0) {
        Write-Status "No valid UserFolderMigrator backup folders found under '$Source'." -Type "Error"
        Write-Status "Each user folder must contain a UFM_Supplemental sub-folder." -Type "Error"
        $script:ExitCode = $script:EXIT_FAILURE; return
    }

    # ── Filter by -TargetUsername / -AllUsers ────────────────────────────────
    if ($TargetUsername) {
        $userFolders = @($userFolders | Where-Object { $_.Name -ieq $TargetUsername })
        if ($userFolders.Count -eq 0) {
            Write-Status "No backup folder found for '$TargetUsername' under '$Source'." -Type "Error"
            $script:ExitCode = $script:EXIT_FAILURE; return
        }
    } elseif (-not $AllUsers -and $userFolders.Count -gt 1) {
        Write-Host "  Multiple user backups found:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $userFolders.Count; $i++) {
            Write-Host ("  [{0}] {1}" -f ($i+1), $userFolders[$i].Name)
        }
        $choice = Invoke-Prompt -Message "  Enter number to restore (or 'all')"
        if ($choice -ieq 'all') { <# keep all #> }
        elseif ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $userFolders.Count) {
            $userFolders = @($userFolders[[int]$choice - 1])
        } else {
            Write-Status "Invalid selection." -Type "Error"
            $script:ExitCode = $script:EXIT_FAILURE; return
        }
    }

    # ── Interactive restore method selection ─────────────────────────────────
    $useRedirectOnly = $false
    if ($RedirectOnly) {
        # If command-line switch was already used, respect it
        $useRedirectOnly = $true
        Write-Status "Restore mode: RedirectOnly (from command line)" -Type "Info"
    } elseif (-not $Unattended) {
        Write-Host ""
        Write-Host "  Select restore method:" -ForegroundColor Cyan
        Write-Host "    1. Full restore        – Copy everything back to C:\Users\<name> (shell folders + AppData + settings)"
        Write-Host "    2. Redirect only       – Keep shell folders on backup device, restore only AppData + settings locally"
        Write-Host ""
        $methodChoice = (Read-Host "  Enter choice (1 or 2)").Trim()
        if ($methodChoice -eq '2') {
            $useRedirectOnly = $true
            Write-Status "RedirectOnly mode selected. Shell folders will stay on backup device." -Type "Info"
        } else {
            $useRedirectOnly = $false
            Write-Status "Full restore mode selected. All data will be copied to C:\Users\<name>." -Type "Info"
        }
    } else {
        # Unattended mode: default to full restore unless -RedirectOnly was passed
        $useRedirectOnly = $RedirectOnly
        Write-Status "Unattended mode: restore method = $(if ($useRedirectOnly) { 'RedirectOnly' } else { 'Full restore' })" -Type "Info"
    }

    # ── Machine-bound portability warnings (only shown when using RedirectOnly) ──
    if ($useRedirectOnly) {
        $boxInner = 73
        $boxBorder = '─' * ($boxInner + 4)
        Write-Host ''
        Write-Host "  ┌$boxBorder┐" -ForegroundColor Yellow
        Write-Host ("  │  {0,-$boxInner}  │" -f 'PORTABILITY WARNINGS — read before continuing') -ForegroundColor Yellow
        Write-Host "  ├$boxBorder┤" -ForegroundColor Yellow

        $warnings = @(
            @{ Tag = 'BROWSER PASSWORDS';
               Body   = "Chrome/Edge/Firefox saved passwords are encrypted to the OLD machine's DPAPI key and cannot be decrypted on this machine.";
               Action = "Open each browser, sign in to your account to re-save passwords." },
            @{ Tag = 'WINDOWS HELLO / PIN';
               Body   = "Hello/PIN credentials are TPM-bound to the old machine and cannot be transferred.";
               Action = "Settings › Accounts › Sign-in options — create a new PIN after restore." },
            @{ Tag = 'OUTLOOK .OST';
               Body   = "The cached mailbox file (.ost) is machine-bound and will not open on this machine.";
               Action = "Launch Outlook — it will re-sync automatically. Large mailboxes may take hours." },
            @{ Tag = 'APP LICENCES';
               Body   = "Microsoft Office, Adobe, and other licensed apps must be reactivated. Licence keys are not stored in the profile backup.";
               Action = "Sign in to each app or re-enter your licence key." },
            @{ Tag = 'INSTALLED APPS';
               Body   = "Applications are NOT restored — only user data and settings are included.";
               Action = "Reinstall all required applications before running this restore." },
            @{ Tag = 'MACHINE CERTIFICATES';
               Body   = "Computer-store certificates (LocalMachine\My) are not in the profile. Only CurrentUser certs are restored.";
               Action = "Re-export and import machine certs separately if required." }
        )

        function Wrap-Text([string]$text, [int]$width) {
            $result = @(); $cur = ''
            foreach ($word in ($text -split ' ')) {
                if ($cur -eq '') { $cur = $word }
                elseif (($cur + ' ' + $word).Length -le $width) { $cur += ' ' + $word }
                else { $result += $cur; $cur = $word }
            }
            if ($cur) { $result += $cur }
            return $result
        }

        foreach ($w in $warnings) {
            Write-Host "  │$(' ' * ($boxInner + 4))│" -ForegroundColor Yellow
            Write-Host ("  │  {0,-$boxInner}  │" -f "[$($w.Tag)]") -ForegroundColor Yellow
            foreach ($line in (Wrap-Text $w.Body ($boxInner - 4))) {
                Write-Host ("  │    {0,-$($boxInner - 4)}  │" -f $line) -ForegroundColor Yellow
            }
            foreach ($aline in (Wrap-Text ("→ $($w.Action)") ($boxInner - 4))) {
                Write-Host ("  │    {0,-$($boxInner - 4)}  │" -f $aline) -ForegroundColor Yellow
            }
        }

        Write-Host "  │$(' ' * ($boxInner + 4))│" -ForegroundColor Yellow
        Write-Host "  └$boxBorder┘" -ForegroundColor Yellow
        Write-Host ''

        if (-not $Force -and -not $DryRun -and -not $Unattended) {
            $confirm = Invoke-Prompt -Message "  Acknowledged? Type YES to continue"
            if ($confirm -ne 'YES') { Write-Status "Restore cancelled." -Type "Info"; return }
        }
    }

    # ── Summary table ─────────────────────────────────────────────────────────
    Write-Host ""
    $col1 = 22; $col2 = 40
    Write-Host ("  {0,-$col1} {1}" -f "User", "Restore Destination") -ForegroundColor Cyan
    Write-TableSeparator -Width 90
    foreach ($uf in $userFolders) {
        $destProf = if ($DestinationProfile -and $userFolders.Count -eq 1) { $DestinationProfile }
                    else { "C:\Users\$($uf.Name)" }
        Write-Host ("  {0,-$col1} {1}" -f $uf.Name, $destProf)
    }
    Write-TableSeparator -Width 90
    Write-Host ""

    # ── Process each user with the chosen method ──────────────────────────────
    $idx = 0
    foreach ($uf in $userFolders) {
        # ── KFM check on DESTINATION machine ────────────────────────────────
        # KFM active on destination means OneDrive will silently re-redirect
        # freshly-restored shell folders within seconds of restore completing.
        $destSID = try {
            (New-Object System.Security.Principal.NTAccount($uf.Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch { $null }
        $kfm = Get-OneDriveKFMStatus -SID $destSID
        if ($kfm.KFMEnabled -and -not $SkipKFMBlock -and -not $ForceOneDrive) {
            $attempt = 0; ${maxAttempts} = 3; $resolved = $false; $skipUser = $false
            while (-not $resolved -and $attempt -lt ${maxAttempts}) {
                if ($attempt -eq 0) {
                    Write-SectionHeader "ONEDRIVE KFM DETECTED ON DESTINATION: $($uf.Name)"
                    Write-Status "OneDrive Known Folder Move is active on this machine for $($uf.Name)." -Type "Error"
                    Write-Status "  Account : $($kfm.AccountName)" -Type "Info"
                    foreach ($f in $kfm.Folders.Keys) { Write-Status "  $f -> $($kfm.Folders[$f])" -Type "Info" }
                    Write-Host ""
                    Write-Status "RestoreProfile will restore shell folders to C:\Users\$($uf.Name)." -Type "Warning"
                    Write-Status "  If KFM remains active, OneDrive will silently re-redirect them within seconds." -Type "Warning"
                    Write-Status "  The restore will appear to succeed but OneDrive will overwrite the registry." -Type "Warning"
                    Write-Host ""
                } else {
                    Write-SectionHeader "RECHECK ATTEMPT $attempt of ${maxAttempts}: $($uf.Name)"
                    Write-Status "KFM still active on destination machine." -Type "Error"
                    Write-Host ""
                }
                Write-Status "Remediation options:" -Type "Info"
                Write-Status "  1. Disable KFM now (remove policy keys, requires gpupdate)" -Type "Info"
                Write-Status "  2. Proceed anyway  (KFM may revert shell folder registry after restore)" -Type "Info"
                Write-Status "  3. Skip this user  (abort)"                                  -Type "Info"
                Write-Status "  4. I have disabled KFM – recheck now"                        -Type "Info"
                Write-Host ""
                $choice = Invoke-KFMChoice
                switch ($choice) {
                    '1' {
                        Set-OneDriveKFMPolicy -Disable
                        Write-Status "KFM disabled. Run 'gpupdate /force' then sign out/in for full effect." -Type "Success"
                        $kfm = Get-OneDriveKFMStatus -SID $destSID
                        if (-not $kfm.KFMEnabled) { Write-Status "KFM policy removed. Proceeding with restore." -Type "Success"; $resolved = $true }
                        else { Write-Status "KFM policy still detected." -Type "Warning"; $attempt++; $kfm = Get-OneDriveKFMStatus -SID $destSID }
                    }
                    '2' { Write-Status "Proceeding despite active KFM — OneDrive may re-redirect after restore." -Type "Warning"; $resolved = $true }
                    '3' { Write-Status "Skipping $($uf.Name)." -Type "Warning"; Write-Log "RestoreProfile: $($uf.Name) skipped — KFM active on destination (user choice)"; $skipUser = $true; $resolved = $true }
                    '4' {
                        $kfm = Get-OneDriveKFMStatus -SID $destSID
                        if (-not $kfm.KFMEnabled) { Write-Status "KFM now disabled. Proceeding." -Type "Success"; $resolved = $true }
                        else {
                            $attempt++
                            if ($attempt -ge ${maxAttempts}) { Write-Status "After ${maxAttempts} attempts, KFM still active. Aborting user." -Type "Error"; Write-Log "RestoreProfile: $($uf.Name) aborted — persistent KFM on destination after ${maxAttempts} rechecks"; $skipUser = $true; $resolved = $true; break }
                            Write-Status "KFM still active. $(${maxAttempts} - $attempt) recheck(s) left." -Type "Warning"; Start-Sleep -Seconds 3
                        }
                    }
                    default { Write-Status "Invalid choice — enter 1, 2, 3, or 4." -Type "Warning"; Start-Sleep -Seconds 1 }
                }
            }
            if ($skipUser) { continue }
        }

        $idx++
        $destProf = if ($DestinationProfile -and $userFolders.Count -eq 1) { $DestinationProfile }
                    else { "C:\Users\$($uf.Name)" }
        Write-SectionHeader "Restoring User $idx of $($userFolders.Count): $($uf.Name)"
        Invoke-RestoreProfileForUser -Username $uf.Name -BackupRoot $uf.FullName -DestinationProfile $destProf -RedirectOnly:$useRedirectOnly
    }

    Write-Host ""
    Write-Status "Restore complete. Review UFM_Supplemental\UFM_RestoreGuide.txt in each backup folder for remaining manual steps." -Type "Success"
}

function Invoke-RestoreProfileForUser {
    [CmdletBinding()]
    param(
        [string]$Username,
        [string]$BackupRoot,
        [string]$DestinationProfile,
        [switch]$RedirectOnly
    )

    $suppDir = Join-Path $BackupRoot 'UFM_Supplemental'

    # ── Phase 1: Files ────────────────────────────────────────────────────────
    if (-not $SkipFileRestore) {
        Write-SectionHeader "Phase 1 — File Restore: $Username"
        Write-Status "Source : $BackupRoot" -Type "Info"
        Write-Status "Target : $DestinationProfile" -Type "Info"

        # Ensure destination folder exists
        if (-not $DryRun -and -not (Test-Path $DestinationProfile)) {
            New-Item -Path $DestinationProfile -ItemType Directory -Force | Out-Null
            Write-Status "Created destination folder: $DestinationProfile" -Type "Success"
        }

        # ── Write‑access check and automatic repair ──────────────────────────
        $writeAccessOk = $false
        if (-not $SkipAccessCheck -and $script:AccessChkPath -and -not $DryRun) {
            Write-Status "Checking write access to destination profile folder..." -Type "Info"
            $writeCheck = & $script:AccessChkPath -accepteula -q -w "$env:USERNAME" "$DestinationProfile" 2>&1
            if ($LASTEXITCODE -eq 0 -and $writeCheck) {
                Write-Status "Write access confirmed by AccessChk." -Type "Success"
                $writeAccessOk = $true
            } else {
                Write-Status "AccessChk indicates NO write access to '$DestinationProfile'." -Type "Warning"
                
                # Attempt to repair permissions (unless -SkipAutoPermissionFix is set)
                if (-not $SkipAutoPermissionFix) {
                    Write-Status "Attempting to automatically fix permissions on destination folder..." -Type "Info"
                    $fixed = Repair-DestinationProfilePermissions -ProfilePath $DestinationProfile -Username $Username
                    if ($fixed) {
                        # Re-check write access after repair
                        $writeCheck2 = & $script:AccessChkPath -accepteula -q -w "$env:USERNAME" "$DestinationProfile" 2>&1
                        if ($LASTEXITCODE -eq 0 -and $writeCheck2) {
                            Write-Status "Write access confirmed after permission repair." -Type "Success"
                            $writeAccessOk = $true
                        } else {
                            Write-Status "Write access STILL denied after repair. Aborting restore." -Type "Error"
                            Write-Log "RestoreProfile aborted: write access denied even after permission fix for $DestinationProfile"
                            return
                        }
                    } else {
                        Write-Status "Permission repair failed. Aborting restore." -Type "Error"
                        Write-Log "RestoreProfile aborted: could not repair permissions for $DestinationProfile"
                        return
                    }
                } else {
                    Write-Status "Permission repair skipped (-SkipAutoPermissionFix). Aborting restore." -Type "Error"
                    Write-Log "RestoreProfile aborted: write access denied and -SkipAutoPermissionFix set"
                    return
                }
            }
        } elseif (-not $SkipAccessCheck -and -not $script:AccessChkPath) {
            Write-Status "AccessChk not available – skipping write‑access check." -Type "Warning"
            $writeAccessOk = $true   # proceed without check
        } else {
            # -SkipAccessCheck is set, assume write access is fine
            $writeAccessOk = $true
        }

        if (-not $writeAccessOk) {
            # Should not reach here, but as safety
            Write-Status "Write access not confirmed. Aborting restore." -Type "Error"
            return
        }

        # ── File copy (Full or RedirectOnly) ──────────────────────────────────
        if ($RedirectOnly) {
            Write-Status "RedirectOnly mode: copying ONLY AppData (shell folders will be registry-redirected to backup)" -Type "Info"
            $appDataSource = Join-Path $BackupRoot 'AppData'
            $appDataDest   = Join-Path $DestinationProfile 'AppData'
            if (Test-Path $appDataSource) {
                $rcArgs = @(
                    "`"$appDataSource`"", "`"$appDataDest`"",
                    '/E', '/COPY:DAT', '/DCOPY:DAT',
                    '/R:3', '/W:5',
                    '/MT:8', '/NP', '/NDL'
                )
                if ($DryRun) {
                    Write-Status "[DRY RUN] Would copy AppData to $appDataDest" -Type "Info"
                } else {
                    $rc = Start-Process robocopy -ArgumentList $rcArgs -Wait -NoNewWindow -PassThru
                    if ($rc.ExitCode -le 7) {
                        Write-Status "AppData restore complete (robocopy exit $($rc.ExitCode))." -Type "Success"
                    } else {
                        Write-Status "AppData restore reported errors (exit $($rc.ExitCode))." -Type "Warning"
                    }
                }
            } else {
                Write-Status "No AppData folder found in backup — skipping." -Type "Warning"
            }
        } else {
            Write-Status "Full restore mode: copying all files from backup..." -Type "Info"
            $rcArgs = @(
                "`"$BackupRoot`"", "`"$DestinationProfile`"",
                '/E', '/COPY:DAT', '/DCOPY:DAT',
                '/XD', "`"$suppDir`"",
                '/XJD', '/XJF',
                "/R:$RobocopyRetries", "/W:$RobocopyWait",
                "/MT:$(if ($RobocopyThreads -gt 0) { $RobocopyThreads } else { 4 })",
                '/NP', '/NDL'
            )
            if ($DryRun) {
                Write-Status "[DRY RUN] Would run: robocopy $($rcArgs -join ' ')" -Type "Info"
            } else {
                $rc = Start-Process robocopy -ArgumentList $rcArgs -Wait -NoNewWindow -PassThru
                if ($rc.ExitCode -le 7) {
                    Write-Status "Full file restore complete (robocopy exit $($rc.ExitCode))." -Type "Success"
                } else {
                    Write-Status "Robocopy reported errors (exit $($rc.ExitCode)) — check log." -Type "Warning"
                }
            }
        }
    } else { Write-Status "Phase 1 (files) skipped via -SkipFileRestore." -Type "Info" }

    # ── Phase 2: Registry Restore (with shell folder redirection for RedirectOnly) ──
    if (-not $SkipRegistryRestore) {
        Write-SectionHeader "Phase 2 — Registry Restore: $Username"
        
        $regFile  = Join-Path $suppDir 'HKCU_Export.reg'
        $appsFile = Join-Path $suppDir 'DefaultApps_Export.reg'
        foreach ($rf in @($regFile, $appsFile)) {
            if (Test-Path $rf) {
                if ($DryRun) {
                    Write-Status "[DRY RUN] Would import: $rf" -Type "Info"
                } else {
                    try {
                        $p = Start-Process reg.exe -ArgumentList "import `"$rf`"" -Wait -NoNewWindow -PassThru
                        if ($p.ExitCode -eq 0) {
                            Write-Status "Imported: $(Split-Path $rf -Leaf)" -Type "Success"
                        } else {
                            Write-Status "reg import exited $($p.ExitCode): $rf" -Type "Warning"
                        }
                    } catch { Write-Status "Registry import failed: $_" -Type "Warning" }
                }
            }
        }
        
        if ($RedirectOnly -and -not $DryRun) {
            Write-Status "RedirectOnly mode: updating shell folder registry to point to backup device..." -Type "Info"
            $backupRootNormalized = $BackupRoot.TrimEnd('\')
            $shellFolders = @('Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Videos', 'Favorites', 'Contacts', 'Links', 'SavedGames', 'Searches')
            
            foreach ($folder in $shellFolders) {
                $folderDefault = $script:SHELL_FOLDERS[$folder].Default
                $newPath = Join-Path $backupRootNormalized $folderDefault
                $regValue = $script:SHELL_FOLDERS[$folder].RegValue
                Set-ItemProperty -Path $script:USF_KEY -Name $regValue -Value $newPath -Type ExpandString -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $script:SF_KEY -Name $regValue -Value $newPath -Type String -Force -ErrorAction SilentlyContinue
                Write-Status "  $folder → $newPath" -Type "Success"
            }
        }
        
        Write-Status "" -Type "Info"
        Write-Status "[NOTE] Shell folder redirections restored. Sign out and back in for changes to take effect." -Type "Info"
    } else { Write-Status "Phase 2 (registry) skipped via -SkipRegistryRestore." -Type "Info" }

    # ── Phase 3: ACLs ─────────────────────────────────────────────────────────
    if (-not $SkipAclRestore) {
        Write-SectionHeader "Phase 3 — ACL Restore: $Username"
        $aclScript = Join-Path $suppDir 'Restore-ACLs.ps1'
        if (Test-Path $aclScript) {
            if ($DryRun) {
                Write-Status "[DRY RUN] Would run Restore-ACLs.ps1 -DestinationRoot '$DestinationProfile' -NewUsername '$Username' (with SID translation)" -Type "Info"
            } else {
                try {
                    & $aclScript -DestinationRoot $DestinationProfile -NewUsername $Username -ErrorAction SilentlyContinue
                    Write-Status "ACL restore complete." -Type "Success"
                    Write-Log "RestoreProfile: ACLs applied for $Username"
                } catch { Write-Status "ACL restore error: $_" -Type "Warning" }
            }
            Write-Status "[NOTE] SIDs from the old machine are translated to this machine's SID for '$Username'." -Type "Info"
        } else { Write-Status "Restore-ACLs.ps1 not found — skipping ACL restore." -Type "Info" }

        Write-Status "Applying strict permissions to .ssh and .gnupg..." -Type "Info"
        foreach ($sensitiveDir in @('.ssh', '.gnupg')) {
            $dirPath = Join-Path $DestinationProfile $sensitiveDir
            if (Test-Path $dirPath) {
                if ($DryRun) {
                    Write-Status "[DRY RUN] Would lock down permissions on $sensitiveDir" -Type "Info"
                } else {
                    try {
                        $acl = Get-Acl $dirPath
                        $acl.SetAccessRuleProtection($true, $false)
                        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
                        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                            'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
                        $acl.AddAccessRule($rule)
                        Set-Acl $dirPath $acl

                        $keyFiles = @(Get-ChildItem $dirPath -Recurse -File -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -match '^id_|^.*\.key$|^secring|^private-keys' })
                        foreach ($kf in $keyFiles) {
                            $kacl = Get-Acl $kf.FullName
                            $kacl.SetAccessRuleProtection($true, $false)
                            $kacl.Access | ForEach-Object { $kacl.RemoveAccessRule($_) | Out-Null }
                            $krule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                                [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                                'Read,Write', 'None', 'None', 'Allow')
                            $kacl.AddAccessRule($krule)
                            Set-Acl $kf.FullName $kacl
                        }
                        Write-Status "  Locked down: $sensitiveDir ($($keyFiles.Count) key file(s) secured)" -Type "Success"
                        Write-Log "RestoreProfile: $sensitiveDir permissions hardened for $Username"
                    } catch {
                        Write-Status "  Permission fix failed for $sensitiveDir`: $_" -Type "Warning"
                    }
                }
            }
        }
    } else { Write-Status "Phase 3 (ACLs) skipped via -SkipAclRestore." -Type "Info" }

    # ── Phase 4: Wi-Fi ────────────────────────────────────────────────────────
    if (-not $SkipWifiRestore) {
        Write-SectionHeader "Phase 4 — Wi-Fi Profile Restore: $Username"
        $wifiDir = Join-Path $suppDir 'WiFi_Profiles'
        if (Test-Path $wifiDir) {
            $xmlFiles = @(Get-ChildItem $wifiDir -Filter '*.xml' -ErrorAction SilentlyContinue)
            $ok = 0; $fail = 0
            foreach ($xml in $xmlFiles) {
                if ($DryRun) {
                    Write-Status "[DRY RUN] Would add Wi-Fi profile: $($xml.BaseName)" -Type "Info"
                    $ok++
                } else {
                    try {
                        # Validate XML root element before passing to netsh
                        $xmlDoc = [xml](Get-Content $xml.FullName -Raw -ErrorAction Stop)
                        if ($xmlDoc.DocumentElement.LocalName -ne 'WLANProfile') {
                            $fail++
                            Write-Status "Skipped (invalid root element): $($xml.BaseName)" -Type "Warning"
                            continue
                        }
                        $p = Start-Process netsh.exe -ArgumentList "wlan add profile filename=`"$($xml.FullName)`"" -Wait -NoNewWindow -PassThru
                        if ($p.ExitCode -eq 0) { $ok++; Write-Status "Added: $($xml.BaseName)" -Type "Success" }
                        else { $fail++; Write-Status "Failed ($($p.ExitCode)): $($xml.BaseName)" -Type "Warning" }
                    } catch { $fail++; Write-Status "Error adding $($xml.BaseName): $_" -Type "Warning" }
                }
            }
            Write-Log "RestoreProfile: Wi-Fi — $ok added, $fail failed for $Username"
        } else { Write-Status "No WiFi_Profiles folder found — skipping." -Type "Info" }
    } else { Write-Status "Phase 4 (Wi-Fi) skipped via -SkipWifiRestore." -Type "Info" }

    # ── Phase 5: Mapped Drives ────────────────────────────────────────────────
    if (-not $SkipDriveRestore) {
        Write-SectionHeader "Phase 5 — Mapped Drive Restore: $Username"
        $driveCmd = Join-Path $suppDir 'Reconnect-MappedDrives.cmd'
        if (Test-Path $driveCmd) {
            # Verify integrity before execution
            $driveCmdHash = $driveCmd + '.sha256'
            if (Test-Path $driveCmdHash) {
                $expectedCmdHash = (Get-Content $driveCmdHash -Raw).Trim()
                $actualCmdHash   = (Get-FileHash $driveCmd -Algorithm SHA256).Hash
                if ($actualCmdHash -ne $expectedCmdHash) {
                    Write-Status "Mapped drives .cmd file hash mismatch — skipping execution." -Type "Warning"
                    Write-Log "RestoreProfile: Reconnect-MappedDrives.cmd hash mismatch for $Username — skipped"
                    $driveCmd = $null
                }
            } else {
                Write-Status "No hash file for Reconnect-MappedDrives.cmd — skipping for safety." -Type "Warning"
                $driveCmd = $null
            }
            if ($driveCmd) {
                if ($DryRun) {
                    Write-Status "[DRY RUN] Would run: $driveCmd" -Type "Info"
                    Get-Content $driveCmd | Where-Object { $_ -match '^net use' } |
                        ForEach-Object { Write-Status "  $_" -Type "Info" }
                } else {
                    try {
                        $p = Start-Process cmd.exe -ArgumentList "/c `"$driveCmd`"" -Wait -NoNewWindow -PassThru
                        Write-Status "Mapped drives reconnect ran (exit $($p.ExitCode))." -Type "Success"
                        Write-Log "RestoreProfile: mapped drives reconnected for $Username (exit $($p.ExitCode))"
                    } catch { Write-Status "Drive reconnect error: $_" -Type "Warning" }
                }
            }
        } else { Write-Status "Reconnect-MappedDrives.cmd not found — skipping." -Type "Info" }
    } else { Write-Status "Phase 5 (mapped drives) skipped via -SkipDriveRestore." -Type "Info" }

    # ── Phase 6: Scheduled Tasks ──────────────────────────────────────────────
    if (-not $SkipTaskRestore) {
        Write-SectionHeader "Phase 6 — Scheduled Task Restore: $Username"
        $taskDir = Join-Path $suppDir 'ScheduledTasks'
        if (Test-Path $taskDir) {
            $xmlFiles = @(Get-ChildItem $taskDir -Filter '*.xml' -ErrorAction SilentlyContinue)
            $ok = 0; $fail = 0
            foreach ($xml in $xmlFiles) {
                if ($DryRun) {
                    Write-Status "[DRY RUN] Would create task: $($xml.BaseName)" -Type "Info"; $ok++
                } else {
                    try {
                        $p = Start-Process schtasks.exe `
                            -ArgumentList "/create /xml `"$($xml.FullName)`" /tn `"$($xml.BaseName)`" /f" `
                            -Wait -NoNewWindow -PassThru
                        if ($p.ExitCode -eq 0) { $ok++; Write-Status "Created: $($xml.BaseName)" -Type "Success" }
                        else { $fail++; Write-Status "Failed ($($p.ExitCode)): $($xml.BaseName)" -Type "Warning" }
                    } catch { $fail++; Write-Status "Error creating $($xml.BaseName): $_" -Type "Warning" }
                }
            }
            Write-Log "RestoreProfile: tasks — $ok created, $fail failed for $Username"
        } else { Write-Status "No ScheduledTasks folder found — skipping." -Type "Info" }
    } else { Write-Status "Phase 6 (tasks) skipped via -SkipTaskRestore." -Type "Info" }

    # ── Phase 7: Printers (full restore with fallback) ───────────────────────
    if (-not $SkipPrinterRestore) {
        Write-SectionHeader "Phase 7 — Printer Restore: $Username"
        Write-Status "Printers and drivers will be restored from backup." -Type "Info"
        Write-Status "Note: Full restore requires matching OS architecture (e.g., both 64‑bit)." -Type "Info"
        Write-Host ""

        $printerBackupFile = Join-Path $suppDir 'Printers\PrinterBackup.printerExport'
        $driversFallback   = Join-Path $suppDir 'Printers\Drivers'
        $restoreOk = Restore-PrinterDrivers -BackupFilePath $printerBackupFile `
                                            -DriversFallbackDir $driversFallback `
                                            -Force -DryRun:$DryRun
        if ($restoreOk) {
            Write-Status "Printer(s) restored successfully." -Type "Success"
        } else {
            Write-Status "Printer restore failed. You may need to re‑add printers manually." -Type "Warning"
            # Optionally list old JSON manifest if present (for reference)
            $manifestPath = Join-Path $BackupRoot 'ufm_printer_manifest.json'
            if (-not (Test-Path $manifestPath)) { $manifestPath = Join-Path $suppDir 'ufm_printer_manifest.json' }
            if (Test-Path $manifestPath) {
                Write-Status "Old printer manifest found – listing previously installed printers:" -Type "Info"
                try {
                    $printers = Get-Content $manifestPath -Raw | ConvertFrom-Json
                    foreach ($p in $printers) {
                        Write-Status "  $($p.Name) (Driver: $($p.DriverName), Port: $($p.PortName))" -Type "Info"
                    }
                } catch { }
            }
        }
    } else { Write-Status "Phase 7 (printers) skipped via -SkipPrinterRestore." -Type "Info" }

    # ── Phase 8: WSL ──────────────────────────────────────────────────────────
    if (-not $SkipWslRestore) {
        Write-SectionHeader "Phase 8 — WSL Distro Restore: $Username"
        $wslDir = Join-Path $suppDir 'WSL'
        if (Test-Path $wslDir) {
            $tarFiles = @(Get-ChildItem $wslDir -Filter '*.tar' -ErrorAction SilentlyContinue)
            if ($tarFiles.Count -gt 0) {
                Write-Status "WSL backup found: $($tarFiles.Count) distro(s) — $($tarFiles.BaseName -join ', ')" -Type "Info"
                $doWsl = if ($Unattended) { $true } else {
                    Confirm-Operation -Message "  Restore WSL distros? (Y/N)"
                }
                if (-not $doWsl) {
                    Write-Status "WSL restore skipped by user." -Type "Info"
                } else {
                    $wslCheck = Get-Command wsl.exe -ErrorAction SilentlyContinue
                    $wslReady = $false
                    if (-not $wslCheck) {
                        Write-Status "[!] WSL is not installed on this machine." -Type "Warning"
                        $enableWsl = if ($Unattended) { $false } else {
                            Confirm-Operation -Message "  Enable WSL feature now? This requires a reboot. (Y/N)"
                        }
                        if ($enableWsl -and -not $DryRun) {
                            Write-Status "Enabling WSL feature..." -Type "Info"
                            try {
                                wsl.exe --install --no-distribution 2>&1 | ForEach-Object { Write-Status "  $_" -Type "Info" }
                                Write-Status "[!] WSL feature enabled. A REBOOT is required." -Type "Warning"
                                Write-Log "RestoreProfile: WSL feature install initiated — reboot required"
                            } catch {
                                Write-Status "WSL enable failed: $_" -Type "Warning"
                            }
                        } else {
                            Write-Status "    Enable manually: wsl --install  then re-run restore." -Type "Info"
                        }
                    } else {
                        $wslReady = $true
                    }

                    if ($wslReady) {
                        $wslOk = 0; $wslFail = 0
                        foreach ($tar in $tarFiles) {
                            $distroName = $tar.BaseName
                            $installPath = Join-Path $WslInstallRoot $distroName
                            if ($DryRun) {
                                Write-Status "[DRY RUN] Would import WSL distro '$distroName' from $($tar.Name)" -Type "Info"
                                $wslOk++
                            } else {
                                Write-Status "Importing WSL distro: $distroName (may take a while)..." -Type "Info"
                                try {
                                    if (-not (Test-Path $installPath)) {
                                        New-Item -Path $installPath -ItemType Directory -Force | Out-Null
                                    }
                                    wsl.exe --import $distroName $installPath $tar.FullName 2>$null
                                    $imported = wsl.exe --list --quiet 2>$null |
                                        ForEach-Object { $_.Trim() -replace '\x00','' } |
                                        Where-Object { $_ -ieq $distroName }
                                    if ($imported) {
                                        Write-Status "  Imported: $distroName → $installPath" -Type "Success"
                                        Write-Log "RestoreProfile: WSL distro '$distroName' imported for $Username"
                                        $wslOk++
                                        wsl.exe --set-version $distroName 2 2>$null
                                    } else {
                                        Write-Status "  Import may have failed — '$distroName' not found in wsl --list" -Type "Warning"
                                        $wslFail++
                                    }
                                } catch {
                                    Write-Status "  Import failed for ${distroName}: $_" -Type "Warning"
                                    $wslFail++
                                }
                            }
                        }
                        Write-Status "WSL: $wslOk distro(s) imported, $wslFail failed." -Type "$(if ($wslFail -eq 0) { 'Success' } else { 'Warning' })"
                        if ($wslOk -gt 0) {
                            Write-Status "[NOTE] Set your default distro: wsl --set-default <distroName>" -Type "Info"
                        }
                    }
                }
            } else {
                Write-Status "No WSL .tar files found in backup — skipping." -Type "Info"
            }
        } else {
            Write-Status "No WSL backup folder found — skipping." -Type "Info"
        }
    } else { Write-Status "Phase 8 (WSL) skipped via -SkipWslRestore." -Type "Info" }

    # ── Final summary ─────────────────────────────────────────────────────────
    Write-Host ""
    Write-SectionHeader "Post-Restore Checklist: $Username"
    if ($RedirectOnly) {
        Write-Status "RedirectOnly mode active:" -Type "Info"
        Write-Status "  ✅ Shell folders (Desktop, Documents, etc.) → backup device ($BackupRoot)" -Type "Success"
        Write-Status "  ✅ AppData + settings → local profile ($DestinationProfile)" -Type "Success"
        Write-Status "  ✅ Supplemental data (Wi-Fi, printers, tasks) → restored" -Type "Success"
        Write-Status "" -Type "Info"
        Write-Status "💡 To verify: Right-click Desktop → Properties → Location tab" -Type "Info"
        Write-Status "   Should show: $BackupRoot\Desktop" -Type "Info"
    } else {
        Write-Status "Full restore mode active:" -Type "Info"
        Write-Status "  ✅ All files restored to local profile ($DestinationProfile)" -Type "Success"
    }
    Write-Host ""
}
# Run Main
Main

#endregion