#Requires -Version 7.0
<#
.SYNOPSIS
    UserFolderMigrator Plugin — Browser Profile Migrator
    Detects and migrates Chrome, Edge, Firefox, Brave, Opera, and Vivaldi
    profiles with automatic cache exclusion and lock-file detection.

.DESCRIPTION
    Hooks into PostUser to copy browser profiles after the main shell-folder
    migration. Cache, GPU, and Code Cache directories are always excluded,
    saving potentially GBs of throwaway data. Profiles from ALL users on the
    machine are mapped, or only the currently migrated user.

    Supported browsers (auto-detected):
      Google Chrome  · Microsoft Edge  · Firefox  · Brave  · Opera  · Vivaldi

.NOTES
    Plugin file  : UserFolderMigrator_BrowserProfileMigrator.psm1
    Drop into    : <script dir>\plugins\
    Hook stages  : PreMigration  — detect available browsers
                   PostUser      — copy profiles per user
                   PostMigration — print browser migration summary
    Inputs       : BrowserMigrateCache   (Y/N, default N) — include cache dirs
                   BrowserSkipIfRunning  (Y/N, default Y) — skip if browser open
                   BrowserList           (comma list or 'All') — filter browsers
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Module-scoped state ───────────────────────────────────────────────────────
$script:BPM_Results        = [System.Collections.Generic.List[object]]::new()
$script:BPM_MigrateCache   = $false
$script:BPM_SkipIfRunning  = $true
$script:BPM_BrowserFilter  = @('All')
$script:BPM_StartTime      = $null

# Canonical browser definitions: Name → relative AppData path + process name
$script:BPM_BrowserDefs = @(
    @{
        Name        = 'Chrome'
        RelPath     = 'AppData\Local\Google\Chrome\User Data'
        ProcessName = 'chrome'
        CacheDirs   = @('Cache','Code Cache','GPUCache','ShaderCache','DawnCache','WidevineCdm')
    },
    @{
        Name        = 'Edge'
        RelPath     = 'AppData\Local\Microsoft\Edge\User Data'
        ProcessName = 'msedge'
        CacheDirs   = @('Cache','Code Cache','GPUCache','ShaderCache','DawnCache')
    },
    @{
        Name        = 'Firefox'
        RelPath     = 'AppData\Roaming\Mozilla\Firefox'
        ProcessName = 'firefox'
        CacheDirs   = @()   # Firefox cache lives in Local; handled separately
        FirefoxMode = $true
    },
    @{
        Name        = 'Brave'
        RelPath     = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'
        ProcessName = 'brave'
        CacheDirs   = @('Cache','Code Cache','GPUCache','ShaderCache')
    },
    @{
        Name        = 'Opera'
        RelPath     = 'AppData\Roaming\Opera Software\Opera Stable'
        ProcessName = 'opera'
        CacheDirs   = @('Cache','Code Cache','GPUCache')
    },
    @{
        Name        = 'Vivaldi'
        RelPath     = 'AppData\Local\Vivaldi\User Data'
        ProcessName = 'vivaldi'
        CacheDirs   = @('Cache','Code Cache','GPUCache','ShaderCache')
    }
)

# ── Helpers ───────────────────────────────────────────────────────────────────
function BPM_Write {
    param([string]$Msg, [string]$Type = 'Info')
    try   { Write-Status -Message $Msg -Type $Type }
    catch { Write-Host "  [BPM] $Msg" }
}
function BPM_Log {
    param([string]$Msg)
    try   { Write-Log "[BrowserMigrator] $Msg" }
    catch { }
}
function BPM_Bytes {
    param([long]$B)
    if ($B -ge 1GB) { return "{0:N2} GB" -f ($B / 1GB) }
    if ($B -ge 1MB) { return "{0:N2} MB" -f ($B / 1MB) }
    if ($B -ge 1KB) { return "{0:N2} KB" -f ($B / 1KB) }
    return "$B B"
}

# ── DeclareInputs ─────────────────────────────────────────────────────────────
function BrowserMigrator_DeclareInputs {
    return @(
        @{
            Key              = 'BrowserMigrateCache'
            Prompt           = 'Include browser cache directories? (wastes GBs — not recommended)'
            Type             = 'YesNo'
            Default          = 'N'
            UnattendedDefault= 'N'
        },
        @{
            Key              = 'BrowserSkipIfRunning'
            Prompt           = 'Skip browser if its process is currently running? (Y/N)'
            Type             = 'YesNo'
            Default          = 'Y'
            UnattendedDefault= 'Y'
        },
        @{
            Key              = 'BrowserList'
            Prompt           = 'Browsers to migrate (All, or comma-separated: Chrome,Edge,Firefox)'
            Type             = 'String'
            Default          = 'All'
            UnattendedDefault= 'All'
        }
    )
}

# ── Stage: PreMigration — detect browsers, apply filter ──────────────────────
function PreMigration_BrowserProfileMigrator {
    param([hashtable]$Context)

    $script:BPM_StartTime      = [datetime]::UtcNow
    $script:BPM_MigrateCache   = [bool]($Context['BrowserMigrateCache'])
    $script:BPM_SkipIfRunning  = if ($Context.ContainsKey('BrowserSkipIfRunning')) { [bool]$Context['BrowserSkipIfRunning'] } else { $true }

    $filterRaw = if ($Context['BrowserList']) { $Context['BrowserList'] } else { 'All' }
    $script:BPM_BrowserFilter = $filterRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    BPM_Write "Browser Profile Migrator active." -Type 'Info'
    BPM_Write "Filter: $($script:BPM_BrowserFilter -join ', ') | Cache: $(if ($script:BPM_MigrateCache) {'Yes'} else {'Excluded'}) | SkipIfRunning: $($script:BPM_SkipIfRunning)" -Type 'Info'
    BPM_Log   "PreMigration — filter=$($filterRaw) cache=$($script:BPM_MigrateCache) skipRunning=$($script:BPM_SkipIfRunning)"
    return $true
}

function PostUser_BrowserProfileMigrator {
    param([hashtable]$Context)

    $username   = $Context['UserName']
    $dryRun     = [bool]($Context['_DryRun'])
    $mode       = $Context['Mode']   # 'RestoreProfile' injected by patched main script

    if ($mode -eq 'RestoreProfile') {
        BPM_Restore_User -Context $Context
    } else {
        BPM_Backup_User -Context $Context
    }
    return $true
}

# ── Backup path (Migrate / FullProfileBackup) ─────────────────────────────────
function BPM_Backup_User {
    param([hashtable]$Context)

    $username = $Context['UserName']
    $dest     = $Context['DestinationPath']
    $dryRun   = [bool]($Context['_DryRun'])

    if (-not $username -or -not $dest) { return $true }

    # Resolve source profile root
    $userProfileRoot = "C:\Users\$username"
    if (-not (Test-Path $userProfileRoot)) {
        BPM_Write "User profile path '$userProfileRoot' not found — skipping browser migration." -Type 'Warning'
        return $true
    }

    Write-Host ''
    BPM_Write "── Browser Profile Migration: $username ──" -Type 'Info'

    $browserDest = Join-Path $dest '_BrowserProfiles'

    foreach ($bDef in $script:BPM_BrowserDefs) {
        # Apply browser filter
        if ($script:BPM_BrowserFilter -notcontains 'All' -and
            $script:BPM_BrowserFilter -notcontains $bDef.Name) { continue }

        $srcPath = Join-Path $userProfileRoot $bDef.RelPath
        if (-not (Test-Path $srcPath)) {
            BPM_Write "  $($bDef.Name): not installed — skipped." -Type 'Info'
            continue
        }

        # Check if browser is running
        $isRunning = $false
        if ($script:BPM_SkipIfRunning) {
            $proc = Get-Process -Name $bDef.ProcessName -ErrorAction SilentlyContinue
            if ($proc) {
                $isRunning = $true
                BPM_Write "  $($bDef.Name): process running — skipped (close browser and re-run, or use -BrowserSkipIfRunning N)." -Type 'Warning'
                $script:BPM_Results.Add(@{
                    Browser  = $bDef.Name
                    Username = $username
                    Status   = 'Skipped-Running'
                    Bytes    = 0
                })
                BPM_Log "PostUser($username) — $($bDef.Name) skipped (process running)"
                continue
            }
        }

        # Build robocopy exclusion list for cache directories
        $excludeDirs = if (-not $script:BPM_MigrateCache -and $bDef.CacheDirs.Count -gt 0) {
            $bDef.CacheDirs
        } else { @() }

        # For Firefox: also exclude Local cache (separate tree)
        if ($bDef.FirefoxMode -and -not $script:BPM_MigrateCache) {
            $ffLocalCache = Join-Path $userProfileRoot 'AppData\Local\Mozilla\Firefox'
            # We copy only Roaming (profiles.ini + profile folders), exclude Local
        }

        $destPath = Join-Path $browserDest $bDef.Name
        if (-not $dryRun) {
            try { New-Item -Path $destPath -ItemType Directory -Force | Out-Null } catch { }
        }

        # Measure source size (excluding caches)
        $srcBytes = 0L
        try {
            $files = Get-ChildItem -Path $srcPath -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object {
                         $pathLower = $_.FullName.ToLower()
                         $skip = $false
                         foreach ($cd in $excludeDirs) {
                             if ($pathLower -like "*\$($cd.ToLower())\*") { $skip = $true; break }
                         }
                         -not $skip
                     }
            foreach ($f in $files) { $srcBytes += $f.Length }
        } catch { }

        BPM_Write "  $($bDef.Name): $(BPM_Bytes $srcBytes) to copy$(if ($excludeDirs.Count -gt 0) { " (cache excluded)" })..." -Type 'Info'

        if ($dryRun) {
            BPM_Write "  [DRY RUN] Would copy $($bDef.Name) → $destPath" -Type 'Info'
            $script:BPM_Results.Add(@{
                Browser  = $bDef.Name
                Username = $username
                Status   = 'DryRun'
                Bytes    = $srcBytes
                Source   = $srcPath
                Dest     = $destPath
            })
            BPM_Log "PostUser($username) — $($bDef.Name) DryRun src=$srcPath bytes=$srcBytes"
            continue
        }

        # Build robocopy args
        $rcArgs = [System.Collections.Generic.List[string]]::new()
        $rcArgs.Add("`"$srcPath`"")
        $rcArgs.Add("`"$destPath`"")
        $rcArgs.Add('/E')       # include subdirs
        $rcArgs.Add('/R:2')     # 2 retries
        $rcArgs.Add('/W:3')     # 3s wait
        $rcArgs.Add('/NP')      # no progress (we print our own)
        $rcArgs.Add('/NDL')     # no dir list noise
        $rcArgs.Add('/NFL')     # no file list noise
        $rcArgs.Add('/XO')      # skip older (delta)
        $rcArgs.Add('/MT:4')    # 4 threads

        foreach ($cd in $excludeDirs) {
            $rcArgs.Add("/XD")
            $rcArgs.Add("`"$cd`"")
        }

        $status = 'Failed'
        $copiedBytes = 0L
        try {
            $proc = Start-Process robocopy -ArgumentList ($rcArgs -join ' ') `
                        -Wait -NoNewWindow -PassThru -ErrorAction Stop
            # Robocopy exit codes: 0=no change, 1=ok copy, 2=extra, 3=ok+extra, 4+ = errors
            if ($proc.ExitCode -le 3) {
                $status = 'Success'
                $copiedBytes = $srcBytes  # approximate
                BPM_Write "  $($bDef.Name): migrated successfully. ($(BPM_Bytes $srcBytes))" -Type 'Success'
            } else {
                $status = 'Partial'
                BPM_Write "  $($bDef.Name): completed with warnings (robocopy exit $($proc.ExitCode))." -Type 'Warning'
            }
        } catch {
            $status = 'Error'
            BPM_Write "  $($bDef.Name): copy failed — $_" -Type 'Error'
            BPM_Log   "PostUser($username) — $($bDef.Name) error: $_"
        }

        $script:BPM_Results.Add(@{
            Browser  = $bDef.Name
            Username = $username
            Status   = $status
            Bytes    = $copiedBytes
            Source   = $srcPath
            Dest     = $destPath
        })
        BPM_Log "PostUser($username) — $($bDef.Name) status=$status bytes=$copiedBytes"
    }

    return $true
}

# ── Restore path (RestoreProfile) ────────────────────────────────────────────
function BPM_Restore_User {
    param([hashtable]$Context)

    $username          = $Context['UserName']
    $backupRoot        = $Context['BackupRoot']        # e.g. Y:\Data\Alice
    $destinationProfile = $Context['DestinationProfile'] # e.g. C:\Users\Alice
    $dryRun            = [bool]($Context['_DryRun'])

    if (-not $username -or -not $backupRoot -or -not $destinationProfile) { return $true }

    $browserBackupBase = Join-Path $backupRoot '_BrowserProfiles'
    if (-not (Test-Path $browserBackupBase)) {
        BPM_Write "No _BrowserProfiles folder in backup for '$username' — skipping browser restore." -Type 'Info'
        BPM_Log   "BPM_Restore_User($username) — no backup folder at $browserBackupBase"
        return $true
    }

    Write-Host ''
    BPM_Write "── Browser Profile Restore: $username ──" -Type 'Info'

    $backupDirs = @(Get-ChildItem -Path $browserBackupBase -Directory -ErrorAction SilentlyContinue)
    if ($backupDirs.Count -eq 0) {
        BPM_Write "  No browser backup folders found — skipping." -Type 'Warning'
        return $true
    }

    foreach ($bDir in $backupDirs) {
        ${bName} = $bDir.Name
        if ($script:BPM_BrowserFilter -notcontains 'All' -and
            $script:BPM_BrowserFilter -notcontains ${bName}) { continue }

        # Find matching browser def to get the correct restore target path
        $bDef = $script:BPM_BrowserDefs | Where-Object { $_.Name -eq ${bName} } | Select-Object -First 1
        if (-not $bDef) {
            BPM_Write "  ${bName}: no matching browser definition — skipping restore." -Type 'Warning'
            continue
        }

        $restoreDest = Join-Path $destinationProfile $bDef.RelPath
        $srcBytes = (Get-ChildItem $bDir.FullName -Recurse -File -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum

        BPM_Write "  ${bName}: restoring $(BPM_Bytes ([long]$srcBytes)) → $restoreDest..." -Type 'Info'

        # Warn about DPAPI-bound data
        if (${bName} -in 'Chrome','Edge') {
            BPM_Write "  [!] ${bName} saved passwords are DPAPI-bound to the source machine — they will not decrypt here." -Type 'Warning'
        }

        if ($dryRun) {
            BPM_Write "  [DRY RUN] Would restore ${bName} → $restoreDest" -Type 'Info'
            $script:BPM_Results.Add(@{ Browser=${bName}; Username=$username; Status='DryRun'; Bytes=[long]$srcBytes })
            continue
        }

        try { New-Item -Path $restoreDest -ItemType Directory -Force | Out-Null } catch { }

        $rcArgs = @(
            "`"$($bDir.FullName)`"", "`"$restoreDest`"",
            '/E', '/COPY:DAT', '/XO',
            '/R:2', '/W:3', '/NP', '/NDL', '/NFL', '/MT:4'
        )

        try {
            $proc = Start-Process robocopy -ArgumentList ($rcArgs -join ' ') `
                        -Wait -NoNewWindow -PassThru -ErrorAction Stop
            $status = if ($proc.ExitCode -le 3) { 'Success' } else { 'Partial' }
            $type   = if ($status -eq 'Success') { 'Success' } else { 'Warning' }
            BPM_Write "  ${bName}: restore $status (robocopy exit $($proc.ExitCode))." -Type $type
        } catch {
            $status = 'Error'
            BPM_Write "  ${bName}: restore failed — $_" -Type 'Error'
            BPM_Log   "BPM_Restore_User($username) — ${bName} error: $_"
        }

        $script:BPM_Results.Add(@{ Browser=${bName}; Username=$username; Status=$status; Bytes=[long]$srcBytes })
        BPM_Log "BPM_Restore_User($username) — ${bName} status=$status"
    }
    return $true
}

# ── Stage: PostMigration — summary ────────────────────────────────────────────
function PostMigration_BrowserProfileMigrator {
    param([hashtable]$Context)

    $elapsed = ([datetime]::UtcNow - $script:BPM_StartTime).TotalSeconds
    $ok      = @($script:BPM_Results | Where-Object { $_['Status'] -eq 'Success' })
    $warn    = @($script:BPM_Results | Where-Object { $_['Status'] -in 'Partial','Skipped-Running' })
    $fail    = @($script:BPM_Results | Where-Object { $_['Status'] -eq 'Error' })
    $dry     = @($script:BPM_Results | Where-Object { $_['Status'] -eq 'DryRun' })
    $totalB  = ($script:BPM_Results | Measure-Object -Property { $_['Bytes'] } -Sum).Sum

    Write-Host ''
    Write-Host '  ── Browser Profile Migrator Summary ───────────────────────' -ForegroundColor DarkCyan
    BPM_Write "  Migrated  : $($ok.Count) browser(s)" -Type $(if ($ok.Count -gt 0) { 'Success' } else { 'Info' })
    if ($dry.Count   -gt 0) { BPM_Write "  Dry-run   : $($dry.Count) browser(s)"     -Type 'Info'    }
    if ($warn.Count  -gt 0) { BPM_Write "  Warnings  : $($warn.Count) browser(s)"    -Type 'Warning' }
    if ($fail.Count  -gt 0) { BPM_Write "  Failed    : $($fail.Count) browser(s)"    -Type 'Error'   }
    BPM_Write "  Data      : $(BPM_Bytes ([long]$totalB))" -Type 'Info'
    BPM_Write "  Elapsed   : $([Math]::Round($elapsed, 1))s" -Type 'Info'

    foreach ($r in $script:BPM_Results) {
        $icon = switch ($r['Status']) {
            'Success'        { '[+]' }
            'DryRun'         { '[~]' }
            'Partial'        { '[!]' }
            'Skipped-Running'{ '[!]' }
            'Error'          { '[X]' }
            default          { '[.]' }
        }
        BPM_Write "    $icon $($r['Username']) / $($r['Browser']) → $($r['Status'])  ($(BPM_Bytes ([long]$r['Bytes'])))" -Type $(
            switch ($r['Status']) {
                'Success'  { 'Success' }
                'Error'    { 'Error'   }
                default    { 'Warning' }
            }
        )
    }

    Write-Host '  ──────────────────────────────────────────────────────────' -ForegroundColor DarkCyan
    Write-Host ''

    BPM_Log ("PostMigration — ok=$($ok.Count) warn=$($warn.Count) fail=$($fail.Count) " +
             "total=$(BPM_Bytes ([long]$totalB)) elapsed=${elapsed}s")
    return $true
}

Export-ModuleMember -Function @(
    'BrowserMigrator_DeclareInputs',
    'PreMigration_BrowserProfileMigrator',
    'PostUser_BrowserProfileMigrator',
    'PostMigration_BrowserProfileMigrator',
    'BPM_Backup_User',
    'BPM_Restore_User'
)
