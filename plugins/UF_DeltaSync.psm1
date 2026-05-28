#Requires -Version 7.0
<#
.SYNOPSIS
    UserFolderMigrator Plugin — Delta Sync
    Tracks file state across migration runs and skips unchanged files,
    dramatically reducing repeat-run copy times.

.DESCRIPTION
    Maintains a JSON manifest per-user at <Destination>\.ufm_delta\<Username>.json
    containing LastWriteTime + Size for every migrated file.
    On subsequent runs, only new or modified files are copied (robocopy /XO + manifest filter).
    Generates a delta summary report after each run.

.NOTES
    Plugin file  : UserFolderMigrator_DeltaSync.psm1
    Drop into    : <script dir>\plugins\
    Hook stages  : PreMigration  — loads manifest, injects /XO robocopy flag
                   PostUser      — updates manifest entries for the migrated user
                   PostMigration — writes delta summary to log
    Inputs       : DeltaAlgorithm (LastWriteTime | SHA256) — default LastWriteTime
                   DeltaForceFullScan — re-baseline all files (ignores manifest)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Module-scoped state ───────────────────────────────────────────────────────
$script:DS_Manifest      = [System.Collections.Generic.Dictionary[string, object]]::new(
                               [System.StringComparer]::OrdinalIgnoreCase)
$script:DS_ManifestPath  = $null
$script:DS_BaseDestination = $null   # set in PreMigration; used by PreUser/PostUser
$script:DS_Algorithm     = 'LastWriteTime'   # overridden by DeclareInputs
$script:DS_ForceFullScan = $false
$script:DS_Stats         = @{ New = 0; Modified = 0; Unchanged = 0; Errors = 0 }
$script:DS_StartTime     = $null

# ── Helper: safe Write-Status / Write-Log (graceful if main functions absent) ─
function DS_Write {
    param([string]$Msg, [string]$Type = 'Info')
    try   { Write-Status -Message $Msg -Type $Type }
    catch { Write-Host "  [DS] $Msg" }
}
function DS_Log {
    param([string]$Msg)
    try   { Write-Log "[DeltaSync] $Msg" }
    catch { }
}

# ── DeclareInputs: collected once by the host script's input wizard ───────────
function DeltaSync_DeclareInputs {
    return @(
        @{
            Key              = 'DeltaAlgorithm'
            Prompt           = 'Delta detection method (LastWriteTime is fast; SHA256 is exact)'
            Type             = 'String'
            Default          = 'LastWriteTime'
            UnattendedDefault= 'LastWriteTime'
        },
        @{
            Key              = 'DeltaForceFullScan'
            Prompt           = 'Force full re-baseline this run? (Y/N)'
            Type             = 'YesNo'
            Default          = 'N'
            UnattendedDefault= 'N'
        }
    )
}

# ── Stage: PreMigration — load manifest, configure options ────────────────────
function PreMigration_DeltaSync {
    param([hashtable]$Context)

    DS_Write "Delta Sync plugin active." -Type 'Info'

    # Read plugin inputs (may be empty if host hasn't collected them yet)
    $script:DS_Algorithm     = if ($Context['DeltaAlgorithm']) { $Context['DeltaAlgorithm'] } else { 'LastWriteTime' }
    $script:DS_ForceFullScan = [bool]($Context['DeltaForceFullScan'])
    $script:DS_StartTime     = [datetime]::UtcNow

    # Reset stats for this run
    $script:DS_Stats = @{ New = 0; Modified = 0; Unchanged = 0; Errors = 0 }

    $dest = $Context['Destination']
    if (-not $dest) {
        DS_Write "No Destination in context — delta manifest location unknown. Skipping." -Type 'Warning'
        return $true
    }
    $script:DS_BaseDestination = $dest   # cache for PreUser/PostUser which lack this key

    # Locate / initialise manifest store
    $deltaDir = Join-Path $dest '.ufm_delta'
    if (-not (Test-Path $deltaDir)) {
        try { New-Item -Path $deltaDir -ItemType Directory -Force | Out-Null } catch { }
        # Hide the folder
        try { (Get-Item $deltaDir -ErrorAction SilentlyContinue).Attributes = 'Hidden','Directory' } catch { }
    }
    $script:DS_ManifestPath = $null   # will be set per-user in PreUser

    if ($script:DS_ForceFullScan) {
        DS_Write "Force full-scan requested — baseline will be rebuilt this run." -Type 'Warning'
    }

    DS_Write "Algorithm: $($script:DS_Algorithm) | ManifestDir: $deltaDir" -Type 'Info'
    DS_Log   "PreMigration — algorithm=$($script:DS_Algorithm) force=$($script:DS_ForceFullScan)"
    return $true
}

# ── Stage: PreUser — load per-user manifest ───────────────────────────────────
function PreUser_DeltaSync {
    param([hashtable]$Context)

    # BaseDestination is present in PreUser context; fall back to module-scoped cache from PreMigration
    $baseDest = if ($Context['BaseDestination']) { $Context['BaseDestination'] } else { $script:DS_BaseDestination }
    $username = $Context['UserName']
    if (-not $baseDest -or -not $username) { return $true }

    $deltaDir  = Join-Path $baseDest '.ufm_delta'
    $script:DS_ManifestPath = Join-Path $deltaDir "$username.json"

    $script:DS_Manifest.Clear()

    if ((Test-Path $script:DS_ManifestPath) -and -not $script:DS_ForceFullScan) {
        try {
            $raw = Get-Content $script:DS_ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
            foreach ($k in $raw.Keys) { $script:DS_Manifest[$k] = $raw[$k] }
            DS_Write "Loaded delta manifest: $($script:DS_Manifest.Count) entries for '$username'." -Type 'Info'
            DS_Log   "PreUser($username) — manifest loaded ($($script:DS_Manifest.Count) entries)"

            # Inject /XO into the main script's robocopy args so unchanged files are skipped
            try {
                if (-not $script:UFM_Plugin_ExtraRoboArgs.Contains('/XO')) {
                    $script:UFM_Plugin_ExtraRoboArgs.Add('/XO')
                    DS_Write "Delta mode: /XO injected — unchanged files will be skipped." -Type 'Info'
                    DS_Log   "PreUser($username) — /XO injected into UFM_Plugin_ExtraRoboArgs"
                }
            } catch {
                DS_Write "Could not inject /XO (UFM_Plugin_ExtraRoboArgs unavailable — update main script)." -Type 'Warning'
            }
        } catch {
            DS_Write "Could not read delta manifest ($username) — full sync this run: $_" -Type 'Warning'
            DS_Log   "PreUser($username) — manifest read error: $_"
        }
    } else {
        DS_Write "No manifest for '$username' — full baseline this run." -Type 'Info'
        DS_Log   "PreUser($username) — first run / forced baseline"
    }
    return $true
}

# ── Stage: PostUser — update manifest from migrated files ────────────────────
function PostUser_DeltaSync {
    param([hashtable]$Context)

    # DestinationPath is the user-specific path (e.g. Y:\Data\Alice) — use directly
    $userDest = $Context['DestinationPath']
    $username = $Context['UserName']
    if (-not $userDest -or -not $username -or -not $script:DS_ManifestPath) { return $true }

    $dryRun = [bool]($Context['_DryRun'])

    DS_Write "Updating delta manifest for '$username'..." -Type 'Info'
    DS_Log   "PostUser($username) — scanning destination for manifest update"

    if (-not (Test-Path $userDest)) {
        DS_Write "User destination '$userDest' not found — skipping manifest update." -Type 'Warning'
        return $true
    }

    $newManifest = [System.Collections.Generic.Dictionary[string, object]]::new(
                       [System.StringComparer]::OrdinalIgnoreCase)
    $newCount = 0; $modCount = 0; $sameCount = 0

    try {
        $files = Get-ChildItem -Path $userDest -Recurse -File -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            $relPath = $f.FullName.Substring($userDest.Length).TrimStart('\','/')
            $entry   = DS_BuildEntry -File $f

            if ($script:DS_Manifest.ContainsKey($relPath)) {
                $old = $script:DS_Manifest[$relPath]
                if (DS_HasChanged -Old $old -New $entry) { $modCount++ } else { $sameCount++ }
            } else {
                $newCount++
            }
            $newManifest[$relPath] = $entry
        }

        $script:DS_Stats.New       += $newCount
        $script:DS_Stats.Modified  += $modCount
        $script:DS_Stats.Unchanged += $sameCount

        if (-not $dryRun) {
            $newManifest | ConvertTo-Json -Depth 5 -Compress |
                Set-Content -Path $script:DS_ManifestPath -Encoding UTF8 -Force
            DS_Write "Manifest saved: $($newManifest.Count) entries → $($script:DS_ManifestPath)" -Type 'Success'
        } else {
            DS_Write "[DRY RUN] Would save manifest: $($newManifest.Count) entries." -Type 'Info'
        }

        DS_Log "PostUser($username) — new=$newCount modified=$modCount unchanged=$sameCount"
    } catch {
        $script:DS_Stats.Errors++
        DS_Write "Manifest update error for '$username': $_" -Type 'Warning'
        DS_Log   "PostUser($username) — error: $_"
    } finally {
        # Always remove /XO after this user — prevents bleed into next user or other modes
        try { [void]$script:UFM_Plugin_ExtraRoboArgs.Remove('/XO') } catch { }
    }
    return $true
}

# ── Stage: PostMigration — print delta summary ────────────────────────────────
function PostMigration_DeltaSync {
    param([hashtable]$Context)

    $elapsed = ([datetime]::UtcNow - $script:DS_StartTime).TotalSeconds

    Write-Host ''
    Write-Host '  ── Delta Sync Summary ─────────────────────────────────────' -ForegroundColor DarkCyan
    DS_Write "  New files      : $($script:DS_Stats.New)"       -Type 'Success'
    DS_Write "  Modified files : $($script:DS_Stats.Modified)"  -Type $(if ($script:DS_Stats.Modified -gt 0) { 'Warning' } else { 'Info' })
    DS_Write "  Unchanged      : $($script:DS_Stats.Unchanged)" -Type 'Info'
    DS_Write "  Errors         : $($script:DS_Stats.Errors)"    -Type $(if ($script:DS_Stats.Errors -gt 0) { 'Error' } else { 'Info' })
    DS_Write "  Elapsed        : $([Math]::Round($elapsed, 1))s" -Type 'Info'
    Write-Host '  ──────────────────────────────────────────────────────────' -ForegroundColor DarkCyan
    Write-Host ''

    DS_Log ("PostMigration — summary: new=$($script:DS_Stats.New) " +
            "mod=$($script:DS_Stats.Modified) same=$($script:DS_Stats.Unchanged) " +
            "err=$($script:DS_Stats.Errors) elapsed=${elapsed}s")
    return $true
}

# ── Public: Test-FileDeltaChanged — call from main script if needed ───────────
function Test-FileDeltaChanged {
    <#
    .SYNOPSIS
        Returns $true if the file has changed since the last delta manifest entry.
        Uses the algorithm configured via DeltaAlgorithm plugin input.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.IO.FileInfo]$File,
        [Parameter(Mandatory)] [string]$RelativePath
    )
    if (-not $script:DS_Manifest.ContainsKey($RelativePath)) { return $true }
    $old   = $script:DS_Manifest[$RelativePath]
    $entry = DS_BuildEntry -File $File
    return DS_HasChanged -Old $old -New $entry
}

# ── Internal helpers ──────────────────────────────────────────────────────────
function DS_BuildEntry {
    param([System.IO.FileInfo]$File)
    $entry = @{
        Size = $File.Length
        Mtime = $File.LastWriteTimeUtc.ToString('o')
    }
    if ($script:DS_Algorithm -eq 'SHA256') {
        try {
            $entry['Hash'] = (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            $entry['Hash'] = ''
        }
    }
    return $entry
}

function DS_HasChanged {
    param([object]$Old, [hashtable]$New)
    if ($script:DS_Algorithm -eq 'SHA256') {
        $oldHash = if ($Old -is [hashtable]) { $Old['Hash'] } else { $Old.Hash }
        return ($oldHash -ne $New['Hash'])
    }
    # LastWriteTime + Size
    $oldMtime = if ($Old -is [hashtable]) { $Old['Mtime'] } else { $Old.Mtime }
    $oldSize  = if ($Old -is [hashtable]) { $Old['Size']  } else { $Old.Size  }
    return ($oldMtime -ne $New['Mtime'] -or $oldSize -ne $New['Size'])
}

Export-ModuleMember -Function @(
    'DeltaSync_DeclareInputs',
    'PreMigration_DeltaSync',
    'PreUser_DeltaSync',
    'PostUser_DeltaSync',
    'PostMigration_DeltaSync',
    'Test-FileDeltaChanged'
)
