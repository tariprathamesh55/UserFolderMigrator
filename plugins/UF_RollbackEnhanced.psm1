
<#
.SYNOPSIS
    UF.Migration.RollbackEnhanced — VSS-based rollback, transaction log, granular restore.
    Hook points: PreMigration, PostMigration, Rollback

.STYLE GUIDE
    Functions: PascalCase
    Parameters: PascalCase
    Local Variables: camelCase

.NOTES
    Depends on: UF.Core, UF.Registry, UF.FileSystem, UF.Logging, UF.UI
    Hook naming: PreMigration_CreateRollbackPoint, Rollback_RestoreFromVss
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fallback: if main script has not defined Write-ErrorGuard, provide a minimal shim
if (-not (Get-Command 'Write-ErrorGuard' -ErrorAction SilentlyContinue)) {
    function Write-ErrorGuard {
        param(
            [string]$Operation  = '',
            [string]$ErrorType  = '',
            [string]$Item       = '',
            [string]$Severity   = 'Warning',
            [string]$SkipReason = '',
            [hashtable]$Recovery    = @{},
            [hashtable]$Diagnostics = @{}
        )
        $msg = "[$Operation] $ErrorType"
        if ($SkipReason) { $msg += " — $SkipReason" }
        switch ($Severity) {
            'Warning' { Write-Warning $msg }
            'Error'   { Write-Error $msg -ErrorAction Continue }
            default   { Write-Warning $msg }
        }
    }
}

# ── Module Manifest ───────────────────────────────────────────────────────────

# Module state
$script:TransactionLogPath = $null
$script:CurrentTransactionId = $null

#region ── VSS Rollback Points ─────────────────────────────────────────────────

<#
.SYNOPSIS
    Creates a VSS snapshot of specified volumes before migration starts.
    Stores snapshot GUID in transaction log for later rollback.
.PARAMETER Volumes Array of volume letters (e.g., @('C', 'D')).
.PARAMETER Label Description for this rollback point.
.PARAMETER TransactionId Optional existing transaction ID.
.PARAMETER DryRun If true, only simulates.
.OUTPUTS [PSCustomObject] with RollbackId, VolumeSnapshots, and Status.
#>
function New-VssRollbackPoint {
    param(
        [string[]]$Volumes = @('C'),
        [string]$Label = "Pre-migration $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        [string]$TransactionId = '',
        [bool]$DryRun = $false
    )

    $result = [PSCustomObject]@{
        RollbackId = if ($TransactionId) { $TransactionId } else { [Guid]::NewGuid().ToString() }
        Timestamp = Get-Date
        Label = $Label
        VolumeSnapshots = [System.Collections.Generic.List[PSCustomObject]]::new()
        Status = 'Pending'
    }

    Write-SectionHeader "Creating VSS Rollback Point"
    Write-Status "Label: $Label" -Type "Info"
    Write-Status "Volumes: $($Volumes -join ', ')" -Type "Info"

    if ($DryRun) {
        Write-Status "[DRY RUN] Would create VSS snapshots for $($Volumes.Count) volume(s)" -Type "Info"
        $result.Status = 'DryRun'
        return $result
    }

    foreach ($volume in $Volumes) {
        $volumeLetter = $volume.TrimEnd(':').ToUpper() + ':\'
        try {
            # Create VSS shadow copy
            $shadow = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create `
                -Arguments @{ Context = 'ClientAccessible'; Volume = $volumeLetter }
            
            if ($shadow.ReturnValue -ne 0) {
                throw "VSS create failed with code $($shadow.ReturnValue)"
            }

            $shadowObject = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }
            
            $snapshot = [PSCustomObject]@{
                Volume = $volumeLetter
                ShadowId = $shadow.ShadowID
                DeviceObject = $shadowObject.DeviceObject
                CreatedTime = Get-Date
            }
            $result.VolumeSnapshots.Add($snapshot)
            
            Write-Status "  Snapshot created for $volumeLetter : $($shadowObject.DeviceObject)" -Type "Success"
            Write-Log "VSSRollback: snapshot for $volumeLetter -> $($shadowObject.DeviceObject)"
        } catch {
            Write-ErrorGuard -Operation "VSSSnapshot" -ErrorType $_.Exception.Message `
                -Item $volumeLetter -Severity "Warning" `
                -SkipReason "VSS snapshot skipped for $volumeLetter — other volumes continue, rollback may be incomplete" `
                -Diagnostics @{ "Volume" = $volumeLetter; "Label" = $Label } `
                -Recovery @{ Hint = "Check VSS service is running: Get-Service VSS | Start-Service. Run as Administrator." }
            $result.Status = 'PartialFailure'
            Write-Log "VSSRollback: ERROR on $volumeLetter — $($_.Exception.Message)" -Level "ERROR"
        }
    }

    if ($result.VolumeSnapshots.Count -gt 0) {
        $result.Status = 'Created'
        
        # Store in transaction log
        $logEntry = [PSCustomObject]@{
            Event = 'RollbackPointCreated'
            RollbackId = $result.RollbackId
            Timestamp = $result.Timestamp
            Label = $Label
            Volumes = $Volumes
            Snapshots = $result.VolumeSnapshots
        }
        # BUGFIX: Write-TransactionLog returns $transId (a string). Without $null capture,
        # that string lands in this function's pipeline output. New-VssRollbackPoint then
        # returns [string, PSCustomObject] and $result.Status in the hook throws under strict mode.
        $null = Write-TransactionLog -Entry $logEntry -TransactionId $result.RollbackId
    }

    return $result
}

<#
.SYNOPSIS
    Lists available rollback points from transaction logs.
.PARAMETER Limit Maximum number of points to return (0 = all).
.OUTPUTS [array] of rollback point objects.
#>
function Get-RollbackPoints {
    param([int]$Limit = 0)

    $rollbackPoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    # Check multiple locations for rollback data
    $searchPaths = @(
        $script:TransactionLogPath,
        (Join-Path (Get-SafeTempPath) "UserFolderMigrator_Rollback"),
        (Join-Path $PSScriptRoot "UserFolderMigrator_Rollback")
    )

    foreach ($searchPath in $searchPaths) {
        if (-not $searchPath -or -not (Test-Path $searchPath)) { continue }
        
        $logFiles = Get-ChildItem -Path $searchPath -Filter "rollback_*.json" -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending
        
        foreach ($file in $logFiles) {
            try {
                $data = Get-Content $file.FullName -Raw | ConvertFrom-Json
                $rollbackPoints.Add([PSCustomObject]@{
                    RollbackId = $data.RollbackId
                    Timestamp = $data.Timestamp
                    Label = $data.Label
                    FilePath = $file.FullName
                    Volumes = $data.Volumes -join ', '
                })
            } catch { }
        }
    }

    if ($Limit -gt 0 -and $rollbackPoints.Count -gt $Limit) {
        $rollbackPoints = $rollbackPoints[0..($Limit-1)]
    }

    Write-Status "Found $($rollbackPoints.Count) rollback point(s)" -Type "Info"
    foreach ($rp in $rollbackPoints) {
        Write-Host "  - $($rp.Timestamp) : $($rp.Label) [ID: $($rp.RollbackId)]" -ForegroundColor Gray
    }

    return $rollbackPoints
}

<#
.SYNOPSIS
    Restores from a VSS rollback point by reverting files to snapshot state.
.PARAMETER RollbackId The ID of the rollback point to restore.
.PARAMETER Paths Specific paths to restore (empty = all paths in snapshot).
.PARAMETER DryRun If true, only simulates.
.OUTPUTS [bool] $true on success.
#>
function Restore-FromRollbackPoint {
    param(
        [Parameter(Mandatory)][string]$RollbackId,
        [string[]]$Paths = @(),
        [bool]$DryRun = $false
    )

    Write-SectionHeader "Restoring from Rollback Point: $RollbackId"
    
    # Locate the rollback data
    $rollbackData = $null
    $searchPaths = @(
        $script:TransactionLogPath,
        (Join-Path (Get-SafeTempPath) "UserFolderMigrator_Rollback"),
        (Join-Path $PSScriptRoot "UserFolderMigrator_Rollback")
    )

    foreach ($searchPath in $searchPaths) {
        if (-not $searchPath -or -not (Test-Path $searchPath)) { continue }
        
        $logFile = Join-Path $searchPath "rollback_$RollbackId.json"
        if (Test-Path $logFile) {
            $rollbackData = Get-Content $logFile -Raw | ConvertFrom-Json
            break
        }
    }

    if (-not $rollbackData) {
        Write-Status "Rollback point not found: $RollbackId" -Type "Error"
        return $false
    }

    Write-Status "Found rollback point: $($rollbackData.Label)" -Type "Info"
    Write-Status "Created: $($rollbackData.Timestamp)" -Type "Info"

    if ($DryRun) {
        Write-Status "[DRY RUN] Would restore from VSS snapshots" -Type "Info"
        return $true
    }

    $success = $true
    foreach ($snapshot in $rollbackData.Snapshots) {
        Write-Status "Restoring from snapshot: $($snapshot.Volume)" -Type "Info"
        
        $sourceVss   = $snapshot.DeviceObject.TrimEnd('\') + '\'
        $targetVolume = $snapshot.Volume

        # H5: True rollback — purge files created AFTER snapshot before restoring
        # This prevents merge state where new files coexist with restored old files
        if ($Paths.Count -gt 0) {
            Write-Status "  Purging post-snapshot files before restore..." -Type "Info"
            foreach ($targetPath in $Paths) {
                if (Test-Path $targetPath) {
                    $vssEquivalent = Join-Path $sourceVss ($targetPath.Substring($targetVolume.TrimEnd('\').Length).TrimStart('\'))
                    if (-not (Test-Path $vssEquivalent)) {
                        Write-Log "Rollback purge: $targetPath (not in snapshot)"
                        Remove-Item -LiteralPath $targetPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        
        $robocopyArgs = @(
            "`"$sourceVss`"", "`"$targetVolume`"",
            '/E', '/COPY:DAT', '/PURGE', '/R:3', '/W:5', '/MT:8', '/NP'
        )
        
        if ($Paths.Count -gt 0) {
            foreach ($path in $Paths) {
                $robocopyArgs += '/IF'
                $robocopyArgs += $path
            }
        }
        
        $process = Start-Process -FilePath 'robocopy.exe' -ArgumentList $robocopyArgs `
            -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -gt 7) {
            Write-ErrorGuard -Operation "RollbackRestore" `
                -ErrorType "Robocopy exited with code $($process.ExitCode)" `
                -Item $snapshot.Volume -Severity "Error" `
                -SkipReason "Restore failed for this volume — other volumes continue" `
                -Recovery @{ Command = "robocopy `"$sourceVss`" `"$targetVolume`" /E /PURGE /COPY:DAT /R:3 /W:5"; Hint = "Run manually to complete restore" }
            $success = $false
        } else {
            Write-Status "  Restore successful for $($snapshot.Volume)" -Type "Success"
            Write-Log "Rollback restore: $($snapshot.Volume) from VSS snapshot $($snapshot.ShadowId)"
        }
    }

    # Log the restore action
    # BUGFIX: same pipeline pollution fix as New-VssRollbackPoint — capture return value
    $null = Write-TransactionLog -Entry @{
        Event = 'RestorePerformed'
        RollbackId = $RollbackId
        Timestamp = Get-Date
        PathsRestored = $Paths
        Success = $success
    }

    return $success
}

#endregion

#region ── Transaction Log ─────────────────────────────────────────────────────

<#
.SYNOPSIS
    Writes an entry to the transaction log for audit and rollback purposes.
.PARAMETER Entry Hashtable or PSCustomObject with log entry data.
.PARAMETER TransactionId Transaction ID (creates new if not provided).
.OUTPUTS [string] Transaction ID.
#>
function Write-TransactionLog {
    param(
        [Parameter(Mandatory)]$Entry,
        [string]$TransactionId = ''
    )

    $transId = if ($TransactionId) { $TransactionId } else { [Guid]::NewGuid().ToString() }
    
    # Determine log directory
    if (-not $script:TransactionLogPath) {
        $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $script:TransactionLogPath = Join-Path $base "UserFolderMigrator_Transactions"
        if (-not (Test-Path $script:TransactionLogPath)) {
            New-Item $script:TransactionLogPath -ItemType Directory -Force | Out-Null
        }
    }

    $logFile = Join-Path $script:TransactionLogPath "transactions_$(Get-Date -Format 'yyyyMMdd').jsonl"
    
    $logLine = [PSCustomObject]@{
        TransactionId = $transId
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        Entry = $Entry
    } | ConvertTo-Json -Compress -Depth 5

    Add-Content -Path $logFile -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    
    # Also maintain per-rollback file
    if ($Entry.Event -eq 'RollbackPointCreated' -or $Entry.RollbackId) {
        $rbId = if ($Entry.RollbackId) { $Entry.RollbackId } else { $transId }
        $rbFile = Join-Path $script:TransactionLogPath "rollback_$rbId.json"
        $Entry | ConvertTo-Json -Depth 5 | Set-Content $rbFile -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    return $transId
}

<#
.SYNOPSIS
    Repairs a corrupted or incomplete transaction log.
.PARAMETER TransactionId Specific transaction to repair.
.PARAMETER RepairFile Path to backup/recovery file.
.OUTPUTS [bool] $true on success.
#>
function Repair-TransactionLog {
    param(
        [string]$TransactionId = '',
        [string]$RepairFile = ''
    )

    Write-Status "Repairing transaction log..." -Type "Info"

    if (-not $script:TransactionLogPath -or -not (Test-Path $script:TransactionLogPath)) {
        Write-Status "Transaction log directory not found" -Type "Error"
        return $false
    }

    $repaired = 0
    $corruptFiles = Get-ChildItem -Path $script:TransactionLogPath -Filter "rollback_*.json" |
                    Where-Object { (Get-Content $_.FullName -Raw | Measure-Object).Characters -eq 0 }

    foreach ($file in $corruptFiles) {
        if ($TransactionId -and $file.Name -notlike "*$TransactionId*") { continue }
        
        if ($RepairFile -and (Test-Path $RepairFile)) {
            Copy-Item $RepairFile $file.FullName -Force
            Write-Status "  Repaired: $($file.Name)" -Type "Success"
            $repaired++
        } else {
            Write-Status "  Skipped: $($file.Name) (no repair file)" -Type "Warning"
        }
    }

    Write-Status "Repaired $repaired file(s)" -Type "Info"
    return $repaired -gt 0
}

#endregion

#region ── Hook System Wrappers ────────────────────────────────────────────────

<#
.SYNOPSIS
    Hook that creates a VSS rollback point before migration begins.
    Called automatically at PreMigration hook point.
#>
function PreMigration_CreateRollbackPoint {
    param($Context)
    
    if ($Context.SkipRollbackPoint -eq $true) {
        Write-Log "Rollback point creation skipped by context"
        return $true
    }
    
    $result = New-VssRollbackPoint -Volumes @('C') -Label "Pre-migration for $($Context.Username)" -DryRun $Context.DryRun
    
    if ($result.Status -eq 'Created' -or $result.Status -eq 'DryRun') {
        $Context.RollbackId = $result.RollbackId
        return $true
    }
    
    return $false
}

<#
.SYNOPSIS
    Hook that restores from rollback point if migration fails.
    Called automatically at Rollback hook point.
#>
function Rollback_RestoreFromSnapshot {
    param($Context)
    
    if (-not $Context.RollbackId) {
        Write-Status "No rollback ID provided for automatic rollback" -Type "Warning"
        return $false
    }
    
    return Restore-FromRollbackPoint -RollbackId $Context.RollbackId -DryRun $Context.DryRun
}

# Update exports
Export-ModuleMember -Function 'PreMigration_CreateRollbackPoint', 'Rollback_RestoreFromSnapshot'