# Requires -Version 7.0
<#
.SYNOPSIS
    WAN / BITS plugin for UserFolderMigrator.
    Detects high‑latency UNC paths and uses BITS for the initial bulk copy,
    then lets the main script finish with robocopy for mirroring.

.DESCRIPTION
    This plugin hooks into the PreFolder stage. If the current folder’s destination
    is a UNC path and the measured RTT (round‑trip time) exceeds 50 ms, it starts an
    asynchronous BITS transfer of the entire folder. After the transfer completes,
    control returns to the main script, which then runs its standard robocopy pass
    (e.g., with /MIR) to handle any changes that occurred during the BITS job.

    Benefits over plain robocopy on a WAN:
        – Automatic resilience to network interruptions.
        – Transfers survive reboots and resume from where they stopped.
        – Uses idle bandwidth only, does not interfere with user work.

.NOTES
    Version   : 1.0
    Author    : Generated for UserFolderMigrator
    Dependencies:
        – Main script version 7.4.0 or later (provides $script:HW and Write‑* functions).
        – PowerShell 7.0+ (Start-BitsTransfer requires PS 5.0+, but works in PS7).
#>

# ============================================================
#  Hook: PreFolder_UseBitsForWanFolders
#  Called by the main script before each folder is processed.
# ============================================================
function PreFolder_UseBitsForWanFolders {
    param($Context)

    # 1. Safety checks
    if ($Context['_DryRun'] -eq $true) {
        Write-Status "[WAN‑BITS] DryRun: BITS transfer skipped." -Type "Info"
        return $true
    }

    $source = $Context['SourcePath']
    $dest   = $Context['DestPath']

    if (-not $source -or -not $dest) {
        return $true   # nothing to do
    }

    # 2. Detect whether this is a high‑latency UNC destination
    $isHighLatencyUnc = $false
    $rttMs = $null

    # 2a. Check if destination is a UNC path (\\server\share)
    if ($dest -match '^\\\\[^\\]+\\[^\\]+') {
        $uncServer = ($dest -split '\\')[2]

        # 2b. Use hardware‑detected RTT if available (from main script)
        if ($script:HW -and $script:HW.DriveRttMs) {
            # Try to find which drive letter (if any) is mapped to this UNC
            $driveLetter = $null
            foreach ($dl in $script:HW.DriveRttMs.Keys) {
                $driveInfo = Get-PSDrive -Name $dl -ErrorAction SilentlyContinue
                if ($driveInfo -and $driveInfo.DisplayRoot -like "\\$uncServer\*") {
                    $driveLetter = $dl
                    break
                }
            }
            if ($driveLetter -and $script:HW.DriveRttMs.ContainsKey($driveLetter)) {
                $rttMs = $script:HW.DriveRttMs[$driveLetter]
                Write-Log "[WAN‑BITS] Using pre‑detected RTT for $driveLetter`: $rttMs ms"
            }
        }

        # 2c. If no cached RTT, perform a quick ping (4 samples)
        if (-not $rttMs) {
            Write-Status "[WAN‑BITS] Measuring latency to $uncServer ..." -Type "Info"
            try {
                $pingResult = Test-Connection -ComputerName $uncServer -Count 4 -ErrorAction Stop
                $rttMs = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
                Write-Log "[WAN‑BITS] Measured RTT to $uncServer : $rttMs ms"
            } catch {
                Write-Status "[WAN‑BITS] Could not ping $uncServer : $_" -Type "Warning"
                $rttMs = $null
            }
        }

        if ($rttMs -and $rttMs -gt 50) {
            $isHighLatencyUnc = $true
            Write-Status "[WAN‑BITS] High‑latency UNC destination detected (RTT = $([math]::Round($rttMs)) ms). Using BITS for bulk copy." -Type "Info"
        } else {
            Write-Status "[WAN‑BITS] Latency to $uncServer = $([math]::Round($rttMs)) ms – within normal range. Skipping BITS." -Type "Info"
            return $true
        }
    } else {
        # Not a UNC path – BITS would work only on local paths, but robocopy is fine.
        return $true
    }

    # 3. Perform BITS transfer
    try {
        # 3a. Ensure destination folder exists
        if (-not (Test-Path $dest)) {
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
            Write-Log "[WAN‑BITS] Created destination folder: $dest"
        }

        # 3b. Start an asynchronous BITS job for the whole folder
        Write-Status "[WAN‑BITS] Starting BITS transfer of $source to $dest" -Type "Info"
        $bitsJob = Start-BitsTransfer -Source $source -Destination $dest -Asynchronous -Priority Low

        # 3c. Wait for completion (poll every 5 seconds, with a generous timeout)
        $timeoutSeconds = 7200   # 2 hours – adjust as needed
        $startTime = Get-Date

        do {
            Start-Sleep -Seconds 5
            $bitsJob = Get-BitsTransfer -JobId $bitsJob.JobId -ErrorAction SilentlyContinue
            if (-not $bitsJob) {
                throw "BITS job disappeared unexpectedly"
            }

            # Show progress (optional)
            if ($bitsJob.BytesTransferred -gt 0 -and $bitsJob.BytesTotal -gt 0) {
                $percent = [math]::Round(($bitsJob.BytesTransferred / $bitsJob.BytesTotal) * 100, 1)
                Write-Status "[WAN‑BITS] Progress: $percent% transferred ($($bitsJob.BytesTransferred)/$($bitsJob.BytesTotal) bytes)" -Type "Info" -NoNewline
            }

            $elapsed = (Get-Date) - $startTime
            if ($elapsed.TotalSeconds -gt $timeoutSeconds) {
                throw "BITS job timed out after $timeoutSeconds seconds"
            }
        } while ($bitsJob.JobState -eq 'Transferring')

        # 3d. Finalise the job
        if ($bitsJob.JobState -eq 'Transferred') {
            Complete-BitsTransfer -BitsJob $bitsJob
            Write-Status "[WAN‑BITS] BITS transfer completed successfully." -Type "Success"
            Write-Log "[WAN‑BITS] Successfully copied $source to $dest via BITS"
        } else {
            $errorDetail = $bitsJob.ErrorDescription
            throw "BITS job finished with state '$($bitsJob.JobState)': $errorDetail"
        }
    } catch {
        Write-Status "[WAN‑BITS] BITS transfer failed: $_" -Type "Error"
        Write-Log "[WAN‑BITS] ERROR: $_ – falling back to robocopy"
        # Do NOT block the pipeline – returning $true will let the main script
        # fall back to its normal robocopy copy routine.
        return $true
    }

    # 4. After BITS is done, let the main script run its robocopy pass.
    #    That final pass will mirror any files that changed during the BITS job.
    Write-Status "[WAN‑BITS] Returning control to main script for final robocopy mirror." -Type "Info"
    return $true
}

# Export the hook so the main script can find it
Export-ModuleMember -Function PreFolder_UseBitsForWanFolders