# ======================================================================
# UserFolderMigrator_Watchdog.psm1
# 
# Plugin for UserFolderMigrator.ps1 — automatically starts a background
# runspace that monitors the main script's heartbeat and sends alerts
# if the script crashes, hangs, or terminates unexpectedly.
#
# REQUIRES ZERO CHANGES TO THE MAIN SCRIPT.
# Uses UserFolderMigrator's existing email infrastructure (Send-MigrationNotification,
# Write-AuditEntry, Write-EventLogEntry, Send-SyslogMessage).
#
# Installation:
#   1. Drop this file alongside UserFolderMigrator.ps1
#   2. Update UserFolderMigrator_Plugins.manifest.json with the SHA-256 of this file
#   3. Run UserFolderMigrator normally — the watchdog starts automatically
#
# Exported Hooks (Stage_Action convention):
#   PreMigration_StartWatchdog  — launches background monitor
#   PostSession_StopWatchdog    — stops monitor and cleans up
#
# Heartbeat Strategy:
#   Patches Write-ProgressBar at runtime to inject heartbeat updates
#   on every progress bar refresh. This ensures heartbeat updates even
#   during long single-folder operations.
#
# Alerts On: Script crash, unexpected termination, script hung
# Heartbeat: Every 30 seconds (via progress bar patch)
# Alert Threshold: 120 seconds without heartbeat
# Debounce: 3 consecutive failures before "hung" alert
# ======================================================================



# ======================================================================
# MODULE PRIVATE HELPERS
# ======================================================================

# ── Alert Dispatcher ──────────────────────────────────────────────────
# Sends alerts through every channel UserFolderMigrator supports.
# Uses script-scope variables from the main script (access via $script:)
$script:UserFolderMigrator_Watchdog_SendAlert = {
    param(
        [string]$Subject,
        [string]$Body,
        [string]$Status = 'Error'
    )

    $sentAny = $false

    # ── 1. UserFolderMigrator Email Notification ─────────────────────────────────
    if ($script:NotificationEmail) {
        try {
            # Use UserFolderMigrator's own notification function if available
            $notifyFn = Get-Command 'Send-MigrationNotification' -ErrorAction SilentlyContinue
            if ($notifyFn) {
                & $notifyFn -Subject $Subject -Body $Body -Status $Status
                $sentAny = $true
            }
        } catch { }
    }

    # ── 2. UserFolderMigrator Event Log ─────────────────────────────────────────
    try {
        $eventFn = Get-Command 'Write-EventLogEntry' -ErrorAction SilentlyContinue
        if ($eventFn) {
            $eventType = if ($Status -eq 'Error') { 'Error' } else { 'Warning' }
            & $eventFn -Message "Watchdog: $Subject — $Body" -EntryType $eventType -EventId 1004
            $sentAny = $true
        }
    } catch { }

    # ── 3. UserFolderMigrator Audit Log (HMAC-signed) ───────────────────────────
    try {
        $auditFn = Get-Command 'Write-AuditEntry' -ErrorAction SilentlyContinue
        if ($auditFn) {
            & $auditFn -Message "WATCHDOG: $Subject — $Body" -Level $(if ($Status -eq 'Error') { 'ERROR' } else { 'WARN' })
            $sentAny = $true
        }
    } catch { }

    # ── 4. UserFolderMigrator Syslog ───────────────────────────────────────────
    try {
        $syslogFn = Get-Command 'Send-SyslogMessage' -ErrorAction SilentlyContinue
        if ($syslogFn) {
            $severity = if ($Status -eq 'Error') { 3 } else { 4 }
            & $syslogFn -Message "UserFolderMigrator Watchdog: $Subject — $Body" -Severity $severity
            $sentAny = $true
        }
    } catch { }

    # ── 5. Dead Letter Fallback ──────────────────────────────────
    if (-not $sentAny) {
        try {
            $dlDir = if ($script:LogFile) { Split-Path $script:LogFile -Parent } else { $env:TEMP }
            $dlFile = Join-Path $dlDir 'UserFolderMigrator_Watchdog_DeadLetter.log'
            $entry = @"

========================================
TIMESTAMP: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
SUBJECT:   $Subject
STATUS:    $Status
BODY:      $Body
========================================

"@
            Add-Content -Path $dlFile -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch { }
    }
}

# ======================================================================
# PRE-MIGRATION HOOK: Start Watchdog
# ======================================================================

function PreMigration_StartWatchdog {
    [CmdletBinding()]
    param($Context)

    # ── Guard: Only start if email is configured ──────────────────────
    if (-not $script:NotificationEmail -and -not $script:EnableSyslog) {
        return
    }

    # ── Determine heartbeat directory ─────────────────────────────────
    $logDir = if ($script:LogFile) {
        Split-Path $script:LogFile -Parent
    } else {
        Join-Path ($PSScriptRoot ?? (Get-Location).Path) 'UFM_Logs'
    }
    $heartbeatDir = Join-Path $logDir 'Watchdog'
    if (-not (Test-Path $heartbeatDir)) {
        New-Item -Path $heartbeatDir -ItemType Directory -Force | Out-Null
    }

    $config = @{
        HeartbeatFile      = Join-Path $heartbeatDir 'heartbeat.json'
        StopFile           = Join-Path $heartbeatDir 'watchdog_stop.txt'
        StaleThresholdSec  = 120
        CheckIntervalSec   = 30
        MaxConsecutive     = 3
        ComputerName       = $env:COMPUTERNAME
        UserName           = $env:USERNAME
        MainPID            = $PID
        Mode               = $script:ReportMode
    }

    # ── Remove stale files from previous runs ────────────────────────
    Remove-Item $config.StopFile -Force -ErrorAction SilentlyContinue
    Remove-Item $config.HeartbeatFile -Force -ErrorAction SilentlyContinue

    # ── Write initial heartbeat ──────────────────────────────────────
    @{
        StartTime  = (Get-Date -Format 'o')
        Computer   = $config.ComputerName
        User       = $config.UserName
        Mode       = $config.Mode
        PID        = $config.MainPID
        Status     = 'Watchdog started'
    } | ConvertTo-Json -Compress | Set-Content $config.HeartbeatFile -Force

    # ── Strategy: Patch Write-ProgressBar for heartbeat injection ────
    # Save the original function and its definition
    $script:UserFolderMigrator_Watchdog_OriginalWPB = ${function:Write-ProgressBar}
    $script:UserFolderMigrator_Watchdog_Config      = $config

    # Override Write-ProgressBar with a wrapper that adds heartbeat
    ${function:Write-ProgressBar} = {
        param(
            [int]$Current,
            [int]$Total,
            [string]$FolderName,
            [long]$DoneBytes,
            [long]$TotalBytes,
            [double]$SpeedMBps,
            [int]$EtaSec,
            [string]$CurrentFile
        )

        # ── Heartbeat injection (throttled to every 30 seconds) ────
        $now = [datetime]::Now
        if (-not $script:UserFolderMigrator_Watchdog_LastBeat -or
            ($now - $script:UserFolderMigrator_Watchdog_LastBeat).TotalSeconds -ge 30) {
            try {
                if ($script:UserFolderMigrator_Watchdog_Config -and $script:UserFolderMigrator_Watchdog_Config.HeartbeatFile) {
                    $beat = [PSCustomObject]@{
                        Timestamp  = $now.ToString('o')
                        Folder     = $FolderName
                        Percent    = if ($Total -gt 0) { [int](($Current / $Total) * 100) } else { 0 }
                        DoneBytes  = $DoneBytes
                        TotalBytes = $TotalBytes
                        SpeedMBps  = if ($SpeedMBps -gt 0) { [math]::Round($SpeedMBps, 1) } else { 0 }
                        EtaSec     = $EtaSec
                        PID        = $PID
                    } | ConvertTo-Json -Compress

                    Set-Content -Path $script:UserFolderMigrator_Watchdog_Config.HeartbeatFile -Value $beat -Force -ErrorAction SilentlyContinue
                    $script:UserFolderMigrator_Watchdog_LastBeat = $now
                }
            } catch { }
        }

        # ── Call original Write-ProgressBar ──────────────────────────
        & $script:UserFolderMigrator_Watchdog_OriginalWPB @PSBoundParameters
    }

    # ── Test that email infrastructure is reachable ──────────────────
    $notifyFn = Get-Command 'Send-MigrationNotification' -ErrorAction SilentlyContinue
    if ($notifyFn) {
        try {
            & $notifyFn -Subject 'UserFolderMigrator Watchdog Started' `
                -Body "Watchdog monitoring active on $($config.ComputerName) for PID $($config.MainPID). Mode: $($config.Mode)" `
                -Status 'Info'
        } catch { }
    }

    # ── Launch watchdog runspace ─────────────────────────────────────
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()

    # Pass everything the runspace needs
    $rs.SessionStateProxy.SetVariable('Config',        $config)
    $rs.SessionStateProxy.SetVariable('AlertSender',   $script:UserFolderMigrator_Watchdog_SendAlert)
    $rs.SessionStateProxy.SetVariable('HeartbeatFile', $config.HeartbeatFile)
    $rs.SessionStateProxy.SetVariable('StopFile',      $config.StopFile)

    $ps = [powershell]::Create()
    $ps.Runspace = $rs

    # ── The actual monitoring loop (runs in background) ──────────────
    $ps.AddScript({
        $alertAlreadySent    = $false
        $consecutiveFailures = 0

        while (-not $alertAlreadySent) {
            Start-Sleep -Seconds $Config.CheckIntervalSec

            # Check for clean shutdown signal
            if (Test-Path $StopFile) {
                break
            }

            # Check if main process still exists
            $mainProcess = Get-Process -Id $Config.MainPID -ErrorAction SilentlyContinue

            if (-not $mainProcess) {
                # ── Process is gone ──
                if (Test-Path $HeartbeatFile) {
                    $lastWrite = (Get-Item $HeartbeatFile).LastWriteTime
                    $ageSec    = ((Get-Date) - $lastWrite).TotalSeconds

                    if ($ageSec -gt $Config.StaleThresholdSec) {
                        # Old heartbeat — genuine crash
                        $beatContent = try { Get-Content $HeartbeatFile -Raw } catch { 'Unreadable' }
                        $body = @"
UserFolderMigrator SCRIPT CRASH DETECTED
=========================================
Computer: $($Config.ComputerName)
User:     $($Config.UserName)
Mode:     $($Config.Mode)
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Main Process PID: $($Config.MainPID) (no longer running)
Last Heartbeat Age: $([math]::Round($ageSec,0)) seconds (threshold: $($Config.StaleThresholdSec)s)
Last Heartbeat: $beatContent

The UserFolderMigrator script has crashed or been forcibly terminated.
Check the log file for details: $($script:LogFile)
"@
                        & $AlertSender "UserFolderMigrator SCRIPT CRASH — $($Config.ComputerName)" $body 'Error'
                        $alertAlreadySent = $true
                        break
                    }
                }

                # Process gone but heartbeat was recent — wait briefly for stop file
                Start-Sleep -Seconds 10
                if (-not (Test-Path $StopFile)) {
                    $body = @"
UserFolderMigrator SCRIPT TERMINATED UNEXPECTEDLY
==================================================
Computer: $($Config.ComputerName)
User:     $($Config.UserName)
Mode:     $($Config.Mode)
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Main Process PID: $($Config.MainPID) (no longer running)

The script process ended but no clean shutdown signal was received.
This may indicate a forced termination or an unhandled exception.
Check the log file for details: $($script:LogFile)
"@
                    & $AlertSender "UserFolderMigrator UNEXPECTED TERMINATION — $($Config.ComputerName)" $body 'Error'
                    $alertAlreadySent = $true
                    break
                }
            }

            # ── Process alive — check heartbeat freshness ──
            if (Test-Path $HeartbeatFile) {
                $lastWrite = (Get-Item $HeartbeatFile).LastWriteTime
                $ageSec    = ((Get-Date) - $lastWrite).TotalSeconds

                if ($ageSec -gt $Config.StaleThresholdSec) {
                    $consecutiveFailures++
                    if ($consecutiveFailures -ge $Config.MaxConsecutive) {
                        $body = @"
UserFolderMigrator SCRIPT APPEARS HUNG
=======================================
Computer: $($Config.ComputerName)
User:     $($Config.UserName)
Mode:     $($Config.Mode)
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Main Process PID: $($Config.MainPID) (still running)
Last Heartbeat Age: $([math]::Round($ageSec,0)) seconds (threshold: $($Config.StaleThresholdSec)s)
Consecutive Stale Checks: $consecutiveFailures (threshold: $($Config.MaxConsecutive))

The script process is running but has not updated its heartbeat.
It may be hung on a network operation, large file transfer, or
waiting for user input in unattended mode.
Check the console or logs before terminating.
"@
                        & $AlertSender "UserFolderMigrator SCRIPT HUNG — $($Config.ComputerName)" $body 'Warning'
                        $alertAlreadySent = $true
                        break
                    }
                } else {
                    # Heartbeat is fresh — reset counter
                    $consecutiveFailures = 0
                }
            } else {
                # Heartbeat file missing entirely
                $consecutiveFailures++
            }
        }

        # ── Cleanup ─────────────────────────────────────────────────
        Remove-Item $HeartbeatFile -Force -ErrorAction SilentlyContinue
        Remove-Item $StopFile -Force -ErrorAction SilentlyContinue
    }) | Out-Null

    $handle = $ps.BeginInvoke()

    # ── Store everything for cleanup in PostSession ──────────────────
    $script:UserFolderMigrator_Watchdog_Runspace = @{
        PS       = $ps
        Handle   = $handle
        Runspace = $rs
        Config   = $config
    }

    Write-Status "Watchdog: Background monitoring started — heartbeat every $($config.CheckIntervalSec)s, alert after $($config.StaleThresholdSec)s" -Type "Info"
}

# ======================================================================
# POST-SESSION HOOK: Stop Watchdog
# ======================================================================

function PostSession_StopWatchdog {
    [CmdletBinding()]
    param($Context)

    $state = $script:UserFolderMigrator_Watchdog_Runspace
    if (-not $state) { return }

    Write-Status "Watchdog: Sending stop signal and waiting for clean shutdown..." -Type "Info"

    # ── Signal clean shutdown ────────────────────────────────────────
    if ($state.Config.StopFile) {
        New-Item -Path $state.Config.StopFile -Force | Out-Null
    }

    # ── Wait for runspace to exit gracefully ─────────────────────────
    Start-Sleep -Seconds 10

    # ── Force cleanup if still running ──────────────────────────────
    try {
        if ($state.Handle -and -not $state.Handle.IsCompleted) {
            $state.PS.Stop()
        }
    } catch { }

    try { $state.PS.Dispose() } catch { }
    try { $state.Runspace.Close() } catch { }
    try { $state.Runspace.Dispose() } catch { }

    # ── Restore original Write-ProgressBar function ──────────────────
    if ($script:UserFolderMigrator_Watchdog_OriginalWPB) {
        ${function:Write-ProgressBar} = $script:UserFolderMigrator_Watchdog_OriginalWPB
        Write-Status "Watchdog: Write-ProgressBar restored to original" -Type "Info"
    }

    # ── Clean up heartbeat files ─────────────────────────────────────
    if ($state.Config.HeartbeatFile) {
        Remove-Item $state.Config.HeartbeatFile -Force -ErrorAction SilentlyContinue
    }
    if ($state.Config.StopFile) {
        Remove-Item $state.Config.StopFile -Force -ErrorAction SilentlyContinue
    }

    # ── Clean up script-scope variables ──────────────────────────────
    Remove-Variable -Name 'UserFolderMigrator_Watchdog_Runspace'    -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name 'UserFolderMigrator_Watchdog_Config'       -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name 'UserFolderMigrator_Watchdog_OriginalWPB'  -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name 'UserFolderMigrator_Watchdog_LastBeat'     -Scope Script -ErrorAction SilentlyContinue

    Write-Status "Watchdog: Stopped and all cleanup complete" -Type "Success"
}

# ======================================================================
# EXPORT HOOK FUNCTIONS
# ======================================================================

Export-ModuleMember -Function 'PreMigration_StartWatchdog', 'PostSession_StopWatchdog'