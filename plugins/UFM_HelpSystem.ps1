#Requires -Version 7.0
<#
.SYNOPSIS
    UFM Interactive Help System Plugin
    Provides context-sensitive help at every prompt via '?' intercept.
    Drop this file into the same folder as UFM_Interactive.ps1.
    Requires Authenticode signature or -BypassSignatureCheck in UFM main script.

.DESCRIPTION
    Exports:
      Read-HostWithHelp    Drop-in replacement for Read-Host. Type '?' for help, '??' for glossary.
      Show-HelpTopic       Display any help topic by key name.
      Show-UFMGlossary     Display the full glossary.

    Help content is loaded from HelpContent\UFM_HelpTopics.json in the same folder.
    Edit the JSON file to customise help text without touching script code.

.VERSION 1.0.0
#>

[CmdletBinding()]
param()

# ── Load help content ──────────────────────────────────────────────────────────
$script:HelpTopicsPath = Join-Path $PSScriptRoot 'HelpContent\UFM_HelpTopics.json'
$script:HelpTopics     = $null

function Initialize-UFMHelp {
    if (Test-Path $script:HelpTopicsPath) {
        try {
            $script:HelpTopics = Get-Content $script:HelpTopicsPath -Raw | ConvertFrom-Json -AsHashtable
            Write-Verbose "UFM Help System: loaded $($script:HelpTopics.Count) topics from $script:HelpTopicsPath"
        } catch {
            Write-Warning "UFM Help System: failed to load topics — $_"
            $script:HelpTopics = @{}
        }
    } else {
        Write-Warning "UFM Help System: topics file not found at $script:HelpTopicsPath"
        $script:HelpTopics = @{}
    }
}

Initialize-UFMHelp

# ── Help display ───────────────────────────────────────────────────────────────
function Show-HelpTopic {
    <#
    .SYNOPSIS
        Display a help topic by key name.
    .PARAMETER Topic
        Key from UFM_HelpTopics.json (e.g. 'vss', 'mode_selection')
    #>
    param([string]$Topic)

    $t = $script:HelpTopics[$Topic]
    if (-not $t) {
        Write-Host ""
        Write-Host "  No help available for topic: '$Topic'" -ForegroundColor DarkGray
        Write-Host "  Available topics: $($script:HelpTopics.Keys -join ', ')" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    $w = try { [Math]::Max(60, [Console]::WindowWidth - 4) } catch { 78 }
    $bar = '─' * $w

    Write-Host ""
    Write-Host "  ┌$('─' * ($w))┐" -ForegroundColor Cyan
    Write-Host ("  │  HELP: {0,-$($w - 8)}│" -f $t.title.ToUpper()) -ForegroundColor Cyan
    Write-Host "  └$('─' * ($w))┘" -ForegroundColor Cyan
    Write-Host ""

    # Body — word-wrap at console width
    foreach ($line in $t.body -split "`n") {
        if ($line.Trim() -eq '') { Write-Host "" }
        else { Write-Host "  $line" -ForegroundColor White }
    }

    Write-Host ""
    Write-Host "  $bar" -ForegroundColor DarkGray

    if ($t.risk) {
        $riskColor = switch -Wildcard ($t.risk) {
            "ZERO*"     { "Green"  }
            "LOW*"      { "Green"  }
            "MEDIUM*"   { "Yellow" }
            "HIGH*"     { "Red"    }
            "CRITICAL*" { "Red"    }
            default     { "Gray"   }
        }
        Write-Host "  Risk level : $($t.risk)" -ForegroundColor $riskColor
    }
    if ($t.example)     { Write-Host "  Example    : $($t.example)"     -ForegroundColor Gray }
    if ($t.recommended) { Write-Host "  Recommended: $($t.recommended)" -ForegroundColor Green }
    Write-Host ""
}

function Show-UFMGlossary {
    Show-HelpTopic -Topic 'glossary'
}

# ── Core function: Read-HostWithHelp ──────────────────────────────────────────
function Read-HostWithHelp {
    <#
    .SYNOPSIS
        Drop-in replacement for Read-Host that intercepts '?' and '??' for help.
    .PARAMETER Prompt
        The prompt text shown to the user (same as Read-Host -Prompt).
    .PARAMETER Topic
        Help topic key to show when user types '?'.
    .PARAMETER AsSecureString
        Pass through to Read-Host for password prompts.
    .PARAMETER AllowEmpty
        If set, empty input is accepted without re-prompting.
    .EXAMPLE
        $mode = Read-HostWithHelp -Prompt "  Enter choice (1-7)" -Topic "mode_selection"
    #>
    param(
        [string]$Prompt,
        [string]$Topic        = '',
        [switch]$AsSecureString,
        [switch]$AllowEmpty
    )

    $helpHint = if ($Topic) { " [? for help]" } else { "" }
    $fullPrompt = "$Prompt$helpHint"

    while ($true) {
        if ($AsSecureString) {
            # Cannot intercept secure strings — just pass through
            return (Read-Host $Prompt -AsSecureString)
        }

        $input = Read-Host $fullPrompt

        if ($input -eq '??') {
            Show-UFMGlossary
            continue
        }

        if ($input -eq '?' -and $Topic) {
            Show-HelpTopic -Topic $Topic
            continue
        }

        if ($input -eq '?' -and -not $Topic) {
            Write-Host "  No specific help available here. Type '??' for the full glossary." -ForegroundColor DarkGray
            continue
        }

        if (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($input)) {
            # Re-prompt — but only if the caller didn't pass a default
            # We return empty so the caller's default logic handles it
            return $input
        }

        return $input
    }
}

# ── Safe-path detection: warn on risky combinations ───────────────────────────
function Test-RiskySettingCombination {
    <#
    .SYNOPSIS
        Detects risky setting combinations and warns the operator before execution.
        Called by UFM_Interactive just before the final confirm prompt.
    .PARAMETER Settings
        Hashtable of current wizard settings (same keys as UFM param block).
    #>
    param([hashtable]$Settings)

    $warnings = @()

    # Secure wipe without dry run
    if ($Settings.SecureWipeSource -and -not $Settings.DryRun) {
        $warnings += @{
            Level   = 'CRITICAL'
            Message = 'SecureWipe is enabled. Files at the source will be PERMANENTLY DESTROYED after copying. This cannot be undone.'
            Confirm = 'Are you absolutely sure you want to permanently destroy the source files?'
        }
    }

    # SkipRegistryUpdate with Migrate
    if ($Settings.Mode -eq 'Migrate' -and $Settings.SkipRegistryUpdate) {
        $warnings += @{
            Level   = 'HIGH'
            Message = 'SkipRegistryUpdate is enabled. Windows will still point at the OLD location after migration. Applications will not find files at the new location.'
            Confirm = 'Do you understand that apps like Office and browser will still use the OLD location?'
        }
    }

    # DisableChecksumVerify on large migration
    if ($Settings.DisableChecksumVerify -and -not $Settings.DryRun) {
        $warnings += @{
            Level   = 'MEDIUM'
            Message = 'Checksum verification is disabled. Corrupted files will not be detected during migration.'
            Confirm = 'Do you accept the risk of undetected file corruption?'
        }
    }

    # AllUsers without DryRun first
    if ($Settings.AllUsers -and -not $Settings.DryRun -and $Settings.Mode -eq 'Migrate') {
        $warnings += @{
            Level   = 'MEDIUM'
            Message = 'Migrating ALL users on this machine. This is a large-scope operation affecting every Windows account.'
            Confirm = 'Have you verified this PC has multiple user accounts that all need migration?'
        }
    }

    # DisableAutoExclusions
    if ($Settings.DisableAutoExclusions) {
        $warnings += @{
            Level   = 'MEDIUM'
            Message = 'Auto-exclusions are disabled. The script will attempt to copy Temp files, $Recycle.Bin, and other system-locked junk. Expect errors and slower performance.'
            Confirm = 'Are you sure you want to disable auto-exclusions?'
        }
    }

    if ($warnings.Count -eq 0) { return $true }

    $w = try { [Math]::Max(60, [Console]::WindowWidth - 4) } catch { 78 }
    Write-Host ""
    Write-Host "  ┌$('─' * $w)┐" -ForegroundColor Red
    Write-Host ("  │  {0,-$($w - 2)}│" -f 'SAFETY WARNINGS — REVIEW BEFORE PROCEEDING') -ForegroundColor Red
    Write-Host "  └$('─' * $w)┘" -ForegroundColor Red
    Write-Host ""

    foreach ($warn in $warnings) {
        $col = if ($warn.Level -eq 'CRITICAL') { 'Red' } elseif ($warn.Level -eq 'HIGH') { 'Yellow' } else { 'DarkYellow' }
        Write-Host "  [$($warn.Level)] $($warn.Message)" -ForegroundColor $col
        Write-Host ""
        $ans = Read-Host "  $($warn.Confirm) (Y/N)"
        if ($ans -ne 'Y' -and $ans -ne 'y') {
            Write-Host ""
            Write-Host "  Operation cancelled. Return to the wizard and adjust settings." -ForegroundColor Yellow
            return $false
        }
        Write-Host ""
    }

    return $true
}

# ── Post-run error recovery help ──────────────────────────────────────────────
function Show-ErrorRecoveryHelp {
    <#
    .SYNOPSIS
        Shows plain-English diagnosis and fix steps based on the exit code
        returned by UserFolderMigrator.ps1.
    .PARAMETER ExitCode
        Exit code from the main script.
    .PARAMETER LogPath
        Path to the script log file for additional context.
    #>
    param([int]$ExitCode, [string]$LogPath = '')

    $w = try { [Math]::Max(60, [Console]::WindowWidth - 4) } catch { 78 }

    $diagnosis = switch ($ExitCode) {
        0  { @{ Title='Success'; Body='Migration completed successfully. No action needed.'; Color='Green' } }
        1  { @{ Title='Partial Failure'; Body="Some folders failed to migrate. Common causes:`n  - Files locked by running applications (try VSS next time)`n  - Insufficient permissions on destination`n  - Destination ran out of disk space mid-run`n`nAction: Check the HTML report for which folders failed, then re-run for those folders only."; Color='Yellow' } }
        2  { @{ Title='Destination Error'; Body="Cannot write to the destination path. Possible causes:`n  - Path does not exist and could not be created`n  - Insufficient permissions (try running as Administrator)`n  - Network share is unavailable`n`nAction: Verify the destination path is accessible and try again."; Color='Yellow' } }
        3  { @{ Title='KFM Block'; Body="OneDrive Known Folder Move is active and blocked the migration.`n`nAction: Re-run the script and choose option 1 (Disable KFM) when prompted.`nOr pass -SkipKFMBlock to acknowledge the risk and proceed anyway."; Color='Yellow' } }
        4  { @{ Title='Compatibility Failure'; Body="The pre-flight compatibility check failed. Common causes:`n  - PowerShell version below 7.0 (run: $($PSVersionTable.PSVersion))`n  - Not running as Administrator`n  - Windows version incompatibility`n`nAction: Ensure you are running PowerShell 7+ as Administrator."; Color='Red' } }
        5  { @{ Title='Checkpoint Conflict'; Body="A checkpoint from a previous run was found but could not be resumed.`n`nAction: Delete the checkpoint file and re-run from scratch.`nCheckpoint location: $env:TEMP\\UFM_Checkpoint_*.json"; Color='Yellow' } }
        99 { @{ Title='Unexpected Error'; Body="An unhandled exception occurred. This is likely a bug.`n`nAction:`n  1. Check the log file for the full error message`n  2. Re-run with -VerboseOutput for more detail`n  3. Report the issue with the log attached"; Color='Red' } }
        default { @{ Title="Unknown Exit Code ($ExitCode)"; Body="Unexpected exit code. Check the log file for details."; Color='Red' } }
    }

    Write-Host ""
    Write-Host "  ┌$('─' * $w)┐" -ForegroundColor $diagnosis.Color
    Write-Host ("  │  RESULT: {0,-$($w - 9)}│" -f $diagnosis.Title.ToUpper()) -ForegroundColor $diagnosis.Color
    Write-Host "  └$('─' * $w)┘" -ForegroundColor $diagnosis.Color
    Write-Host ""

    foreach ($line in $diagnosis.Body -split "`n") {
        Write-Host "  $line" -ForegroundColor White
    }

    if ($LogPath -and (Test-Path $LogPath)) {
        Write-Host ""
        Write-Host "  Log file: $LogPath" -ForegroundColor Gray
        $errors = Select-String -Path $LogPath -Pattern 'ERROR|FAIL|Exception' | Select-Object -Last 5
        if ($errors) {
            Write-Host "  Last errors in log:" -ForegroundColor DarkGray
            $errors | ForEach-Object { Write-Host "    $($_.Line)" -ForegroundColor DarkGray }
        }
    }
    Write-Host ""
}

# ── Export ─────────────────────────────────────────────────────────────────────
Export-ModuleMember -Function @(
    'Read-HostWithHelp',
    'Show-HelpTopic',
    'Show-UFMGlossary',
    'Test-RiskySettingCombination',
    'Show-ErrorRecoveryHelp',
    'Initialize-UFMHelp'
)
