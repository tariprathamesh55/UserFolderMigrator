
<#
.SYNOPSIS
    UF.Migration.Troubleshooter — self-healing and diagnostic functions.
    Detects stuck transactions, repairs permissions, resolves registry conflicts.
    Hook points: PostMigration, Rollback
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fallback: if main script hasn't defined Write-ErrorGuard, provide a minimal shim
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

function Get-StuckTransactions {
    param(
        [string]$UserProfilePath = '',
        [string]$DestinationPath = '',
        [int]$TimeoutHours = 4
    )

    $stuckTransactions = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Note: orphaned-process detection requires a PID tracked from a prior transaction log.
    # That context is not available in the general diagnostic scan — handled by
    # Repair-StuckTransaction when called with a specific transaction object.

    if ($DestinationPath -and (Test-Path $DestinationPath)) {
        $knownFolders = @('Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Videos')

        foreach ($folder in $knownFolders) {
            $folderPath = Join-Path $DestinationPath $folder
            if (Test-Path $folderPath) {
                $partialMarkers = @(Get-ChildItem -Path $folderPath -Filter '*.partial' -Recurse -ErrorAction SilentlyContinue)
                if ($partialMarkers.Count -gt 0) {
                    $stuckTransactions.Add([PSCustomObject]@{
                        Type = 'PartialMigration'
                        Path = $folderPath
                        MarkerFiles = $partialMarkers
                        MarkerFileCount = $partialMarkers.Count
                        RecommendedAction = 'Remove markers and re-run migration with -RepairTransactions'
                    })
                }
            }
        }
    }

    if ($UserProfilePath) {
        try {
            $sfKey = Get-SfKey
            $shellValues = Get-ItemProperty -Path $sfKey -ErrorAction SilentlyContinue
            foreach ($prop in $shellValues.PSObject.Properties) {
                if ($prop.Name -in @('Desktop', 'Personal', 'My Pictures', 'My Music', 'My Video')) {
                    $path = $prop.Value
                    if ($path -and $path -like "*$UserProfilePath*" -and -not (Test-Path $path)) {
                        $stuckTransactions.Add([PSCustomObject]@{
                            Type = 'RegistryPointingToMissingPath'
                            RegistryValue = $prop.Name
                            Path = $path
                            RecommendedAction = 'Update registry to correct path or restore backup'
                        })
                    }
                }
            }
        } catch { }
    }

    $statusType = if ($stuckTransactions.Count -gt 0) { 'Warning' } else { 'Success' }
    Write-Status "Found $($stuckTransactions.Count) stuck transaction(s)" -Type $statusType

    return $stuckTransactions
}

function Repair-StuckTransaction {
    param(
        [Parameter(Mandatory)]$Transaction,
        [bool]$DryRun = $false
    )

    Write-Status "Repairing stuck transaction: $($Transaction.Type)" -Type "Info"

    if ($DryRun) {
        Write-Status "  [DRY RUN] Would repair: $($Transaction.RecommendedAction)" -Type "Info"
        return $true
    }

    switch ($Transaction.Type) {
        'OrphanedProcess' {
            try {
                Stop-Process -Id $Transaction.PID -Force -ErrorAction Stop
                Write-Status "  Terminated orphaned process PID $($Transaction.PID)" -Type "Success"
                Write-Log "Terminated stuck robocopy process: $($Transaction.PID)"
                return $true
            } catch {
                Write-Status "  Failed to terminate process: $($_.Exception.Message)" -Type "Error"
                return $false
            }
        }

        'PartialMigration' {
            try {
                foreach ($marker in $Transaction.MarkerFiles) {
                    Remove-Item -LiteralPath $marker.FullName -Force -ErrorAction SilentlyContinue
                }
                Write-Status "  Removed partial migration markers from $($Transaction.Path)" -Type "Success"
                return $true
            } catch {
                Write-Status "  Failed to remove markers: $($_.Exception.Message)" -Type "Error"
                return $false
            }
        }

        'RegistryPointingToMissingPath' {
            # L15: Was hardcoded return $false — implement actual registry repair
            try {
                $regPath  = $Transaction.RegistryKey
                $regName  = $Transaction.RegistryValue
                $expected = $Transaction.ExpectedPath   # the default path to restore

                if (-not $regPath -or -not $regName) {
                    Write-Status "  RegistryConflict: missing key/value in transaction — cannot auto-repair" -Type "Warning"
                    return $false
                }

                # If a specific expected path is stored, restore it; else use environment-expanded default
                $restoreValue = if ($expected) { $expected } else {
                    $folderName = $regName -replace '[{}]', ''
                    "%USERPROFILE%\$folderName"
                }

                if ($DryRun) {
                    Write-Status "  [DRY RUN] Would restore: $regPath\$regName = $restoreValue" -Type "Info"
                    return $true
                }

                Set-ItemProperty -Path $regPath -Name $regName -Value $restoreValue -Type ExpandString -ErrorAction Stop
                Write-Status "  Restored registry: $regName -> $restoreValue" -Type "Success"
                Write-Log "Repair-StuckTransaction: restored $regPath\$regName = $restoreValue"
                return $true
            } catch {
                Write-ErrorGuard -Operation "RegistryRepair" -ErrorType $_.Exception.Message `
                    -Severity "Warning" `
                    -SkipReason "Automated registry repair failed — use -RestoreDefaults to reset all shell folders" `
                    -Recovery @{ Command = ".\UserFolderMigrator.ps1 -RestoreDefaults"; Hint = "This will reset all shell folders to Windows defaults" }
                return $false
            }
        }

        default {
            Write-Status "  No automated repair available for this transaction type" -Type "Warning"
            return $false
        }
    }
}

function Repair-BrokenPermissions {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$ResetToDefaults,
        [bool]$DryRun = $false
    )

    $result = [PSCustomObject]@{
        Path = $Path
        Success = $false
        ActionsTaken = [System.Collections.Generic.List[string]]::new()
    }

    if (-not (Test-Path $Path)) {
        Write-Status "Path not found: $Path" -Type "Error"
        return $result
    }

    Write-Status "Repairing permissions on: $Path" -Type "Info"

    if ($DryRun) {
        Write-Status "  [DRY RUN] Would reset permissions using icacls.exe" -Type "Info"
        $result.Success = $true
        return $result
    }

    try {
        if ($ResetToDefaults) {
            $null = & icacls.exe "`"$Path`"" /reset /t /q 2>&1
            $result.ActionsTaken.Add("Reset inheritance using icacls /reset")
            Write-Status "  Reset inheritance" -Type "Success"
        }

        $null = & icacls.exe "`"$Path`"" /grant "Administrators:(OI)(CI)F" /t /q 2>&1
        $result.ActionsTaken.Add("Granted FullControl to Administrators")

        $null = & icacls.exe "`"$Path`"" /grant "SYSTEM:(OI)(CI)F" /t /q 2>&1
        $result.ActionsTaken.Add("Granted FullControl to SYSTEM")

        $currentUser = $env:USERNAME
        $null = & icacls.exe "`"$Path`"" /grant "${env:USERDOMAIN}\${currentUser}:(OI)(CI)F" /t /q 2>&1
        $result.ActionsTaken.Add("Granted FullControl to $currentUser")

        $result.Success = $true
        Write-Status "  Permission repair completed" -Type "Success"
        Write-Log "Permission repair on ${Path}: $($result.ActionsTaken.Count) actions"

    } catch {
        Write-Status "  Permission repair failed: $($_.Exception.Message)" -Type "Error"
        Write-Log "Permission repair failed on $Path : $_"
    }

    return $result
}

function Resolve-RegistryConflicts {
    param(
        [string]$SID = '',
        [bool]$DryRun = $false
    )

    $conflicts = [System.Collections.Generic.List[PSCustomObject]]::new()

    $registryPaths = if ($SID) {
        Get-UserRegistryPaths -SID $SID
    } else {
        # C3: No SID = current user — use their actual HKCU keys (this is correct for current user)
        @{ UsfKey = Get-UsfKey; SfKey = Get-SfKey }
    }

    $folderDefs = Get-ShellFolderDefinitions

    foreach ($folderName in $folderDefs.Keys) {
        $def = $folderDefs[$folderName]

        $usfValue = $null
        $sfValue = $null

        try {
            $usfValue = Get-ItemPropertyValue -Path $registryPaths.UsfKey -Name $def.RegValue -ErrorAction SilentlyContinue
        } catch { }

        try {
            $sfValue = Get-ItemPropertyValue -Path $registryPaths.SfKey -Name $def.RegValue -ErrorAction SilentlyContinue
        } catch { }

        if ($usfValue -and $sfValue -and $usfValue -ne $sfValue) {
            $conflicts.Add([PSCustomObject]@{
                Type = 'USF_SF_Mismatch'
                Folder = $folderName
                UsfValue = $usfValue
                SfValue = $sfValue
                RecommendedAction = "Set both to: $usfValue"
            })
        }

        if ($usfValue -and $usfValue -match '%USERPROFILE%') {
            $conflicts.Add([PSCustomObject]@{
                Type = 'UnresolvedEnvironmentVariable'
                Folder = $folderName
                UsfValue = $usfValue
                RecommendedAction = "Expand %USERPROFILE% to actual path for current user"
            })
        }
    }

    if ($conflicts.Count -eq 0) {
        Write-Status "No registry conflicts found" -Type "Success"
        return $conflicts
    }

    Write-Status "Found $($conflicts.Count) registry conflict(s)" -Type "Warning"

    if (-not $DryRun) {
        foreach ($conflict in $conflicts) {
            if ($conflict.Type -eq 'USF_SF_Mismatch') {
                try {
                    Set-ItemProperty -Path $registryPaths.SfKey -Name $folderDefs[$conflict.Folder].RegValue -Value $conflict.UsfValue -Type String -ErrorAction Stop
                    Write-Status "  Resolved: $($conflict.Folder) -> $($conflict.UsfValue)" -Type "Success"
                    Write-Log "Registry conflict resolved: $($conflict.Folder) USF/SF mismatch"
                } catch {
                    Write-Status "  Failed to resolve $($conflict.Folder): $_" -Type "Error"
                }
            }
        }
    }

    return $conflicts
}

function Invoke-Diagnostics {
    param(
        [string]$UserProfilePath = '',
        [string]$DestinationPath = '',
        [switch]$IncludeRegistry,
        [bool]$DryRun = $false
    )

    Write-SectionHeader "MIGRATION DIAGNOSTICS"

    $results = [PSCustomObject]@{
        StuckTransactions = @()
        RegistryConflicts = @()
        PermissionIssues = @()
        Summary = ''
    }

    $results.StuckTransactions = Get-StuckTransactions -UserProfilePath $UserProfilePath -DestinationPath $DestinationPath

    if ($IncludeRegistry) {
        $results.RegistryConflicts = Resolve-RegistryConflicts -DryRun $DryRun
    }

    if ($UserProfilePath -and (Test-Path $UserProfilePath)) {
        $hasAccess = Test-PathPermissions -Path $UserProfilePath -RequiredRights 'Write'
        if (-not $hasAccess) {
            $results.PermissionIssues += [PSCustomObject]@{
                Path = $UserProfilePath
                Issue = 'Insufficient write access'
                RecommendedAction = 'Run Repair-BrokenPermissions'
            }
        }
    }

    $totalIssues = $results.StuckTransactions.Count + $results.RegistryConflicts.Count + $results.PermissionIssues.Count
    if ($totalIssues -eq 0) {
        $results.Summary = 'No issues detected'
        Write-Status "Diagnostics: No issues found" -Type "Success"
    } else {
        $results.Summary = "$totalIssues issue(s) detected"
        Write-Status "Diagnostics: $totalIssues issue(s) detected" -Type "Warning"
        foreach ($issue in $results.StuckTransactions) {
            Write-Status "  - Stuck: $($issue.Type) ($($issue.RecommendedAction))" -Type "Warning"
        }
    }

    return $results
}

function Invoke-AutoRemediation {
    param(
        [string]$UserProfilePath = '',
        [string]$DestinationPath = '',
        [switch]$FixPermissions,
        [switch]$FixRegistry,
        [switch]$KillStuckProcesses,
        [bool]$DryRun = $false
    )

    Write-SectionHeader "AUTO-REMEDIATION"

    $results = [PSCustomObject]@{
        ActionsTaken = [System.Collections.Generic.List[string]]::new()
        Successful = 0
        Failed = 0
    }

    if ($KillStuckProcesses) {
        $stuck = Get-StuckTransactions -UserProfilePath $UserProfilePath -DestinationPath $DestinationPath
        foreach ($transaction in $stuck) {
            if ($transaction.Type -eq 'OrphanedProcess') {
                $repaired = Repair-StuckTransaction -Transaction $transaction -DryRun $DryRun
                if ($repaired) {
                    $results.ActionsTaken.Add("Terminated orphaned robocopy PID $($transaction.PID)")
                    $results.Successful++
                } else {
                    $results.Failed++
                }
            }
        }
    }

    if ($FixPermissions -and $UserProfilePath -and (Test-Path $UserProfilePath)) {
        $permResult = Repair-BrokenPermissions -Path $UserProfilePath -ResetToDefaults -DryRun $DryRun
        if ($permResult.Success) {
            $results.ActionsTaken.Add("Repaired permissions on $UserProfilePath")
            $results.Successful++
        } else {
            $results.Failed++
        }
    }

    if ($FixRegistry) {
        $regConflicts = Resolve-RegistryConflicts -DryRun $DryRun
        if ($regConflicts.Count -gt 0) {
            $results.ActionsTaken.Add("Resolved $($regConflicts.Count) registry conflict(s)")
            $results.Successful += $regConflicts.Count
        }
    }

    $statusType = if ($results.Failed -eq 0) { 'Success' } else { 'Warning' }
    Write-Status "Remediation complete: $($results.Successful) fixed, $($results.Failed) failed" -Type $statusType
    Write-Log "AutoRemediation: $($results.Successful) success, $($results.Failed) failed"

    return $results
}

function PostMigration_RunDiagnostics {
    param($Context)

    # Resolve ProfilePath — FullProfileBackup passes $Destination for both fields;
    # Migrate passes the actual C:\Users\<user> source path.
    $profilePath = if ($Context.PSObject.Properties['ProfilePath'] -and $Context.ProfilePath) {
        $Context.ProfilePath
    } elseif ($Context.PSObject.Properties['DestinationPath'] -and $Context.DestinationPath) {
        $Context.DestinationPath
    } else { $null }

    $destPath = if ($Context.PSObject.Properties['DestinationPath'] -and $Context.DestinationPath) {
        $Context.DestinationPath
    } else { $null }

    if (-not $destPath) {
        Write-Log "PostMigration_RunDiagnostics: missing DestinationPath in context — skipping" -Level "WARN"
        return $true
    }

    try {
        $diagResult = Invoke-Diagnostics -UserProfilePath $profilePath -DestinationPath $destPath `
            -IncludeRegistry -DryRun $Context.DryRun
        $Context.DiagnosticsResult = $diagResult

        if ($Context.AutoRemediation -eq $true -and $diagResult -and $diagResult.StuckTransactions.Count -gt 0) {
            try {
                $remediation = Invoke-AutoRemediation -KillStuckProcesses -DryRun $Context.DryRun
                $Context.RemediationResult = $remediation
            } catch {
                Write-ErrorGuard -Operation "AutoRemediation" -ErrorType $_.Exception.Message `
                    -Severity "Warning" `
                    -SkipReason "Auto-remediation failed — manual cleanup may be needed" `
                    -Recovery @{ Hint = "Run Invoke-RepairTransactionsForUser manually" }
            }
        }
    } catch {
        Write-ErrorGuard -Operation "PostMigrationDiagnostics" -ErrorType $_.Exception.Message `
            -Severity "Warning" `
            -SkipReason "Diagnostics failed — migration result unaffected, run diagnostics manually" `
            -Diagnostics @{ "ProfilePath" = $profilePath; "DestinationPath" = $destPath } `
            -Recovery @{ Command = "Invoke-Diagnostics -UserProfilePath '$profilePath' -DestinationPath '$destPath'"; Hint = "Run manually after migration completes" }
    }
    return $true
}

function Rollback_FixRegistryConflicts {
    param($Context)

    if (-not $Context.SID) {
        Write-Log "Rollback_FixRegistryConflicts: no SID in context — skipping" -Level "WARN"
        return $true
    }

    try {
        $conflicts = Resolve-RegistryConflicts -SID $Context.SID -DryRun $Context.DryRun
        $Context.RegistryConflictsResolved = $conflicts.Count
    } catch {
        Write-ErrorGuard -Operation "RegistryConflictResolution" -ErrorType $_.Exception.Message `
            -Severity "Warning" `
            -SkipReason "Registry conflict resolution failed — rollback may be incomplete" `
            -Diagnostics @{ "SID" = $Context.SID } `
            -Recovery @{ Hint = "Run Resolve-RegistryConflicts manually with the user SID" }
    }
    return $true
}

function Test-PathPermissions {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$User = "$env:USERNAME",
        [ValidateSet('Read','Write','Modify','FullControl')][string]$RequiredRights = 'Write'
    )
    if (-not (Test-Path $Path)) { return $false }
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        $accessRules = $acl.Access | Where-Object {
            $_.IdentityReference -like "*$User*" -or $_.IdentityReference -eq 'BUILTIN\Administrators'
        }
        $rightsMap = @{
            'Read' = [System.Security.AccessControl.FileSystemRights]::Read
            'Write' = [System.Security.AccessControl.FileSystemRights]::Write
            'Modify' = [System.Security.AccessControl.FileSystemRights]::Modify
            'FullControl' = [System.Security.AccessControl.FileSystemRights]::FullControl
        }
        $required = $rightsMap[$RequiredRights]
        foreach ($rule in $accessRules) {
            if ($rule.FileSystemRights -band $required) { return $true }
        }
        return $false
    } catch { return $false }
}

function PostMigration_Diagnostics_DeclareInputs {
    return @(
        @{
            Key               = 'AutoRemediation'
            Prompt            = 'Auto-fix stuck transactions and registry conflicts after migration?'
            Type              = 'YesNo'
            Default           = 'N'
            UnattendedDefault = 'Y'
            Required          = $false
        }
    )
}

Export-ModuleMember -Function 'PostMigration_RunDiagnostics', 'Rollback_FixRegistryConflicts', 'PostMigration_Diagnostics_DeclareInputs'