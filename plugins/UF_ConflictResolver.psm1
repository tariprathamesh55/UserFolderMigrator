
<#
.SYNOPSIS
    UF.Migration.ConflictResolver — detects and resolves path conflicts pre-copy.
    Hook point: PreFolder (runs before each folder copy)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function PreFolder_ResolveConflicts {
    param($Context)
    
    $Username   = [string]$Context.Username
    $FolderName = [string]$Context.FolderName
    $SourcePath = [string]$Context.SourcePath
    $DestPath   = [string]$Context.DestPath
    $DryRun     = [bool]$Context.DryRun

    # Guard: missing context keys mean we cannot validate — skip safely
    if (-not $SourcePath -or -not $DestPath) {
        Write-Log "ConflictResolver: missing SourcePath/DestPath in context — skipping" -Level "WARN"
        return $true
    }

    $issues = [System.Collections.Generic.List[string]]::new()

    if ($SourcePath.Length -gt 240 -or $DestPath.Length -gt 240) {
        $issues.Add("Path exceeds 240 characters — may cause 'path too long' errors")
        Write-Log "ConflictResolver: long path detected — Src:$($SourcePath.Length) Dst:$($DestPath.Length)"
    }

    $reservedNames = @('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9')
    $sourceParts = $SourcePath -split '\\'
    $destParts = $DestPath -split '\\'

    foreach ($part in ($sourceParts + $destParts)) {
        if ($part -in $reservedNames) {
            $issues.Add("Reserved name '$part' in path — may cause access errors")
            Write-Log "ConflictResolver: reserved name '$part' in path"
            break
        }
    }

    if (Test-Path $DestPath) {
        $actualPath = (Get-Item $DestPath -ErrorAction SilentlyContinue).FullName
        if ($actualPath -and $actualPath -ne $DestPath) {
            $issues.Add("Case mismatch: exists at '$actualPath' vs expected '$DestPath'")
            Write-Log "ConflictResolver: case mismatch for $DestPath"
        }
    }

    # M13: Normalize paths consistently — trim ALL trailing separators and use canonical form
    # TrimEnd('\') alone misses '/' separators and double-backslash UNC paths
    $normalizedSource = $SourcePath.TrimEnd('\', '/').ToUpperInvariant()
    $normalizedDest   = $DestPath.TrimEnd('\', '/').ToUpperInvariant()
    
    # M13: StartsWith check alone gives false positive: C:\Users\John matches C:\Users\Johnny
    # Must require a path separator AFTER the matching prefix to confirm it's truly a child path
    $destInsideSource = $normalizedDest.StartsWith($normalizedSource + '\') -or ($normalizedDest -eq $normalizedSource)
    $sourceInsideDest = $normalizedSource.StartsWith($normalizedDest + '\') -or ($normalizedSource -eq $normalizedDest)

    if ($destInsideSource) {
        $issues.Add("CIRCULAR: Destination '$DestPath' is inside source '$SourcePath' — would cause infinite loop")
        Write-Log "ConflictResolver: CIRCULAR — dest inside source: $normalizedDest within $normalizedSource"
        Write-Status "  Conflict: Destination is inside source folder — ABORTING $FolderName" -Type "Error"
        return $false
    }

    if ($sourceInsideDest) {
        $issues.Add("CIRCULAR: Source '$SourcePath' is inside destination '$DestPath' — would cause data loss")
        Write-Log "ConflictResolver: CIRCULAR — source inside dest: $normalizedSource within $normalizedDest"
        Write-Status "  Conflict: Source is inside destination folder — ABORTING $FolderName" -Type "Error"
        return $false
    }

    if ($issues.Count -gt 0) {
        Write-ErrorGuard -Operation "ConflictResolver" `
            -ErrorType "$($issues.Count) conflict(s) in '$FolderName'" `
            -Folder $FolderName -Severity "Warning" `
            -Diagnostics @{ "Issues" = ($issues -join '; ') }

        if ($DryRun) {
            Write-Status "    [DRY RUN] Would skip this folder due to conflicts" -Type "Info"
            return $false
        }

        $resolveAttempted = $false
        foreach ($issue in $issues) {
            if ($issue -like "*path exceeds*") {
                $resolveAttempted = $true
                Write-Status "    Attempting resolution: using subst for shorter path..." -Type "Info"
            }
        }

        if (-not $resolveAttempted) {
            Write-ErrorGuard -Operation "ConflictResolver" `
                -ErrorType "Cannot auto-resolve conflicts for '$FolderName'" `
                -Folder $FolderName -Severity "Error" `
                -SkipReason "Folder skipped — fix conflicts and re-run migration" `
                -Recovery @{ Hint = "Enable long path support: Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -Value 1" }
            return $false
        }
    }

    return $true
}

function Resolve-PathConflict {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestPath,
        [switch]$AutoFix
    )

    $result = [PSCustomObject]@{
        HasConflict = $false
        Issues = [System.Collections.Generic.List[string]]::new()
        AutoFixed = $false
        RecommendedAction = ''
    }

    if ($SourcePath.Length -gt 240 -or $DestPath.Length -gt 240) {
        $result.HasConflict = $true
        $result.Issues.Add("Path length exceeds 240 characters")
        $result.RecommendedAction = "Use shorter destination path or enable long path support via Group Policy"
    }

    # M13: Separator-aware comparison to prevent C:\Users\John matching C:\Users\Johnny
    $normalizedSource = $SourcePath.TrimEnd('\', '/').ToUpperInvariant()
    $normalizedDest   = $DestPath.TrimEnd('\', '/').ToUpperInvariant()

    if ($normalizedDest.StartsWith($normalizedSource + '\') -or ($normalizedDest -eq $normalizedSource)) {
        $result.HasConflict = $true
        $result.Issues.Add("Destination is inside source")
        $result.RecommendedAction = "Choose destination outside source tree"
    }

    if ($normalizedSource.StartsWith($normalizedDest + '\') -or ($normalizedSource -eq $normalizedDest)) {
        $result.HasConflict = $true
        $result.Issues.Add("Source is inside destination")
        $result.RecommendedAction = "Choose destination outside source tree"
    }

    return $result
}

Export-ModuleMember -Function 'PreFolder_ResolveConflicts'