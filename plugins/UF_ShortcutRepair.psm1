
<#
.SYNOPSIS
    UF.Migration.ShortcutRepair — rewrites broken .lnk shortcuts post-migration.
    Hook point: PostUser

.STYLE GUIDE
    Functions: PascalCase
    Parameters: PascalCase
    Local Variables: camelCase

.NOTES
    Depends on: UF.Core, UF.FileSystem, UF.Logging, UF.UI
    Hook naming: PostUser_RewriteShortcuts
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

# ── Module Manifest ───────────────────────────────────────────────────────────

# WSH Shell for .lnk manipulation
$script:WshShell = $null

function Initialize-WshShell {
    if (-not $script:WshShell) {
        try {
            $script:WshShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
        } catch {
            Write-ErrorGuard -Operation "WshShellInit" -ErrorType $_.Exception.Message `
                -Severity "Warning" `
                -SkipReason "WScript.Shell COM unavailable — shortcut repair skipped, migration unaffected" `
                -Recovery @{ Hint = "Ensure Windows Script Host is enabled (wscript.exe /H:wscript)" }
            return $null
        }
    }
    return $script:WshShell
}

<#
.SYNOPSIS
    Hook that rewrites broken shortcuts after each user migration.
    Scans Desktop, Documents, Favorites, and Start Menu for broken .lnk files.
.PARAMETER Username The username.
.PARAMETER Result The migration result object.
.PARAMETER DryRun Whether this is a dry run.
.OUTPUTS [bool] $true to continue, $false to abort.
#>
function PostUser_RewriteShortcuts {
    param($Context)
    
    $Username = if ($Context.PSObject.Properties['UserName']) { [string]$Context.UserName } elseif ($Context.PSObject.Properties['Username']) { [string]$Context.Username } else { '' }
    $Result   = $Context.Result
    $DryRun   = [bool]$Context.DryRun
    
    # Guard: test COM availability up front
    if (-not $DryRun -and -not (Initialize-WshShell)) {
        Write-Log "ShortcutRepair skipped for $Username — WScript.Shell unavailable" -Level "WARN"
        return $true
    }

    # Skip if no folders were migrated successfully
    $successFolders = @($Result.Folders | Where-Object { $_.Success })
    if ($successFolders.Count -eq 0) {
        Write-Log "ShortcutRepair: no successful migrations for $Username — skipping"
        return $true
    }
    
    Write-Status "ShortcutRepair: scanning for broken shortcuts for $Username" -Type "Info"

    # M14: oldRoot must be the SOURCE (old location) — shortcuts were created pointing there
    # Previous bug: used Split-Path $firstFolder.Destination -Parent which gave the NEW location's parent
    # That means $oldRoot contained the new path, and repair searched for old paths INSIDE new location — found nothing
    $firstFolder = $successFolders[0]

    # Source root = parent of where folders were (e.g. C:\Users\John from C:\Users\John\Documents)
    # We derive it from the folder object's SourcePath if available, otherwise profile path
    $oldRoot = if ($firstFolder.PSObject.Properties['SourcePath'] -and $firstFolder.SourcePath) {
        Split-Path $firstFolder.SourcePath -Parent
    } elseif ($Result.PSObject.Properties['ProfilePath'] -and $Result.ProfilePath) {
        $Result.ProfilePath
    } else {
        # Fallback: standard profile location
        [System.IO.Path]::Combine($env:SystemDrive, 'Users', $Username)
    }

    # Destination root = parent of where folders were moved (e.g. Y:\Data from Y:\Data\Documents)
    $newRoot = Split-Path $firstFolder.Destination -Parent

    if (-not $oldRoot -or -not $newRoot) {
        Write-Log "ShortcutRepair: could not determine path mapping for $Username — skipping"
        return $true
    }

    Write-Log "ShortcutRepair: mapping $oldRoot -> $newRoot for $Username"
    
    # Scan locations
    $scanPaths = @(
        [System.IO.Path]::Combine($env:SystemDrive, "Users", $Username, "Desktop"),
        [System.IO.Path]::Combine($env:SystemDrive, "Users", $Username, "Documents"),
        [System.IO.Path]::Combine($env:SystemDrive, "Users", $Username, "Favorites"),
        [System.IO.Path]::Combine($env:SystemDrive, "Users", $Username, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu")
    )
    
    $repaired = 0
    $failed = 0
    
    foreach ($scanPath in $scanPaths) {
        if (-not (Test-Path $scanPath)) { continue }
        
        $shortcuts = @(Get-ChildItem -Path $scanPath -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue)
        
        foreach ($shortcut in $shortcuts) {
            if ($DryRun) {
                Write-Status "  [DRY RUN] Would check: $($shortcut.FullName)" -Type "Info"
                continue
            }
            
            try {
                $shell = Initialize-WshShell
                $link = $shell.CreateShortcut($shortcut.FullName)
                $target = $link.TargetPath
                
                # Check if target is broken and points to old location
                if ($target -and (Test-Path $target) -eq $false -and $target -like "$oldRoot*") {
                    $newTarget = $target -replace [regex]::Escape($oldRoot), $newRoot
                    
                    if (Test-Path $newTarget) {
                        $link.TargetPath = $newTarget
                        $link.Save()
                        $repaired++
                        Write-Log "  Repaired: $($shortcut.Name) -> $newTarget"
                    } else {
                        $failed++
                        Write-Log "  Cannot repair: $($shortcut.Name) - target not found at $newTarget"
                    }
                }
            } catch {
                $failed++
                Write-ErrorGuard -Operation "ShortcutRepair" -ErrorType $_.Exception.Message `
                    -Item $shortcut.FullName -Severity "Warning" `
                    -SkipReason "Shortcut skipped — other shortcuts continue processing"
            }
        }
    }
    
    if ($repaired -gt 0) {
        Write-Status "  Repaired $repaired shortcut(s)" -Type "Success"
    }
    if ($failed -gt 0) {
        Write-Status "  Failed to repair $failed shortcut(s)" -Type "Warning"
    }
    
    Write-Log "ShortcutRepair: $repaired repaired, $failed failed for $Username"
    return $true
}

# Standalone function for manual invocation
function Repair-Shortcuts {
    param(
        [Parameter(Mandatory)][string]$Username,
        [string]$OldRoot,
        [string]$NewRoot,
        [switch]$DryRun
    )
    
    $result = [PSCustomObject]@{
        Username = $Username
        Repaired = 0
        Failed = 0
        ScannedPaths = @()
    }
    
    $scanPaths = @(
        [System.IO.Path]::Combine($env:SystemDrive, "Users", $Username, "Desktop"),
        [System.IO.Path]::Combine($env:SystemDrive, "Users", $Username, "Documents"),
        [System.IO.Path]::Combine($env:SystemDrive, "Users", $Username, "Favorites"),
        [System.IO.Path]::Combine($env:SystemDrive, "Users", $Username, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu")
    )
    
    foreach ($scanPath in $scanPaths) {
        if (-not (Test-Path $scanPath)) { continue }
        $result.ScannedPaths += $scanPath
        
        $shortcuts = @(Get-ChildItem -Path $scanPath -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue)
        
        foreach ($shortcut in $shortcuts) {
            if ($DryRun) {
                $result.Repaired++
                continue
            }
            
            try {
                $shell = Initialize-WshShell
                $link = $shell.CreateShortcut($shortcut.FullName)
                $target = $link.TargetPath
                
                if ($target -and (Test-Path $target) -eq $false -and $target -like "$OldRoot*") {
                    $newTarget = $target -replace [regex]::Escape($OldRoot), $NewRoot
                    if (Test-Path $newTarget) {
                        $link.TargetPath = $newTarget
                        $link.Save()
                        $result.Repaired++
                    } else {
                        $result.Failed++
                    }
                }
            } catch {
                $result.Failed++
            }
        }
    }
    
    return $result
}

Export-ModuleMember -Function 'PostUser_RewriteShortcuts'