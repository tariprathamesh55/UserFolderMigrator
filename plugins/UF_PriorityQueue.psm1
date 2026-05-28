
<#
.SYNOPSIS
    UF.Migration.PriorityQueue — prioritizes critical folders over bulk data.
    Hook point: PreFolder (reorders folder processing order)

.STYLE GUIDE
    Functions: PascalCase
    Parameters: PascalCase
    Local Variables: camelCase

.NOTES
    Depends on: UF.Core, UF.Logging, UF.UI
    Hook naming: PreFolder_ReorderByPriority
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Module Manifest ───────────────────────────────────────────────────────────

# Priority tiers: Tier 1 = migrate first, Tier 3 = migrate last
$script:PriorityTiers = @{
    'Desktop'    = 1
    'Documents'  = 1
    'Favorites'  = 1
    'Downloads'  = 2
    'Pictures'   = 2
    'Videos'     = 3
    'Music'      = 3
    'SavedGames' = 3
    'Contacts'   = 2
    'Links'      = 2
    'Searches'   = 3
}

<#
.SYNOPSIS
    Hook that reorders folder processing queue — high-priority folders first.
    Called automatically at PreFolder hook point.
.PARAMETER Username Current username.
.PARAMETER FolderName Current folder (not used — hook processes the queue).
.PARAMETER FoldersList Reference to the folders array (passed by reference).
.OUTPUTS [bool] $true to continue, $false to abort.
.NOTES
    This hook modifies the $FoldersList array in place.
    Called once at the start of each user migration.
#>
function PreFolder_ReorderByPriority {
    param($Context)
    
    $Username    = [string]$Context.Username
    $FolderName  = [string]$Context.FolderName
    $FoldersList = $Context.FoldersList
    
    if (-not $FoldersList) {
        Write-Log "PriorityQueue: no FoldersList in context — skipping reorder" -Level "WARN"
        return $true
    }

    # M5: FoldersList must be a mutable List — if caller passed [string[]] array, .Clear()/.Add() will throw
    if ($FoldersList -isnot [System.Collections.Generic.List[object]] -and
        $FoldersList -isnot [System.Collections.Generic.List[string]] -and
        $FoldersList -isnot [System.Collections.IList]) {
        Write-Log "PriorityQueue: FoldersList is $($FoldersList.GetType().Name) — converting to mutable List for reorder" -Level "WARN"
        $mutableList = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $FoldersList) { $mutableList.Add([string]$f) }
        $FoldersList = $mutableList
        $Context.FoldersList = $FoldersList
    }
    
    # M5: FoldersList must be a mutable List — convert if caller passed array
    if ($FoldersList -isnot [System.Collections.Generic.List[string]]) {
        try {
            $converted = [System.Collections.Generic.List[string]]::new()
            foreach ($f in $FoldersList) { if ($f) { $converted.Add([string]$f) } }
            # Update context reference to the converted list
            $Context.FoldersList = $converted
            $FoldersList = $converted
            Write-Log "PriorityQueue: converted FoldersList from $($FoldersList.GetType().Name) to List[string]"
        } catch {
            Write-ErrorGuard -Operation "PriorityReorder" -ErrorType "FoldersList type conversion failed: $($_.Exception.Message)" `
                -Severity "Warning" -SkipReason "Folders migrate in default order — non-fatal"
            return $true
        }
    }
    
    # Only reorder once per user (check if already ordered)
    $sessionKey = "PriorityOrdered_$Username"
    if ($Context.ContainsKey($sessionKey)) {
        return $true
    }
    
    if (-not $FoldersList -or $FoldersList.Count -le 1) {
        return $true
    }
    
    Write-Status "PriorityQueue: reordering folders for $Username" -Type "Info"
    
    $ordered = [System.Collections.Generic.List[string]]::new()
    $tier1 = @()
    $tier2 = @()
    $tier3 = @()
    $unknown = @()
    
    foreach ($folder in $FoldersList) {
        if ($folder -eq 'All') {
            # Can't reorder 'All' — exit
            Write-Log "PriorityQueue: 'All' folders selected — skipping reorder"
            $Context[$sessionKey] = $true
            return $true
        }
        
        $priority = $script:PriorityTiers[$folder]
        if ($priority -eq 1) { $tier1 += $folder }
        elseif ($priority -eq 2) { $tier2 += $folder }
        elseif ($priority -eq 3) { $tier3 += $folder }
        else { $unknown += $folder }
    }
    
    # Add in priority order — wrapped in try/catch so order failure never blocks migration
    try {
        foreach ($f in ($tier1 + $tier2 + $tier3 + $unknown)) {
            $ordered.Add($f)
        }
        $FoldersList.Clear()
        foreach ($f in $ordered) {
            $FoldersList.Add($f)
        }
        Write-Status "  Priority order: $($ordered -join ' → ')" -Type "Info"
        Write-Log "PriorityQueue reorder: $($ordered -join ', ')"
        $Context[$sessionKey] = $true
    } catch {
        Write-ErrorGuard -Operation "PriorityReorder" -ErrorType $_.Exception.Message `
            -Severity "Warning" `
            -SkipReason "Reorder failed — folders migrate in default order, non-fatal" `
            -Recovery @{ Hint = "Migration continues normally" }
    }
    return $true
}

# Also export as standard function for manual invocation
function Invoke-PriorityReorder {
    param([string[]]$Folders)
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $Folders) { $list.Add($f) }
    $null = PreFolder_ReorderByPriority -Username "manual" -FolderName "" -FoldersList $list
    return $list.ToArray()
}

Export-ModuleMember -Function 'PreFolder_ReorderByPriority'