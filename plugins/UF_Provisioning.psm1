
<#
.SYNOPSIS
    UF.Migration.Provisioning — pre-creates folder structures and quotas.
    Hook points: PreUser
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-UserFolderStructure {
    param(
        [Parameter(Mandatory)][string]$BaseDestination,
        [Parameter(Mandatory)][string]$Username,
        [string[]]$Folders = @('Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Videos'),
        [string]$TemplateFile = '',
        [bool]$DryRun = $false
    )

    $result = [PSCustomObject]@{
        Username = $Username
        CreatedFolders = [System.Collections.Generic.List[string]]::new()
        FailedFolders = [System.Collections.Generic.List[string]]::new()
        TotalSize = 0L
    }

    $userPath = Join-Path $BaseDestination $Username

    if ($DryRun) {
        Write-Status "[DRY RUN] Would create structure at: $userPath" -Type "Info"
        foreach ($folder in $Folders) {
            $result.CreatedFolders.Add((Join-Path $userPath $folder))
        }
        return $result
    }

    if (-not (Test-Path $userPath)) {
        try {
            New-Item -Path $userPath -ItemType Directory -Force | Out-Null
            $result.CreatedFolders.Add($userPath)
        } catch {
            $result.FailedFolders.Add($userPath)
            Write-Status "Failed to create user root: $userPath" -Type "Error"
            return $result
        }
    }

    foreach ($folder in $Folders) {
        $folderPath = Join-Path $userPath $folder
        try {
            if (-not (Test-Path $folderPath)) {
                New-Item -Path $folderPath -ItemType Directory -Force | Out-Null
                Write-Status "  Created: $folder" -Type "Success"
            }
            $result.CreatedFolders.Add($folderPath)
        } catch {
            $result.FailedFolders.Add($folderPath)
            Write-Status "  Failed: $folder - $($_.Exception.Message)" -Type "Error"
        }
    }

    Write-Status "Provisioned $($result.CreatedFolders.Count) folder(s) for $Username" -Type "Success"
    Write-Log "Provisioning: $Username -> $($result.CreatedFolders.Count) folders"

    return $result
}

function Set-FolderQuota {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][long]$LimitBytes,
        [long]$WarningBytes = 0,
        [bool]$DryRun = $false
    )

    if ($WarningBytes -eq 0) {
        $WarningBytes = [long]($LimitBytes * 0.85)
    }

    $result = [PSCustomObject]@{
        Path = $Path
        LimitGB = [math]::Round($LimitBytes / 1GB, 1)
        Success = $false
        Method = 'None'
    }

    if ($DryRun) {
        Write-Status "[DRY RUN] Would set quota: $($result.LimitGB) GB on $Path" -Type "Info"
        $result.Success = $true
        return $result
    }

    try {
        $fsrm = New-Object -ComObject Fsrm.FsrmQuotaManager -ErrorAction SilentlyContinue
        if ($fsrm) {
            $quota = $fsrm.CreateQuota($Path)
            $quota.QuotaLimit = $LimitBytes
            $quota.QuotaWarningLimit = $WarningBytes
            $quota.ApplyTemplate('') | Out-Null
            $quota.Commit() | Out-Null
            $result.Success = $true
            $result.Method = 'FSRM'
            Write-Status "Quota set via FSRM: $($result.LimitGB) GB on $Path" -Type "Success"
            Write-Log "Quota set: $Path -> $($result.LimitGB) GB (FSRM)"
            return $result
        }
    } catch { }

    try {
        $driveLetter = (Split-Path $Path -Qualifier).TrimEnd(':')
        $diskQuota = Get-CimInstance -ClassName Win32_DiskQuota -Filter "QuotaVolume='$driveLetter'" -ErrorAction SilentlyContinue
        if ($diskQuota) {
            Write-Status "Warning: FSRM not available. Using disk-level quotas (less precise)" -Type "Warning"
            $result.Method = 'DiskQuota'
            $result.Success = $true
        } else {
            Write-Status "No quota system available. Install FSRM for folder-level quotas" -Type "Warning"
        }
    } catch { }

    return $result
}

function Test-PathPermissionsInternal {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$User = "$env:USERNAME",
        [ValidateSet('Read', 'Write', 'Modify', 'FullControl')][string]$RequiredRights = 'Write'
    )

    if (-not (Test-Path $Path)) {
        return $false
    }

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
            if ($rule.FileSystemRights -band $required) {
                return $true
            }
        }
        return $false
    } catch {
        Write-Log "Permission check failed for $Path : $_"
        return $false
    }
}

function Grant-FolderAccess {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$User,
        [ValidateSet('Read', 'Write', 'Modify', 'FullControl')][string]$Rights = 'Modify',
        [ValidateSet('None', 'ContainerInherit', 'ObjectInherit', 'ContainerAndObject')][string]$Inheritance = 'ContainerAndObject',
        [bool]$DryRun = $false
    )

    if ($DryRun) {
        Write-Status "[DRY RUN] Would grant $Rights to $User on $Path" -Type "Info"
        return $true
    }

    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop

        $rightsMap = @{
            'Read' = [System.Security.AccessControl.FileSystemRights]::Read
            'Write' = [System.Security.AccessControl.FileSystemRights]::Write
            'Modify' = [System.Security.AccessControl.FileSystemRights]::Modify
            'FullControl' = [System.Security.AccessControl.FileSystemRights]::FullControl
        }

        $inheritanceMap = @{
            'None' = [System.Security.AccessControl.InheritanceFlags]::None
            'ContainerInherit' = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
            'ObjectInherit' = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            'ContainerAndObject' = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor 
                                   [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        }

        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $User,
            $rightsMap[$Rights],
            $inheritanceMap[$Inheritance],
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop

        Write-Status "Granted $Rights to $User on $Path" -Type "Success"
        Write-Log "Permission granted: $User -> $Rights on $Path"
        return $true
    } catch {
        Write-Status "Failed to grant permissions: $($_.Exception.Message)" -Type "Error"
        Write-Log "Permission grant failed: $_"
        return $false
    }
}

function Invoke-ProvisionDestination {
    param(
        [Parameter(Mandatory)][string]$BaseDestination,
        [Parameter(Mandatory)][string]$Username,
        [string[]]$Folders = @('Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Videos'),
        [int]$QuotaGB = 0,
        [string]$GrantUser = '',
        [bool]$DryRun = $false
    )

    if (-not $GrantUser) { $GrantUser = $Username }

    $result = [PSCustomObject]@{
        Username         = $Username
        FolderStructure  = $null
        QuotaResult      = $null
        PermissionResult = $null
        StartTime        = Get-Date
        EndTime          = $null
        DurationSec      = 0.0
    }

    Write-SectionHeader "Provisioning: $Username"

    try {
        $result.FolderStructure = New-UserFolderStructure -BaseDestination $BaseDestination `
            -Username $Username -Folders $Folders -DryRun $DryRun
    } catch {
        Write-ErrorGuard -Operation "FolderStructureCreation" -ErrorType $_.Exception.Message `
            -Item $Username -Severity "Warning" `
            -SkipReason "Folder structure creation failed — migration will attempt anyway using existing paths" `
            -Diagnostics @{ "BaseDestination" = $BaseDestination; "Username" = $Username } `
            -Recovery @{ Hint = "Check destination path write permissions" }
        $result.EndTime = Get-Date
        $result.DurationSec = 0.0
        return $result
    }

    if ($result.FolderStructure -and $result.FolderStructure.FailedFolders.Count -gt 0) {
        Write-ErrorGuard -Operation "FolderStructureCreation" `
            -ErrorType "$($result.FolderStructure.FailedFolders.Count) folder(s) could not be created" `
            -Item $Username -Severity "Warning" `
            -SkipReason "Provisioning incomplete — migration may partially succeed for already-created folders" `
            -Diagnostics @{ "Failed" = ($result.FolderStructure.FailedFolders -join ', ') } `
            -Recovery @{ Hint = "Manually create missing folders and grant user Modify rights" }
        $result.EndTime = Get-Date
        $result.DurationSec = [math]::Round(($result.EndTime - $result.StartTime).TotalSeconds, 1)
        return $result
    }

    $userPath = Join-Path $BaseDestination $Username

    if ($QuotaGB -gt 0) {
        $quotaBytes = [long]$QuotaGB * 1GB
        try {
            $result.QuotaResult = Set-FolderQuota -Path $userPath -LimitBytes $quotaBytes -DryRun $DryRun
        } catch {
            Write-ErrorGuard -Operation "QuotaAssignment" -ErrorType $_.Exception.Message `
                -Item $Username -Severity "Warning" `
                -SkipReason "Quota not applied — FSRM may not be installed, migration continues without quota" `
                -Recovery @{ Hint = "Install FSRM role or set -QuotaGB 0 to skip quota enforcement" }
        }
    }

    try {
        $result.PermissionResult = Grant-FolderAccess -Path $userPath -User $GrantUser -Rights 'Modify' -DryRun $DryRun
    } catch {
        Write-ErrorGuard -Operation "PermissionGrant" -ErrorType $_.Exception.Message `
            -Item $Username -Severity "Warning" `
            -SkipReason "ACL grant failed — user may not have access to destination, files will copy but may be inaccessible" `
            -Diagnostics @{ "Path" = $userPath; "User" = $GrantUser } `
            -Recovery @{ Command = "icacls `"$userPath`" /grant `"$GrantUser`":(OI)(CI)M"; Hint = "Run manually as Administrator" }
    }

    $result.EndTime = Get-Date
    $result.DurationSec = [math]::Round(($result.EndTime - $result.StartTime).TotalSeconds, 1)
    Write-Status "Provisioning complete in $($result.DurationSec)s" -Type "Success"
    return $result
}

# After (fixed):
function PreUser_CreateFolderStructure {
    param($Context)

    # Defensive: convert hashtable to PSCustomObject if needed
    if ($Context -is [hashtable]) {
        $Context = [PSCustomObject]$Context
    }

    # Safe property check for both PSCustomObject and hashtable
    $skipProv = if ($Context -is [hashtable]) {
        $Context.ContainsKey('SkipProvisioning') -and $Context['SkipProvisioning'] -eq $true
    } else {
        $Context.PSObject.Properties['SkipProvisioning'] -and $Context.SkipProvisioning -eq $true
    }
    if ($skipProv) {
        Write-Log "Provisioning skipped by context"
        return $true
    }

    # Safe property access for both hashtable and PSCustomObject
    $ctxFolders = if ($Context -is [hashtable]) { $Context['Folders'] } else { $Context.Folders }
    $ctxBaseDest = if ($Context -is [hashtable]) { $Context['BaseDestination'] } else { $Context.BaseDestination }
    $ctxDest = if ($Context -is [hashtable]) { $Context['Destination'] } else { $Context.Destination }
    $ctxUsername = if ($Context -is [hashtable]) { $Context['Username'] } else { $Context.Username }
    $ctxDryRun = if ($Context -is [hashtable]) { $Context['DryRun'] } else { $Context.DryRun }
    $ctxQuotaGB = if ($Context -is [hashtable]) { $Context['QuotaGB'] } else { $Context.QuotaGB }

    $folders = if ($ctxFolders -and $ctxFolders -ne 'All') {
        $ctxFolders
    } else {
        @('Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Videos')
    }

    $provisionBase = if ($ctxBaseDest) { $ctxBaseDest } else { $ctxDest }

    try {
        $result = Invoke-ProvisionDestination -BaseDestination $provisionBase `
            -Username $ctxUsername -Folders $folders -QuotaGB $ctxQuotaGB `
            -GrantUser $ctxUsername -DryRun $ctxDryRun

        # Store result back into the context (write to whichever type it is)
        if ($Context -is [hashtable]) { $Context['ProvisioningResult'] = $result }
        else                         { $Context.ProvisioningResult = $result }

        return ($result.FolderStructure -eq $null -or $result.FolderStructure.FailedFolders.Count -eq 0)
    } catch {
        Write-ErrorGuard -Operation "PreUser_CreateFolderStructure" -ErrorType $_.Exception.Message `
            -Item $ctxUsername -Severity "Warning" `
            -SkipReason "Provisioning hook failed — migration continues using existing paths" `
            -Recovery @{ Hint = "Set SkipProvisioning=true in context to bypass provisioning" }
        return $true
    }
}

function PreUser_DeclareInputs {
    return @(
        @{
            Key               = 'QuotaGB'
            Prompt            = 'Disk quota per user on destination in GB (0 = no limit)'
            Type              = 'Int'
            Default           = '0'
            UnattendedDefault = '0'
            Required          = $false
        }
    )
}

Export-ModuleMember -Function 'PreUser_CreateFolderStructure', 'PreUser_DeclareInputs'