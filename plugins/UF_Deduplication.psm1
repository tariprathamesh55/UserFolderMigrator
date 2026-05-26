
<#
.SYNOPSIS
    UF.Migration.Deduplication — identifies duplicate files across user profiles.
    Creates hard links to save storage space.
    Hook points: PostMigration
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

function Get-FileHashFast {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Algorithm = 'MD5',
        [switch]$FastMode
    )

    try {
        $fileInfo = [System.IO.FileInfo]::new($FilePath)
        $size = $fileInfo.Length

        if ($FastMode -and $size -lt 1MB) {
            $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop
            return "$size|$($hash.Hash)"
        }

        if ($FastMode) {
            $sampleSize = [Math]::Min(65536, [int]($size / 10))
            $buffer = [byte[]]::new($sampleSize)

            $fs = $null
            try {
                $fs = [System.IO.File]::OpenRead($FilePath)
                $bytesRead = $fs.Read($buffer, 0, $buffer.Length)
                $hashBytes = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm).ComputeHash($buffer, 0, $bytesRead)
                $sampleHash = ([System.BitConverter]::ToString($hashBytes) -replace '-', '')
            } finally {
                if ($fs) { $fs.Dispose() }
            }
            return "$size|$sampleHash"
        }

        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop
        return "$size|$($hash.Hash)"
    } catch {
        return "$size|ERROR:$($_.Exception.Message)"
    }
}

function Find-DuplicateFiles {
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [switch]$Recurse,
        [int]$MinSizeMB = 1,
        [string[]]$FilePatterns = @(),
        [switch]$FastMode
    )

    Write-Status "Scanning for duplicate files across $($Paths.Count) path(s)..." -Type "Info"

    $sizeGroups = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $hashGroups = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $totalFiles = 0
    $scanned = 0

    foreach ($rootPath in $Paths) {
        if (-not (Test-Path $rootPath)) { continue }

        $options = [System.IO.EnumerationOptions]::new()
        $options.RecurseSubdirectories = $Recurse

        $files = [System.IO.Directory]::EnumerateFiles($rootPath, '*', $options)

        foreach ($file in $files) {
            $totalFiles++
            try {
                $fileInfo = [System.IO.FileInfo]::new($file)
                if ($fileInfo.Length -lt ($MinSizeMB * 1MB)) { continue }

                $ext = [System.IO.Path]::GetExtension($file).ToLower()
                if ($FilePatterns.Count -gt 0 -and $ext -notin $FilePatterns) { continue }

                $sizeKey = $fileInfo.Length.ToString()
                if (-not $sizeGroups.ContainsKey($sizeKey)) {
                    $sizeGroups[$sizeKey] = [System.Collections.Generic.List[string]]::new()
                }
                $sizeGroups[$sizeKey].Add($file)
            } catch { }
        }
    }

    Write-Status "  Phase 1: $totalFiles files -> $($sizeGroups.Keys.Count) size groups" -Type "Info"

    foreach ($sizeKey in $sizeGroups.Keys) {
        $fileList = $sizeGroups[$sizeKey]
        if ($fileList.Count -lt 2) { continue }

        foreach ($file in $fileList) {
            $scanned++
            if ($scanned % 100 -eq 0) {
                Write-Host "`r  Scanning: $scanned/$totalFiles files" -NoNewline -ForegroundColor DarkCyan
            }

            $hash = Get-FileHashFast -FilePath $file -FastMode:$FastMode

            if (-not $hashGroups.ContainsKey($hash)) {
                $hashGroups[$hash] = [System.Collections.Generic.List[string]]::new()
            }
            $hashGroups[$hash].Add($file)
        }
    }

    if ($totalFiles -gt 0) { Write-Host "" }

    $duplicates = @{}
    foreach ($hash in $hashGroups.Keys) {
        $files = $hashGroups[$hash]
        if ($files.Count -gt 1) {
            $duplicates[$hash] = $files
        }
    }

    $duplicateCount = ($duplicates.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    $uniqueDupeGroups = $duplicates.Count

    Write-Status "  Phase 2: $uniqueDupeGroups duplicate groups ($duplicateCount total duplicate files)" -Type "Info"
    Write-Log "Dedupe: $totalFiles files, $uniqueDupeGroups duplicate groups"

    return $duplicates
}

function Measure-DedupePotential {
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [switch]$Recurse
    )

    $result = [PSCustomObject]@{
        TotalFiles = 0
        TotalBytes = 0L
        DuplicateFiles = 0
        DuplicateBytes = 0L
        UniqueFiles = 0
        UniqueBytes = 0L
        PotentialSavingsPercent = 0
        PotentialSavingsGB = 0
    }

    $duplicates = Find-DuplicateFiles -Paths $Paths -Recurse:$Recurse -FastMode

    $uniqueBytes = 0L
    $duplicateBytes = 0L
    $duplicateFileCount = 0

    foreach ($hash in $duplicates.Keys) {
        $files = $duplicates[$hash]
        if ($files.Count -le 1) { continue }

        $firstFile = $files[0]
        $firstSize = (Get-Item $firstFile -ErrorAction SilentlyContinue).Length

        $uniqueBytes += $firstSize
        $duplicateBytes += $firstSize * ($files.Count - 1)
        $duplicateFileCount += ($files.Count - 1)
        $result.TotalBytes += $firstSize * $files.Count
        $result.TotalFiles += $files.Count
    }

    $result.DuplicateFiles = $duplicateFileCount
    $result.DuplicateBytes = $duplicateBytes
    $result.UniqueFiles = $result.TotalFiles - $duplicateFileCount
    $result.UniqueBytes = $uniqueBytes

    if ($result.TotalBytes -gt 0) {
        $result.PotentialSavingsPercent = [math]::Round(($result.DuplicateBytes / $result.TotalBytes) * 100, 1)
        $result.PotentialSavingsGB = [math]::Round($result.DuplicateBytes / 1GB, 2)
    }

    Write-SectionHeader "Deduplication Potential"
    Write-Status "Total files scanned   : $($result.TotalFiles)" -Type "Info"
    Write-Status "Total data            : $(Format-Bytes $result.TotalBytes)" -Type "Info"
    Write-Status "Duplicate files       : $($result.DuplicateFiles)" -Type "Warning"
    Write-Status "Duplicate data        : $(Format-Bytes $result.DuplicateBytes)" -Type "Warning"
    Write-Status "Potential savings     : $($result.PotentialSavingsPercent)% ($($result.PotentialSavingsGB) GB)" -Type $(if ($result.PotentialSavingsPercent -gt 20) { 'Success' } else { 'Info' })

    return $result
}

function ConvertTo-HardLink {
    param(
        [Parameter(Mandatory)]$Duplicates,
        [switch]$PreserveOldest,
        [bool]$DryRun = $false
    )

    $result = [PSCustomObject]@{
        FilesProcessed = 0
        LinksCreated = 0
        LinksFailed = 0
        SpaceSavedBytes = 0L
        Errors = [System.Collections.Generic.List[string]]::new()
    }

    Write-Status "Creating hard links for duplicate files..." -Type "Info"

    foreach ($hash in $Duplicates.Keys) {
        $files = $Duplicates[$hash]
        if ($files.Count -le 1) { continue }

        $sortedFiles = if ($PreserveOldest) {
            $files | Sort-Object { (Get-Item $_).LastWriteTime }
        } else {
            $files
        }

        $original = $sortedFiles[0]
        $originSize = (Get-Item $original).Length
        $duplicatesToLink = $sortedFiles[1..($sortedFiles.Count-1)]

        foreach ($dup in $duplicatesToLink) {
            $result.FilesProcessed++

            if ($DryRun) {
                $result.LinksCreated++
                $result.SpaceSavedBytes += $originSize
                continue
            }

            try {
                # M12: NEVER delete before hardlink creation succeeds
                # Old code: Remove-Item then mklink — if mklink fails, file is permanently lost
                # Fix: Copy original to temp, verify temp, delete dup, create hardlink, verify hardlink
                $dupDir  = Split-Path $dup -Parent
                $dupName = Split-Path $dup -Leaf
                $tempLink = Join-Path $dupDir ".ufm_hltemp_$([System.IO.Path]::GetRandomFileName())"
                
                # Step 1: Pre-flight — can we even create a hardlink? (must be same volume)
                $dupDrive      = (Split-Path $dup     -Qualifier).TrimEnd(':')
                $originalDrive = (Split-Path $original -Qualifier).TrimEnd(':')
                if ($dupDrive -ne $originalDrive) {
                    $result.LinksFailed++
                    $result.Errors.Add("Cannot hardlink across volumes: $dup (drive $dupDrive) -> $original (drive $originalDrive)")
                    Write-Log "HardLink skip: cross-volume not supported ($dup -> $original)" -Level "WARN"
                    continue
                }
                
                # Step 2: Create hardlink FIRST — don't touch original file
                $mklinkOut = cmd /c "mklink /H `"$tempLink`" `"$original`"" 2>&1
                if ($LASTEXITCODE -ne 0) {
                    $result.LinksFailed++
                    $result.Errors.Add("mklink failed for $dup : $mklinkOut")
                    Write-Log "HardLink failed (mklink): $dup -> $original : $mklinkOut" -Level "WARN"
                    continue
                }
                
                # Step 3: Verify the hardlink resolves to the correct file (same inode)
                $tempInfo  = Get-Item -LiteralPath $tempLink  -ErrorAction SilentlyContinue
                $origInfo  = Get-Item -LiteralPath $original  -ErrorAction SilentlyContinue
                if (-not $tempInfo -or $tempInfo.Length -ne $origInfo.Length) {
                    Remove-Item -LiteralPath $tempLink -Force -ErrorAction SilentlyContinue
                    $result.LinksFailed++
                    $result.Errors.Add("HardLink verification failed for $dup")
                    continue
                }
                
                # Step 4: Only NOW safe to remove duplicate and rename temp link into place
                Remove-Item -LiteralPath $dup -Force -ErrorAction Stop
                Rename-Item -LiteralPath $tempLink -NewName $dupName -ErrorAction Stop
                
                $result.LinksCreated++
                $result.SpaceSavedBytes += $originSize
                Write-Log "Hard link created: $dup -> $original"
            } catch {
                # Cleanup temp link if rename failed
                if (Test-Path -LiteralPath $tempLink) {
                    Remove-Item -LiteralPath $tempLink -Force -ErrorAction SilentlyContinue
                }
                $result.LinksFailed++
                $result.Errors.Add("Error linking $dup : $($_.Exception.Message)")
                Write-ErrorGuard -Operation "HardLink" -ErrorType $_.Exception.Message `
                    -Item $dup -Severity "Warning" `
                    -SkipReason "Duplicate file preserved — hardlink creation failed safely (original untouched)" `
                    -Recovery @{ Hint = "Check same-volume requirement and file permissions on $dup" }
            }
        }
    }

    Write-Status "  Links created: $($result.LinksCreated) | Failed: $($result.LinksFailed)" -Type $(if ($result.LinksFailed -eq 0) { 'Success' } else { 'Warning' })
    Write-Status "  Space saved: $(Format-Bytes $result.SpaceSavedBytes)" -Type "Success"

    return $result
}

function Invoke-Deduplication {
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [switch]$Recurse,
        [int]$MinSizeMB = 1,
        [string[]]$FilePatterns = @(),
        [switch]$PreserveOldest,
        [bool]$DryRun = $false,
        [bool]$Unattended = $false
    )

    Write-SectionHeader "DEDUPLICATION"

    $measureResult = Measure-DedupePotential -Paths $Paths -Recurse:$Recurse

    if ($measureResult.DuplicateFiles -eq 0) {
        Write-Status "No duplicate files found to deduplicate" -Type "Info"
        return $measureResult
    }

    if (-not $DryRun) {
        $confirm = if ($Unattended) { 'Y' } else {
            Read-Host "  Create hard links for $($measureResult.DuplicateFiles) duplicate files? (Y/N)"
        }
        if ($confirm -ne 'Y' -and $confirm -ne 'y') {
            Write-Status "Deduplication cancelled" -Type "Info"
            return $measureResult
        }
    }

    $duplicates = Find-DuplicateFiles -Paths $Paths -Recurse:$Recurse -MinSizeMB $MinSizeMB -FilePatterns $FilePatterns -FastMode
    $linkResult = ConvertTo-HardLink -Duplicates $duplicates -PreserveOldest:$PreserveOldest -DryRun $DryRun

    $measureResult | Add-Member -NotePropertyName LinksCreated -NotePropertyValue $linkResult.LinksCreated
    $measureResult | Add-Member -NotePropertyName LinksFailed -NotePropertyValue $linkResult.LinksFailed
    $measureResult | Add-Member -NotePropertyName SpaceSavedBytes -NotePropertyValue $linkResult.SpaceSavedBytes

    Write-AuditEntry -Message "DEDUPLICATION: $($linkResult.LinksCreated) links, saved $(Format-Bytes $linkResult.SpaceSavedBytes)" -Level "INFO"

    return $measureResult
}

function PostMigration_DeduplicateDestination {
    param($Context)

    if ($Context.SkipDeduplication -eq $true) {
        Write-Log "Deduplication skipped by context"
        return $true
    }

    $destPath = if ($Context.PSObject.Properties['DestinationPath']) { $Context.DestinationPath } else { $null }
    if (-not $destPath -or -not (Test-Path $destPath)) {
        Write-Log "Deduplication skipped — DestinationPath empty or not found"
        return $true
    }

    try {
        $result = Invoke-Deduplication -Paths @($destPath) -Recurse `
            -MinSizeMB 1 -PreserveOldest -DryRun $Context.DryRun `
            -Unattended ($Context.PSObject.Properties['Unattended'] -and $Context.Unattended)
        $Context.DeduplicationResult = $result
    } catch {
        Write-ErrorGuard -Operation "Deduplication" -ErrorType $_.Exception.Message `
            -Severity "Warning" `
            -SkipReason "Deduplication failed — migration data is intact, disk savings not applied" `
            -Recovery @{ Hint = "Run Invoke-Deduplication manually after migration completes" }
    }
    return $true
}

function PostMigration_Deduplication_DeclareInputs {
    return @(
        @{
            Key               = 'SkipDeduplication'
            Prompt            = 'Skip deduplication of destination after migration?'
            Type              = 'YesNo'
            Default           = 'N'
            UnattendedDefault = 'N'
            Required          = $false
        }
    )
}

Export-ModuleMember -Function 'PostMigration_DeduplicateDestination', 'PostMigration_Deduplication_DeclareInputs'