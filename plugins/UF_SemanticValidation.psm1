
<#
.SYNOPSIS
    UF.Migration.SemanticValidation — validates file content actually opens/can be read.
    Detects silent corruption that hash checks miss.
    Hook points: PostFolder
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

function Get-FileMagicNumber {
    param([string]$FilePath)

    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -lt 4) { return $null }

        $header = ($bytes[0..3] | ForEach-Object { $_.ToString('X2') }) -join ''

        $magicMap = @{
            'D0CF11E0' = 'DOC/XLS/PPT (OLE)'
            '504B0304' = 'DOCX/XLSX/PPTX (ZIP)'
            '25504446' = 'PDF'
            'FFD8FFE0' = 'JPEG'
            'FFD8FFE1' = 'JPEG (EXIF)'
            '89504E47' = 'PNG'
            '47494638' = 'GIF'
            '424D'     = 'BMP'
            '7B5C7274' = 'RTF'
            '1F8B08'   = 'GZIP'
            '3C3F786D' = 'XML'
        }

        foreach ($magic in $magicMap.Keys) {
            if ($header.StartsWith($magic)) {
                return $magicMap[$magic]
            }
        }
        return 'Unknown'
    } catch {
        return 'Error'
    }
}

function Test-FileOpens {
    param([Parameter(Mandatory)][string]$FilePath)

    $result = [PSCustomObject]@{
        Passed = $false
        Error = ''
        SizeBytes = 0L
        FileType = ''
    }

    try {
        $fileInfo = [System.IO.FileInfo]::new($FilePath)
        $result.SizeBytes = $fileInfo.Length
        $result.FileType = Get-FileMagicNumber -FilePath $FilePath

        $fs = $null
        try {
            $fs = [System.IO.File]::OpenRead($FilePath)
            $buffer = [byte[]]::new(1024)
            $bytesRead = $fs.Read($buffer, 0, 1024)
            $result.Passed = $bytesRead -gt 0
        } finally {
            if ($fs) { $fs.Dispose() }
        }
    } catch {
        $result.Error = $_.Exception.Message
        $result.Passed = $false
    }

    return $result
}

function Test-DocxIntegrity {
    param([Parameter(Mandatory)][string]$FilePath)

    $result = [PSCustomObject]@{
        Passed = $false
        Error = ''
        MissingParts = [System.Collections.Generic.List[string]]::new()
        FileCount = 0
    }

    try {
        $requiredFiles = @(
            '[Content_Types].xml',
            '_rels/.rels'
        )

        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

        $zip = $null
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
            $entries = $zip.Entries | ForEach-Object { $_.FullName }
            $result.FileCount = $entries.Count

            foreach ($required in $requiredFiles) {
                if ($entries -notcontains $required) {
                    $result.MissingParts.Add($required)
                }
            }

            $result.Passed = ($result.MissingParts.Count -eq 0) -and ($result.FileCount -gt 0)
        } finally {
            if ($zip) { $zip.Dispose() }
        }
    } catch {
        $result.Error = $_.Exception.Message
        $result.Passed = $false
    }

    return $result
}

function Test-ImageIntegrity {
    param([Parameter(Mandatory)][string]$FilePath)

    $result = [PSCustomObject]@{
        Passed = $false
        Error = ''
        Width = 0
        Height = 0
        Format = ''
    }

    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

        $image = $null
        try {
            # M6: Load via MemoryStream so file handle is released immediately
            # System.Drawing.Image.FromFile holds a GDI lock until Dispose — copy to memory first
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)
            $ms    = [System.IO.MemoryStream]::new($bytes)
            $image = [System.Drawing.Image]::FromStream($ms)
            $result.Width  = $image.Width
            $result.Height = $image.Height
            $result.Format = $image.RawFormat.ToString()
            $result.Passed = ($result.Width -gt 0) -and ($result.Height -gt 0)
        } finally {
            if ($image) { $image.Dispose() }
            if ($ms)    { $ms.Dispose() }
        }
    } catch {
        $result.Error = $_.Exception.Message
        $result.Passed = $false
    }

    return $result
}

function Invoke-SemanticValidation {
    param(
        [Parameter(Mandatory)][string]$FolderPath,
        [switch]$Recursive,
        [int]$SamplePercentage = 0,
        [bool]$DryRun = $false
    )

    $result = [PSCustomObject]@{
        Passed = $true
        TotalFiles = 0
        TestedFiles = 0
        CorruptedFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
        Errors = [System.Collections.Generic.List[string]]::new()
        StartTime = Get-Date
        EndTime = $null
        DurationSec = 0
    }

    if (-not (Test-Path $FolderPath)) {
        $result.Errors.Add("Folder not found: $FolderPath")
        $result.Passed = $false
        return $result
    }

    $options = [System.IO.EnumerationOptions]::new()
    $options.RecurseSubdirectories = $Recursive

    $allFiles = @(try { [System.IO.Directory]::EnumerateFiles($FolderPath, '*', $options) } catch { @() })
    $result.TotalFiles = $allFiles.Count

    $filesToTest = if ($SamplePercentage -gt 0 -and $SamplePercentage -lt 100) {
        $sampleCount = [Math]::Max(1, [int]($allFiles.Count * $SamplePercentage / 100))
        $allFiles | Get-Random -Count $sampleCount
    } else {
        $allFiles
    }

    $result.TestedFiles = $filesToTest.Count

    Write-Status "Semantic validation: testing $($result.TestedFiles) of $($result.TotalFiles) file(s)" -Type "Info"

    $tested = 0
    foreach ($file in $filesToTest) {
        $tested++
        $extension = [System.IO.Path]::GetExtension($file).ToLower()

        if ($tested % 100 -eq 0) {
            Write-Host "`r  Progress: $tested/$($result.TestedFiles)" -NoNewline -ForegroundColor DarkCyan
        }

        if ($DryRun) {
            continue
        }

        $openResult = Test-FileOpens -FilePath $file
        if (-not $openResult.Passed) {
            $result.CorruptedFiles.Add([PSCustomObject]@{
                FilePath = $file
                Type = $openResult.FileType
                Error = $openResult.Error
                Reason = 'CannotOpen'
            })
            $result.Passed = $false
            continue
        }

        if ($extension -in @('.docx', '.xlsx', '.pptx')) {
            $docxResult = Test-DocxIntegrity -FilePath $file
            if (-not $docxResult.Passed) {
                $result.CorruptedFiles.Add([PSCustomObject]@{
                    FilePath = $file
                    Type = 'OfficeOpenXML'
                    Error = $docxResult.Error
                    Reason = "Missing parts: $($docxResult.MissingParts -join ', ')"
                })
                $result.Passed = $false
            }
        }
        elseif ($extension -in @('.jpg', '.jpeg', '.png', '.gif', '.bmp')) {
            $imgResult = Test-ImageIntegrity -FilePath $file
            if (-not $imgResult.Passed) {
                $result.CorruptedFiles.Add([PSCustomObject]@{
                    FilePath = $file
                    Type = 'Image'
                    Error = $imgResult.Error
                    Reason = 'CannotDecode'
                })
                $result.Passed = $false
            }
        }
    }

    if ($result.TestedFiles -gt 0) { Write-Host "" }

    $result.EndTime = Get-Date
    $result.DurationSec = [math]::Round(($result.EndTime - $result.StartTime).TotalSeconds, 1)

    if ($result.Passed) {
        Write-Status "Semantic validation: PASSED ($($result.TestedFiles) files, $($result.DurationSec)s)" -Type "Success"
    } else {
        Write-Status "Semantic validation: FAILED — $($result.CorruptedFiles.Count) corrupted file(s)" -Type "Error"
        foreach ($corrupt in $result.CorruptedFiles | Select-Object -First 5) {
            Write-Status "  - $(Split-Path $corrupt.FilePath -Leaf) : $($corrupt.Reason)" -Type "Warning"
        }
        if ($result.CorruptedFiles.Count -gt 5) {
            Write-Status "  ... and $($result.CorruptedFiles.Count - 5) more" -Type "Info"
        }
    }

    Write-Log "SemanticValidation: $($result.TestedFiles) tested, $($result.CorruptedFiles.Count) corrupted"

    return $result
}

function Repair-CorruptedFile {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$BackupPath = '',
        [string]$VssSnapshotPath = '',
        [bool]$DryRun = $false
    )

    Write-Status "Attempting repair: $(Split-Path $FilePath -Leaf)" -Type "Info"

    if ($DryRun) {
        Write-Status "  [DRY RUN] Would attempt repair" -Type "Info"
        return $true
    }

    $source = if ($BackupPath -and (Test-Path $BackupPath)) {
        $BackupPath
    } elseif ($VssSnapshotPath) {
        $vssFile = $FilePath -replace '^[A-Z]:\\', "$VssSnapshotPath"
        if (Test-Path $vssFile) { $vssFile } else { $null }
    } else {
        $null
    }

    if (-not $source) {
        Write-Status "  No valid repair source found" -Type "Error"
        return $false
    }

    try {
        Copy-Item -LiteralPath $source -Destination $FilePath -Force -ErrorAction Stop
        Write-Status "  Repaired successfully from $source" -Type "Success"
        Write-Log "Repaired file: $FilePath from $source"
        return $true
    } catch {
        Write-Status "  Repair failed: $($_.Exception.Message)" -Type "Error"
        return $false
    }
}

function PostFolder_SemanticValidate {
    param($Context)

    if ($Context.PSObject.Properties['SkipValidation'] -and $Context.SkipValidation -eq $true) {
        Write-Log "Semantic validation skipped by context"
        return $true
    }

# After (fixed):
$files = @(Get-ChildItem -LiteralPath $Context.DestPath -File -Recurse -ErrorAction SilentlyContinue)
$fileCount = if ($files) { $files.Count } else { 0 }
if ($fileCount -eq 0) {
    return $true
}

    # Initialise $result so the post-catch check is always safe under StrictMode
    $result = [PSCustomObject]@{
        Passed = $true
        CorruptedFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    try {
        $result = Invoke-SemanticValidation -FolderPath $Context.DestPath -Recursive `
            -SamplePercentage 10 -DryRun $Context.DryRun
        $Context.ValidationResult = $result
    } catch {
        Write-ErrorGuard -Operation "SemanticValidation" -ErrorType $_.Exception.Message `
            -Severity "Warning" `
            -SkipReason "Semantic validation failed — files are present, content integrity unverified" `
            -Diagnostics @{ "Path" = $Context.DestPath } `
            -Recovery @{ Hint = "Run Invoke-SemanticValidation manually on destination folder" }
    }

    if (-not $result.Passed -and $result.CorruptedFiles.Count -gt 0) {
        Write-AuditEntry -Message "SEMANTIC_VALIDATION_FAIL: $($Context.FolderName) - $($result.CorruptedFiles.Count) corrupt files" -Level "WARN"

        if ($Context.PSObject.Properties['StopOnCorruption'] -and $Context.StopOnCorruption -eq $true) {
            return $false
        }
    }

    return $true
}

function PostFolder_Validation_DeclareInputs {
    return @(
        @{
            Key               = 'StopOnCorruption'
            Prompt            = 'Abort migration if corrupt files are detected in a folder?'
            Type              = 'YesNo'
            Default           = 'N'
            UnattendedDefault = 'N'
            Required          = $false
        }
    )
}

Export-ModuleMember -Function 'PostFolder_SemanticValidate', 'PostFolder_Validation_DeclareInputs'