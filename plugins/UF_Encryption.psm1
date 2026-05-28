
<#
.SYNOPSIS
    UF.Migration.Encryption — EFS and BitLocker integration for data protection.
    Hook points: PreFolder, PostFolder
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-BitLockerStatus {
    param([Parameter(Mandatory)][string]$DriveLetter)

    $result = [PSCustomObject]@{
        DriveLetter = $DriveLetter
        IsEncrypted = $false
        EncryptionPercentage = 0
        ProtectionStatus = 'Unknown'
        KeyProtectors = @()
        Error = ''
    }

    try {
        $volume = Get-BitLockerVolume -MountPoint "${DriveLetter}:" -ErrorAction SilentlyContinue
        if ($volume) {
            $result.IsEncrypted = $volume.ProtectionStatus -eq 'On'
            $result.EncryptionPercentage = $volume.EncryptionPercentage
            $result.ProtectionStatus = $volume.ProtectionStatus

            $protectors = Get-BitLockerVolume -MountPoint "${DriveLetter}:" |
                          Select-Object -ExpandProperty KeyProtector
            $result.KeyProtectors = $protectors | ForEach-Object { $_.KeyProtectorType }
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Enable-EFSEncryption {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$CertificateThumbprint = '',
        [string]$BackupCertPath = '',
        [bool]$DryRun = $false
    )

    $result = [PSCustomObject]@{
        Path = $Path
        Success = $false
        FilesEncrypted = 0
        Errors = [System.Collections.Generic.List[string]]::new()
    }

    if (-not (Test-Path $Path)) {
        $result.Errors.Add("Path not found: $Path")
        return $result
    }

    Write-Status "Enabling EFS encryption on: $Path" -Type "Info"

    if ($DryRun) {
        Write-Status "  [DRY RUN] Would encrypt $(Get-ChildItem $Path -Recurse -File | Measure-Object).Count files" -Type "Info"
        $result.Success = $true
        return $result
    }

    try {
        $cipherPath = "$env:SystemRoot\System32\cipher.exe"
        if (-not (Test-Path $cipherPath)) {
            throw "cipher.exe not found at $cipherPath"
        }

        # L12: ArgumentList as string fails on paths with Unicode or special chars — use array form
        $process = Start-Process -FilePath $cipherPath -ArgumentList @('/e', "/s:$Path") `
            -NoNewWindow -Wait -PassThru

        if ($process.ExitCode -eq 0) {
            $result.Success = $true
            $result.FilesEncrypted = (Get-ChildItem $Path -Recurse -File | Where-Object {
                (Get-Item $_).Attributes -match 'Encrypted'
            }).Count

            Write-Status "  Encrypted $($result.FilesEncrypted) file(s)" -Type "Success"

            if ($BackupCertPath) {
                $certResult = Backup-EFSCertificate -OutputPath $BackupCertPath -DryRun $DryRun
                if ($certResult.Success) {
                    Write-Status "  Certificate backed up to: $BackupCertPath" -Type "Success"
                }
            }
        } else {
            $result.Errors.Add("cipher.exe exited with code $($process.ExitCode)")
            Write-Status "  Encryption failed with exit code $($process.ExitCode)" -Type "Error"
        }
    } catch {
        $result.Errors.Add($_.Exception.Message)
        Write-Status "  Encryption failed: $($_.Exception.Message)" -Type "Error"
    }

    Write-Log "EFS encryption: Path=$Path Success=$($result.Success) Files=$($result.FilesEncrypted)"
    return $result
}

function Test-EFSStatus {
    param([Parameter(Mandatory)][string]$Path)

    $result = [PSCustomObject]@{
        Path = $Path
        IsEncrypted = $false
        EncryptedFileCount = 0
        CertificateThumbprints = @()
    }

    if (-not (Test-Path $Path)) {
        return $result
    }

    $item = Get-Item $Path
    $result.IsEncrypted = $item.Attributes -match 'Encrypted'

    if ((Get-Item $Path).PSIsContainer) {
        $encryptedFiles = Get-ChildItem $Path -Recurse -File | Where-Object {
            (Get-Item $_).Attributes -match 'Encrypted'
        }
        $result.EncryptedFileCount = $encryptedFiles.Count
        $result.IsEncrypted = $result.EncryptedFileCount -gt 0
    }

    try {
        $cipherPath = "$env:SystemRoot\System32\cipher.exe"
        $tempFile = [System.IO.Path]::GetTempFileName()

        $process = Start-Process -FilePath $cipherPath -ArgumentList @('/c', $Path) `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tempFile

        if ($process.ExitCode -eq 0) {
            $output = Get-Content $tempFile -Raw
            $certs = [regex]::Matches($output, '[A-F0-9]{40}')
            foreach ($cert in $certs) {
                $result.CertificateThumbprints += $cert.Value
            }
        }
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    } catch { }

    return $result
}

function Backup-EFSCertificate {
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$Password = '',
        [bool]$DryRun = $false
    )

    $result = [PSCustomObject]@{
        Success = $false
        OutputPath = $OutputPath
        Password = ''
    }

    if ($DryRun) {
        Write-Status "  [DRY RUN] Would backup EFS certificate to $OutputPath" -Type "Info"
        $result.Success = $true
        return $result
    }

    try {
        if (-not $Password) {
            $Password = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([Guid]::NewGuid().ToString()))
            $result.Password = $Password
        }

        $certs = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {
            $_.EnhancedKeyUsageList -match 'Encrypting File System'
        }

        if ($certs.Count -eq 0) {
            throw "No EFS certificate found in CurrentUser\My store"
        }

        $certToExport = $certs[0]
        $pfxBytes = $certToExport.Export('Pfx', $Password)
        [System.IO.File]::WriteAllBytes($OutputPath, $pfxBytes)

        $result.Success = $true
        Write-Status "  EFS certificate backed up: $OutputPath" -Type "Success"
        Write-Log "EFS certificate backup: Thumbprint=$($certToExport.Thumbprint) Output=$OutputPath"

        if ($Password) {
            Write-Status "  Password (save securely): $Password" -Type "Warning"
        }
    } catch {
        Write-Status "  EFS certificate backup failed: $($_.Exception.Message)" -Type "Error"
        Write-Log "EFS backup error: $_"
    }

    return $result
}

function Invoke-EncryptDestination {
    param(
        [Parameter(Mandatory)][string]$DestinationPath,
        [switch]$EnableBitLocker,
        [switch]$EnableEFS,
        [string]$BackupCertPath = '',
        [bool]$DryRun = $false
    )

    $result = [PSCustomObject]@{
        BitLockerStatus = $null
        EFSStatus = $null
        CertificateBackup = $null
    }

    Write-SectionHeader "Encryption"

    $driveLetter = (Split-Path $DestinationPath -Qualifier).TrimEnd(':')

    if ($EnableBitLocker) {
        $bitStatus = Test-BitLockerStatus -DriveLetter $driveLetter
        $result.BitLockerStatus = $bitStatus

        if (-not $bitStatus.IsEncrypted) {
            Write-Status "BitLocker not enabled on ${driveLetter}:" -Type "Warning"
            if (-not $DryRun) {
                $prompt = if ($Context.ContainsKey('Unattended') -and $Context['Unattended']) { 'N' } else {
                    Read-Host "  Enable BitLocker on ${driveLetter}: now? (Y/N)"
                }
                if ($prompt -eq 'Y' -or $prompt -eq 'y') {
                    Write-Status "  Please enable BitLocker via Control Panel and re-run encryption" -Type "Info"
                }
            }
        } else {
            Write-Status "BitLocker active: $($bitStatus.EncryptionPercentage)% encrypted" -Type "Success"
        }
    }

    if ($EnableEFS) {
        Write-Status "Enabling EFS encryption..." -Type "Info"
        $efsResult = Enable-EFSEncryption -Path $DestinationPath -BackupCertPath $BackupCertPath -DryRun $DryRun
        $result.EFSStatus = $efsResult

        if ($BackupCertPath -and $efsResult.Success -and -not $DryRun) {
            $backupResult = Backup-EFSCertificate -OutputPath $BackupCertPath -DryRun $DryRun
            $result.CertificateBackup = $backupResult
        }
    }

    return $result
}

function PreMigration_CheckBitLocker {
    param($Context)

    if (-not $Context.RequireBitLocker) {
        return $true
    }

    $driveLetter = $null
    try { $driveLetter = (Split-Path $Context.DestinationPath -Qualifier).TrimEnd(':') } catch {}
    if (-not $driveLetter) { Write-Log "BitLocker check: could not determine drive letter" -Level "WARN"; return $true }

    $bitStatus = $null
    try { $bitStatus = Test-BitLockerStatus -DriveLetter $driveLetter } catch {
        Write-ErrorGuard -Operation "BitLockerCheck" -ErrorType $_.Exception.Message `
            -Severity "Warning" `
            -SkipReason "BitLocker status check failed — proceeding without encryption verification" `
            -Recovery @{ Hint = "Run Test-BitLockerStatus -DriveLetter $driveLetter manually" }
        return $true
    }

    if (-not $bitStatus.IsEncrypted) {
        Write-ErrorGuard -Operation "BitLockerCheck" `
            -ErrorType "${driveLetter}: is NOT BitLocker encrypted" `
            -Severity "Error" `
            -SkipReason "Migration blocked — -RequireBitLocker is set" `
            -Recovery @{ Command = "Enable-BitLocker -MountPoint ${driveLetter}: -EncryptionMethod XtsAes256"; Hint = "Or remove -RequireBitLocker flag to allow unencrypted destinations" }
        return $false
    }
    return $true
}

function PostFolder_EncryptFiles {
    param($Context)

    if (-not $Context.EnableEncryption) {
        return $true
    }

    try {
        $efsResult = Enable-EFSEncryption -Path $Context.DestPath -DryRun $Context.DryRun
        $Context.EncryptionResult = $efsResult
        return $efsResult.Success
    } catch {
        Write-ErrorGuard -Operation "EFSEncryption" -ErrorType $_.Exception.Message `
            -Severity "Warning" `
            -SkipReason "EFS encryption failed — files are copied but not encrypted" `
            -Diagnostics @{ "Path" = $Context.DestPath } `
            -Recovery @{ Command = "cipher /E /S:`"$($Context.DestPath)`""; Hint = "Ensure EFS is supported on the destination filesystem (NTFS only)" }
        return $true   # non-fatal — data is safe, just not encrypted
    }
}

function PostFolder_Encryption_DeclareInputs {
    return @(
        @{
            Key               = 'EnableEncryption'
            Prompt            = 'Enable EFS encryption on migrated folders?'
            Type              = 'YesNo'
            Default           = 'N'
            UnattendedDefault = 'N'
            Required          = $false
        },
        @{
            Key               = 'RequireBitLocker'
            Prompt            = 'Require BitLocker on destination drive before migrating?'
            Type              = 'YesNo'
            Default           = 'N'
            UnattendedDefault = 'N'
            Required          = $false
        }
    )
}

Export-ModuleMember -Function 'PreMigration_CheckBitLocker', 'PostFolder_EncryptFiles', 'PostFolder_Encryption_DeclareInputs'