
<#
.SYNOPSIS
    UF.Migration.PreFlight — advanced pre-migration validation.
    SMART disk health, path conflict detection, network stability, antivirus verification.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── SMART Disk Health ───────────────────────────────────────────────────

function Test-DiskHealth {
    param([Parameter(Mandatory)][string]$Path)

    $result = [PSCustomObject]@{
        DriveLetter = ''
        Model = ''
        HealthPercent = 100
        PredictFailure = $false
        Warnings = [System.Collections.Generic.List[string]]::new()
        RawAttributes = @{}
    }

    try {
        $driveLetter = (Split-Path $Path -Qualifier).TrimEnd(':').ToUpper()
        $result.DriveLetter = $driveLetter

        $partition = Get-CimInstance -ClassName Win32_LogicalDiskToPartition -ErrorAction SilentlyContinue |
            Where-Object { $_.Dependent.DeviceID -like "*${driveLetter}:*" } |
            Select-Object -First 1

        if (-not $partition) {
            $result.Warnings.Add("Could not map ${driveLetter}: to physical disk — may be network or RAM drive")
            return $result
        }

        $diskDrive = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue |
            Where-Object { $partition.Antecedent.DeviceID -match [regex]::Escape($_.DeviceID) } |
            Select-Object -First 1

        if (-not $diskDrive) {
            $result.Warnings.Add("Physical disk not found for ${driveLetter}:")
            return $result
        }

        $result.Model = $diskDrive.Model

        $smart = Get-CimInstance -Namespace "root\WMI" -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue |
            Where-Object { $_.InstanceName -match [regex]::Escape($diskDrive.PNPDeviceID) }

        if ($smart) {
            $result.PredictFailure = $smart.PredictFailure
            if ($result.PredictFailure) {
                $result.Warnings.Add("PREDICTED FAILURE — disk should be replaced immediately")
                $result.HealthPercent = 0
            }
        }

        $attrs = Get-CimInstance -Namespace "root\WMI" -ClassName MSStorageDriver_ATAPISmartData -ErrorAction SilentlyContinue |
            Where-Object { $_.InstanceName -match [regex]::Escape($diskDrive.PNPDeviceID) }

        if ($attrs -and $attrs.VendorSpecific) {
            $rawData = $attrs.VendorSpecific
            # L11: Hardcoded offsets (5*12+5, 197*12+5) assumed a fixed layout that varies by vendor.
            # Parse the attribute table properly: starts at byte 2, each entry is 12 bytes.
            # Layout per entry: [AttrId(1)][Flags(2)][Current(1)][Worst(1)][Raw(6)][Reserved(1)]
            $attrTable = @{}
            for ($i = 2; ($i + 12) -le $rawData.Count; $i += 12) {
                $attrId = $rawData[$i]
                if ($attrId -gt 0) {
                    # Raw value: 6 bytes little-endian starting at offset +5
                    $raw = [long]$rawData[$i+5] `
                        -bor ([long]$rawData[$i+6] -shl 8) `
                        -bor ([long]$rawData[$i+7] -shl 16) `
                        -bor ([long]$rawData[$i+8] -shl 24)
                    $attrTable[$attrId] = [Math]::Max(0, $raw)
                }
            }
            # ID 5=ReallocatedSectors, 197=CurrentPendingSector
            $reallocSectors = if ($attrTable.ContainsKey(5))   { $attrTable[5] }   else { 0 }
            $pendingSectors = if ($attrTable.ContainsKey(197)) { $attrTable[197] } else { 0 }
            if ($reallocSectors -gt 0) {
                $result.Warnings.Add("$reallocSectors reallocated sectors — disk degrading")
                $result.HealthPercent = [Math]::Max(0, 100 - ($reallocSectors / 10))
            }
            if ($pendingSectors -gt 0) {
                $result.Warnings.Add("$pendingSectors pending sectors — data at risk")
                $result.HealthPercent = [Math]::Max(0, $result.HealthPercent - ($pendingSectors / 2))
            }
        }

        Write-Log "Disk health check: $($result.DriveLetter): $($result.HealthPercent)% ($($result.Warnings.Count) warnings)"
    } catch {
        $result.Warnings.Add("SMART check failed: $($_.Exception.Message)")
        Write-Log "Test-DiskHealth error: $_"
    }

    return $result
}

#endregion

#region ── Path Conflict Detection ────────────────────────────────────────────

function Test-PathConflicts {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [int]$MaxDepth = 50
    )

    $result = [PSCustomObject]@{
        SourcePath = $SourcePath
        Safe = $true
        Conflicts = [System.Collections.Generic.List[PSCustomObject]]::new()
        JunctionCount = 0
        MaxDepthReached = $false
    }

    if (-not (Test-Path $SourcePath)) {
        $result.Conflicts.Add([PSCustomObject]@{ Type = 'Missing'; Path = $SourcePath; Message = 'Source path does not exist' })
        $result.Safe = $false
        return $result
    }

    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[object]]::new()
    $queue.Enqueue([PSCustomObject]@{ Path = $SourcePath; Depth = 0 })

    $reparsePoint = [System.IO.FileAttributes]::ReparsePoint

    while ($queue.Count -gt 0 -and $result.Conflicts.Count -lt 100) {
        $item = $queue.Dequeue()
        $current = $item.Path
        $depth = $item.Depth

        if (-not $visited.Add($current)) {
            $result.Conflicts.Add([PSCustomObject]@{
                Type = 'Circular'
                Path = $current
                Message = "Circular reference detected at depth $depth"
            })
            $result.Safe = $false
            continue
        }

        if ($depth -ge $MaxDepth) {
            $result.MaxDepthReached = $true
            $result.Conflicts.Add([PSCustomObject]@{
                Type = 'MaxDepth'
                Path = $current
                Message = "Max depth ($MaxDepth) reached — possible deep nesting"
            })
            continue
        }

        try {
            foreach ($dir in [System.IO.Directory]::EnumerateDirectories($current, '*', [System.IO.EnumerationOptions]::new())) {
                $attrs = ([System.IO.DirectoryInfo]::new($dir)).Attributes
                if (($attrs -band $reparsePoint) -ne 0) {
                    $result.JunctionCount++

                    $target = try {
                        $linkTarget = [System.IO.Directory]::ResolveLinkTarget($dir, $true)
                        if ($linkTarget) { $linkTarget.FullName } else { $null }
                    } catch { $null }

                    if ($target) {
                        if ($target.StartsWith($SourcePath, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $result.Conflicts.Add([PSCustomObject]@{
                                Type = 'SelfReferentialJunction'
                                Path = $dir
                                Target = $target
                                Message = "Junction points inside source tree — may cause infinite loop"
                            })
                            $result.Safe = $false
                        }
                        $queue.Enqueue([PSCustomObject]@{ Path = $target; Depth = $depth + 1 })
                    } else {
                        $result.Conflicts.Add([PSCustomObject]@{
                            Type = 'BrokenJunction'
                            Path = $dir
                            Target = '(unresolvable)'
                            Message = "Junction points to missing or inaccessible target"
                        })
                    }
                } else {
                    $queue.Enqueue([PSCustomObject]@{ Path = $dir; Depth = $depth + 1 })
                }
            }
        } catch {
            $result.Conflicts.Add([PSCustomObject]@{
                Type = 'AccessDenied'
                Path = $current
                Message = "Cannot enumerate: $($_.Exception.Message)"
            })
        }
    }

    Write-Log "Path conflict check: $($result.JunctionCount) junctions, $($result.Conflicts.Count) conflicts"
    return $result
}

#endregion

#region ── Network Latency Test ────────────────────────────────────────────────

function Test-NetworkLatency {
    param(
        [Parameter(Mandatory)][string]$UncPath,
        [int]$PacketCount = 10,
        [int]$TimeoutMs = 5000
    )

    $result = [PSCustomObject]@{
        Target = $UncPath
        Reachable = $false
        AvgLatencyMs = 0.0
        MinLatencyMs = 0.0
        MaxLatencyMs = 0.0
        PacketLoss = 0.0
        JitterMs = 0.0
        Stability = 'Unknown'
        Recommendations = [System.Collections.Generic.List[string]]::new()
    }

    # L14: '^\\\\[^\\]+' matches '\\server' but TrimStart('\\') trims individual chars not the prefix
    # For \\server\share we need just 'server' — use a capture group instead
    if ($UncPath -match '^\\\\([^\\]+)') {
        $hostname = $Matches[1]   # L14: capture group 1 = server name only, no backslashes
        $result.Target = $hostname

        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $latencies = [System.Collections.Generic.List[long]]::new()
            $losses = 0

            for ($i = 0; $i -lt $PacketCount; $i++) {
                $reply = $ping.Send($hostname, $TimeoutMs)
                if ($reply.Status -eq 'Success') {
                    $latencies.Add($reply.RoundtripTime)
                } else {
                    $losses++
                }
                Start-Sleep -Milliseconds 100
            }

            if ($latencies.Count -gt 0) {
                $result.Reachable = $true
                $result.AvgLatencyMs = [Math]::Round(($latencies | Measure-Object -Average).Average, 1)
                $result.MinLatencyMs = ($latencies | Measure-Object -Minimum).Minimum
                $result.MaxLatencyMs = ($latencies | Measure-Object -Maximum).Maximum
                $result.PacketLoss = [Math]::Round(($losses / $PacketCount) * 100, 1)

                if ($latencies.Count -gt 1) {
                    $diffs = [System.Collections.Generic.List[long]]::new()
                    for ($i = 1; $i -lt $latencies.Count; $i++) {
                        $diffs.Add([Math]::Abs($latencies[$i] - $latencies[$i-1]))
                    }
                    $result.JitterMs = [Math]::Round(($diffs | Measure-Object -Average).Average, 1)
                }

                if ($result.PacketLoss -gt 10) {
                    $result.Stability = 'Poor'
                    $result.Recommendations.Add("High packet loss ($($result.PacketLoss)%) — unstable connection")
                } elseif ($result.PacketLoss -gt 2) {
                    $result.Stability = 'Fair'
                    $result.Recommendations.Add("Packet loss $($result.PacketLoss)% — may cause retries")
                } elseif ($result.JitterMs -gt 50) {
                    $result.Stability = 'Fair'
                    $result.Recommendations.Add("High jitter ($($result.JitterMs)ms) — inconsistent latency")
                } elseif ($result.AvgLatencyMs -gt 200) {
                    $result.Stability = 'Fair'
                    $result.Recommendations.Add("High latency ($($result.AvgLatencyMs)ms) — slow transfers")
                } else {
                    $result.Stability = 'Good'
                }

                if ($result.AvgLatencyMs -gt 100) {
                    $result.Recommendations.Add("Consider using -UseRobocopyZ and -BandwidthLimitMbps for reliability")
                }
            } else {
                $result.PacketLoss = 100
                $result.Stability = 'Unreachable'
                $result.Recommendations.Add("Cannot ping $hostname — check network connectivity")
            }

            Write-Log "Network test to ${hostname}: $($result.AvgLatencyMs)ms avg, $($result.PacketLoss)% loss"
        } catch {
            $result.Recommendations.Add("Ping test failed: $($_.Exception.Message)")
            Write-Log "Network latency test error: $_"
        }
    } else {
        $result.Recommendations.Add("Not a UNC path — local drive, no network test needed")
        $result.Stability = 'NotApplicable'
    }

    return $result
}

#endregion

#region ── Antivirus Exclusion Verification ────────────────────────────────────

function Test-AntivirusExclusions {
    param([string[]]$Paths = @())

    $result = [PSCustomObject]@{
        HasDefender = $false
        HasThirdParty = $false
        ExclusionsConfigured = [System.Collections.Generic.List[string]]::new()
        MissingExclusions = [System.Collections.Generic.List[string]]::new()
        Recommendations = [System.Collections.Generic.List[string]]::new()
    }

    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            $result.HasDefender = $true
            $exclusions = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExclusionPath
            if ($exclusions) {
                foreach ($path in $Paths) {
                    $excluded = $false
                    foreach ($excl in $exclusions) {
                        if ($path -like "$excl*") {
                            $excluded = $true
                            break
                        }
                    }
                    if ($excluded) {
                        $result.ExclusionsConfigured.Add($path)
                    } else {
                        $result.MissingExclusions.Add($path)
                    }
                }
            } else {
                foreach ($path in $Paths) {
                    $result.MissingExclusions.Add($path)
                }
            }

            if ($result.MissingExclusions.Count -gt 0) {
                $result.Recommendations.Add("Add exclusions: Add-MpPreference -ExclusionPath '$($result.MissingExclusions[0])'")
            }
        }
    } catch {
        Write-Log "Defender check failed: $_"
    }

    $thirdPartyServices = @(
        'Sophos', 'McAfee', 'Symantec', 'CrowdStrike', 'SentinelOne',
        'CarbonBlack', 'TrendMicro', 'Kaspersky', 'Bitdefender', 'ESET'
    )
    foreach ($service in $thirdPartyServices) {
        $svc = Get-Service -Name "*$service*" -ErrorAction SilentlyContinue
        if ($svc) {
            $result.HasThirdParty = $true
            $result.Recommendations.Add("Third-party AV ($service) detected — verify exclusions manually")
            break
        }
    }

    Write-Log "AV exclusion check: Defender=$($result.HasDefender), Missing=$($result.MissingExclusions.Count)"
    return $result
}

#endregion

#region ── Combined Pre-Flight Report ──────────────────────────────────────────

function Invoke-PreFlightReport {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath,
        [string]$NetworkUncPath = '',
        [switch]$SkipDiskHealth,
        [switch]$SkipConflictCheck,
        [switch]$SkipNetworkTest,
        [switch]$SkipAVCheck
    )

    Write-SectionHeader "PRE-FLIGHT VALIDATION REPORT"
    Write-Status "Source: $SourcePath" -Type "Info"
    Write-Status "Destination: $DestinationPath" -Type "Info"
    if ($NetworkUncPath) { Write-Status "Network target: $NetworkUncPath" -Type "Info" }
    Write-Host ""

    $allChecks = [System.Collections.Generic.List[PSCustomObject]]::new()
    $overallPass = $true
    $warnings = 0

    if (-not $SkipDiskHealth) {
        Write-Status "Checking disk health..." -Type "Info"
        $sourceHealth = Test-DiskHealth -Path $SourcePath
        $destHealth = Test-DiskHealth -Path $DestinationPath

        $allChecks.Add([PSCustomObject]@{
            Check = 'Source Disk Health'
            Passed = (-not $sourceHealth.PredictFailure) -and ($sourceHealth.HealthPercent -gt 50)
            Detail = if ($sourceHealth.PredictFailure) { "FAILURE IMMINENT" }
                     elseif ($sourceHealth.HealthPercent -lt 80) { "Degrading ($($sourceHealth.HealthPercent)%)" }
                     else { "Healthy ($($sourceHealth.HealthPercent)%)" }
            Warnings = $sourceHealth.Warnings -join '; '
        })

        $allChecks.Add([PSCustomObject]@{
            Check = 'Destination Disk Health'
            Passed = (-not $destHealth.PredictFailure) -and ($destHealth.HealthPercent -gt 50)
            Detail = if ($destHealth.PredictFailure) { "FAILURE IMMINENT" }
                     elseif ($destHealth.HealthPercent -lt 80) { "Degrading ($($destHealth.HealthPercent)%)" }
                     else { "Healthy ($($destHealth.HealthPercent)%)" }
            Warnings = $destHealth.Warnings -join '; '
        })

        if ($sourceHealth.PredictFailure -or $destHealth.PredictFailure) { $overallPass = $false }
        if ($sourceHealth.Warnings.Count -gt 0) { $warnings++ }
        if ($destHealth.Warnings.Count -gt 0) { $warnings++ }
    }

    if (-not $SkipConflictCheck) {
        Write-Status "Checking for path conflicts..." -Type "Info"
        $conflicts = Test-PathConflicts -SourcePath $SourcePath
        $allChecks.Add([PSCustomObject]@{
            Check = 'Path Conflicts'
            Passed = $conflicts.Safe
            Detail = "$($conflicts.JunctionCount) junctions, $($conflicts.Conflicts.Count) conflicts"
            Warnings = if ($conflicts.Conflicts.Count -gt 0) { ($conflicts.Conflicts | ForEach-Object { $_.Message }) -join '; ' } else { '' }
        })
        if (-not $conflicts.Safe) { $overallPass = $false }
        if ($conflicts.Conflicts.Count -gt 0) { $warnings++ }
    }

    if (-not $SkipNetworkTest -and $NetworkUncPath) {
        Write-Status "Testing network latency..." -Type "Info"
        $latency = Test-NetworkLatency -UncPath $NetworkUncPath
        $allChecks.Add([PSCustomObject]@{
            Check = 'Network Stability'
            Passed = $latency.Stability -in @('Good', 'NotApplicable')
            Detail = if ($latency.Stability -eq 'NotApplicable') { 'Local path' }
                     else { "$($latency.AvgLatencyMs)ms avg, $($latency.PacketLoss)% loss" }
            Warnings = $latency.Recommendations -join '; '
        })
        if ($latency.Stability -eq 'Poor') { $overallPass = $false }
        if ($latency.Recommendations.Count -gt 0) { $warnings++ }
    }

    if (-not $SkipAVCheck) {
        Write-Status "Checking antivirus exclusions..." -Type "Info"
        $av = Test-AntivirusExclusions -Paths @($SourcePath, $DestinationPath)
        $allChecks.Add([PSCustomObject]@{
            Check = 'Antivirus Exclusions'
            Passed = $av.MissingExclusions.Count -eq 0
            Detail = if ($av.HasDefender) { "$($av.ExclusionsConfigured.Count)/$($av.ExclusionsConfigured.Count + $av.MissingExclusions.Count) excluded" }
                     else { 'Defender not detected' }
            Warnings = $av.Recommendations -join '; '
        })
        if ($av.MissingExclusions.Count -gt 0) { $warnings++ }
    }

    Write-Host ""
    Write-Host ("  {0,-35} {1,-10} {2}" -f "Check", "Status", "Details") -ForegroundColor Cyan
    Write-TableSeparator -Width 90

    foreach ($check in $allChecks) {
        $statusText = if ($check.Passed) { "PASS" } else { "FAIL" }
        $statusColor = if ($check.Passed) { "Green" } else { "Red" }
        Write-Host ("  {0,-35} " -f $check.Check) -NoNewline
        Write-Host ("{0,-10} " -f $statusText) -ForegroundColor $statusColor -NoNewline
        Write-Host $check.Detail -ForegroundColor Gray
        if ($check.Warnings) {
            Write-Host ("  {0,-35} {1,-10} {2}" -f "", "", $check.Warnings) -ForegroundColor Yellow
        }
    }

    Write-TableSeparator -Width 90
    Write-Host ""

    if ($overallPass -and $warnings -eq 0) {
        Write-Status "PRE-FLIGHT: ALL CHECKS PASSED — safe to proceed" -Type "Success"
    } elseif ($overallPass) {
        Write-Status "PRE-FLIGHT: PASSED WITH WARNINGS ($warnings warning(s)) — proceed with caution" -Type "Warning"
    } else {
        Write-Status "PRE-FLIGHT: FAILED — address issues before migration" -Type "Error"
    }

    Write-Log "Pre-flight completed: Passed=$overallPass, Warnings=$warnings"

    return [PSCustomObject]@{
        Passed = $overallPass
        WarningCount = $warnings
        Checks = $allChecks
        Timestamp = Get-Date
    }
}

#endregion

#region ── Hook System Wrapper ─────────────────────────────────────────────────

function PreFlight_RunFullReport {
    param($Context)

    if ([string]::IsNullOrEmpty($Context.Destination)) {
        Write-Log "PreFlight: no destination provided — skipping destination checks"
        return $true
    }

    $result = $null
    try {
        $result = Invoke-PreFlightReport -SourcePath $Context.SourcePath -DestinationPath $Context.Destination
    } catch {
        Write-ErrorGuard -Operation "PreFlightReport" -ErrorType $_.Exception.Message `
            -Severity "Warning" `
            -SkipReason "Pre-flight check threw exception — skipping pre-flight, proceeding with caution" `
            -Recovery @{ Hint = "Add -SkipDiskHealth -SkipNetworkTest to bypass failing checks" }
        return $true   # non-fatal — let migration attempt proceed
    }

    if (-not $result.Passed) {
        # Identify which checks failed for actionable output
        $failed = @($result.Checks | Where-Object { -not $_.Passed })
        Write-ErrorGuard -Operation "PreFlightReport" `
            -ErrorType "$($failed.Count) check(s) failed" `
            -Severity "Error" `
            -SkipReason "Migration blocked — pre-flight failure prevents data loss risk" `
            -Diagnostics ($failed | ForEach-Object -Begin { $d = @{} } -Process { $d[$_.Check] = $_.Detail } -End { $d }) `
            -Recovery @{ Command = "Re-run with -SkipDiskHealth/-SkipConflictCheck to bypass specific checks"; Hint = "Or address the listed issues and re-run pre-flight" }
        return $false
    }

    if ($result.WarningCount -gt 0) {
        if (-not $Context.Unattended -and -not $Context.DryRun) {
            $continue = Confirm-Operation -Message "Pre-flight warnings detected ($($result.WarningCount)). Continue anyway?"
            if (-not $continue) {
                Write-Status "Migration cancelled by user at pre-flight warnings." -Type "Error"
                return $false
            }
        } else {
            Write-Status "Pre-flight: $($result.WarningCount) warning(s) — proceeding unattended." -Type "Warning"
        }
    }

    return $true
}

#endregion

# ── Export all public functions ───────────────────────────────────────────────
Export-ModuleMember -Function 'PreFlight_RunFullReport'