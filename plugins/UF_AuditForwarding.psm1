
<#
.SYNOPSIS
    UF.Migration.AuditForwarding — forwards HMAC-signed audit logs to SIEM platforms.
    Supports Splunk HEC, Azure Sentinel, Elasticsearch, and Syslog.
    Hook points: PostSession

.STYLE GUIDE
    Functions: PascalCase
    Parameters: PascalCase
    Local Variables: camelCase

.NOTES
    Depends on: UF.Logging, UF.Security, UF.UI
    Hook naming: PostSession_ForwardAuditLogs
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Module Manifest ──────────────────────────────────────────────────────────

#region ── Splunk HEC ──────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Forwards audit logs to Splunk HTTP Event Collector (HEC).
.PARAMETER AuditLogPath Path to the HMAC-signed audit log file.
.PARAMETER SplunkUrl HEC endpoint URL (e.g., https://splunk:8088/services/collector).
.PARAMETER SplunkToken HEC authentication token.
.PARAMETER Index Splunk index name (optional).
.PARAMETER SourceType Source type name (default: 'ufm:audit').
.PARAMETER DryRun If true, only simulates.
.OUTPUTS [bool] $true on success.
#>
function Send-ToSplunk {
    param(
        [Parameter(Mandatory)][string]$AuditLogPath,
        [Parameter(Mandatory)][string]$SplunkUrl,
        [Parameter(Mandatory)][string]$SplunkToken,
        [string]$Index = '',
        [string]$SourceType = 'ufm:audit',
        [bool]$DryRun = $false
    )
    
    if (-not (Test-Path $AuditLogPath)) {
        Write-Status "Audit log not found: $AuditLogPath" -Type "Error"
        return $false
    }
    
    Write-Status "Forwarding audit log to Splunk..." -Type "Info"
    
    if ($DryRun) {
        Write-Status "  [DRY RUN] Would send $(Get-Item $AuditLogPath).Length bytes to Splunk HEC" -Type "Info"
        return $true
    }
    
    try {
        $auditContent = Get-Content $AuditLogPath -Raw -Encoding UTF8
        
        $payload = @{
            sourcetype = $SourceType
            event = $auditContent
            host = $env:COMPUTERNAME
        }
        
        if ($Index) { $payload['index'] = $Index }
        
        $jsonPayload = $payload | ConvertTo-Json -Depth 3
        $headers = @{
            'Authorization' = "Splunk $SplunkToken"
            'Content-Type' = 'application/json'
        }
        
        $response = Invoke-RestMethod -Uri $SplunkUrl -Method Post -Body $jsonPayload -Headers $headers -ErrorAction Stop
        
        if ($response.code -eq 0) {
            Write-Status "  Splunk forward successful (code 0)" -Type "Success"
            Write-Log "AuditForwarding: Splunk OK"
            return $true
        } else {
            Write-Status "  Splunk returned code $($response.code): $($response.text)" -Type "Error"
            return $false
        }
    } catch {
        Write-Status "  Splunk forward failed: $($_.Exception.Message)" -Type "Error"
        Write-Log "AuditForwarding: Splunk error - $_"
        return $false
    }
}

#endregion

#region ── Azure Sentinel ──────────────────────────────────────────────────────

<#
.SYNOPSIS
    Forwards audit logs to Azure Sentinel Log Analytics workspace.
.PARAMETER AuditLogPath Path to audit log file.
.PARAMETER WorkspaceId Log Analytics workspace ID.
.PARAMETER WorkspaceKey Primary or secondary workspace key.
.PARAMETER LogType Custom log type name (default: 'UserFolderMigrator_Audit').
.PARAMETER DryRun If true, only simulates.
.OUTPUTS [bool] $true on success.
#>
function Send-ToAzureSentinel {
    param(
        [Parameter(Mandatory)][string]$AuditLogPath,
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][string]$WorkspaceKey,
        [string]$LogType = 'UserFolderMigrator_Audit',
        [bool]$DryRun = $false
    )
    
    if (-not (Test-Path $AuditLogPath)) {
        Write-Status "Audit log not found: $AuditLogPath" -Type "Error"
        return $false
    }
    
    Write-Status "Forwarding audit log to Azure Sentinel..." -Type "Info"
    
    if ($DryRun) {
        Write-Status "  [DRY RUN] Would send $(Get-Item $AuditLogPath).Length bytes to Log Analytics" -Type "Info"
        return $true
    }
    
    try {
        $auditContent = Get-Content $AuditLogPath -Raw -Encoding UTF8
        $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        
        # Format for Log Analytics Data Collector API
        $logEntry = @{
            Host = $env:COMPUTERNAME
            User = $env:USERNAME
            Timestamp = $timestamp
            AuditData = $auditContent
        }
        
        $jsonBody = @($logEntry) | ConvertTo-Json -Depth 5
        
        # Build signature for Azure Data Collector API
        $rfc1123date = (Get-Date).ToUniversalTime().ToString('r')
        $stringToHash = "POST`n$($jsonBody.Length)`napplication/json`nx-ms-date:$rfc1123date`n/api/logs"
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [System.Convert]::FromBase64String($WorkspaceKey)
        $signature = [System.Convert]::ToBase64String($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stringToHash)))
        
        $url = "https://$WorkspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        $headers = @{
            'Authorization' = "SharedKey $WorkspaceId`:$signature"
            'Content-Type' = 'application/json'
            'Log-Type' = $LogType
            'x-ms-date' = $rfc1123date
        }
        
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $jsonBody -Headers $headers -ErrorAction Stop
        Write-Status "  Azure Sentinel forward successful" -Type "Success"
        Write-Log "AuditForwarding: Azure Sentinel OK"
        return $true
        
    } catch {
        Write-Status "  Azure Sentinel forward failed: $($_.Exception.Message)" -Type "Error"
        Write-Log "AuditForwarding: Azure Sentinel error - $_"
        return $false
    }
}

#endregion

#region ── Elasticsearch ───────────────────────────────────────────────────────

<#
.SYNOPSIS
    Forwards audit logs to Elasticsearch.
.PARAMETER AuditLogPath Path to audit log file.
.PARAMETER ElasticUrl Elasticsearch endpoint (e.g., http://localhost:9200).
.PARAMETER IndexName Index name (default: 'ufm-audit').
.PARAMETER Username Basic auth username (optional).
.PARAMETER Password Basic auth password (optional).
.PARAMETER ApiKey API key for authentication (optional).
.PARAMETER DryRun If true, only simulates.
.OUTPUTS [bool] $true on success.
#>
function Send-ToElasticsearch {
    param(
        [Parameter(Mandatory)][string]$AuditLogPath,
        [Parameter(Mandatory)][string]$ElasticUrl,
        [string]$IndexName = 'ufm-audit',
        [string]$Username = '',
        [string]$Password = '',
        [string]$ApiKey = '',
        [bool]$DryRun = $false
    )
    
    if (-not (Test-Path $AuditLogPath)) {
        Write-Status "Audit log not found: $AuditLogPath" -Type "Error"
        return $false
    }
    
    Write-Status "Forwarding audit log to Elasticsearch..." -Type "Info"
    
    if ($DryRun) {
        Write-Status "  [DRY RUN] Would send to Elasticsearch index: $IndexName" -Type "Info"
        return $true
    }
    
    try {
        $auditContent = Get-Content $AuditLogPath -Raw -Encoding UTF8
        $lines = $auditContent -split "`n"
        
        # Build bulk request (one document per audit line)
        $bulkBody = [System.Text.StringBuilder]::new()
        $docId = 1
        
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            
            $action = @{ index = @{ _index = $IndexName; _id = "$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMddHHmmss')-$docId" } } | ConvertTo-Json -Compress
            $source = @{
                timestamp = (Get-Date).ToUniversalTime().ToString('o')
                host = $env:COMPUTERNAME
                user = $env:USERNAME
                audit_line = $line
            } | ConvertTo-Json -Compress
            
            [void]$bulkBody.AppendLine($action)
            [void]$bulkBody.AppendLine($source)
            $docId++
        }
        
        $url = "$ElasticUrl/_bulk"
        $headers = @{ 'Content-Type' = 'application/json' }
        
        if ($ApiKey) {
            $headers['Authorization'] = "ApiKey $ApiKey"
        } elseif ($Username -and $Password) {
            $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$Username`:$Password"))
            $headers['Authorization'] = "Basic $encoded"
        }
        
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $bulkBody.ToString() -Headers $headers -ErrorAction Stop
        
        if ($response.errors -eq $false) {
            Write-Status "  Elasticsearch forward successful ($($docId-1) documents)" -Type "Success"
            Write-Log "AuditForwarding: Elasticsearch OK - $($docId-1) docs"
            return $true
        } else {
            Write-Status "  Elasticsearch returned errors" -Type "Warning"
            return $false
        }
    } catch {
        Write-Status "  Elasticsearch forward failed: $($_.Exception.Message)" -Type "Error"
        Write-Log "AuditForwarding: Elasticsearch error - $_"
        return $false
    }
}

#endregion

#region ── Syslog (RFC 3164/5424) ──────────────────────────────────────────────

<#
.SYNOPSIS
    Forwards audit logs to a syslog server (RFC 3164 compliant).
.PARAMETER AuditLogPath Path to audit log file.
.PARAMETER SyslogServer Syslog server hostname or IP.
.PARAMETER SyslogPort UDP port (default: 514).
.PARAMETER Facility Syslog facility (default: 1 = user-level).
.PARAMETER Severity Base severity (default: 5 = notice).
.PARAMETER DryRun If true, only simulates.
.OUTPUTS [bool] $true on success.
#>
function Send-ToSyslogServer {
    param(
        [Parameter(Mandatory)][string]$AuditLogPath,
        [Parameter(Mandatory)][string]$SyslogServer,
        [int]$SyslogPort = 514,
        [int]$Facility = 1,
        [int]$Severity = 5,
        [bool]$DryRun = $false
    )
    
    if (-not (Test-Path $AuditLogPath)) {
        Write-Status "Audit log not found: $AuditLogPath" -Type "Error"
        return $false
    }
    
    Write-Status "Forwarding audit log to syslog server: $SyslogServer`:$SyslogPort" -Type "Info"
    
    if ($DryRun) {
        Write-Status "  [DRY RUN] Would send $(Get-Item $AuditLogPath).Length bytes via UDP syslog" -Type "Info"
        return $true
    }
    
    try {
        $priority = ($Facility * 8) + $Severity
        $hostname = $env:COMPUTERNAME
        $timestamp = Get-Date -Format 'MMM dd HH:mm:ss'
        
        $auditContent = Get-Content $AuditLogPath -Encoding UTF8
        $udpClient = [System.Net.Sockets.UdpClient]::new()
        
        try {
            foreach ($line in $auditContent) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                
                $syslogMessage = "<$priority>$timestamp $hostname UserFolderMigrator: $line"
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($syslogMessage)
                [void]$udpClient.Send($bytes, $bytes.Length, $SyslogServer, $SyslogPort)
                Start-Sleep -Milliseconds 10  # Rate limiting
            }
        } finally {
            $udpClient.Dispose()
        }
        
        Write-Status "  Syslog forward successful ($($auditContent.Count) messages)" -Type "Success"
        Write-Log "AuditForwarding: Syslog OK - $($auditContent.Count) messages"
        return $true
        
    } catch {
        Write-Status "  Syslog forward failed: $($_.Exception.Message)" -Type "Error"
        Write-Log "AuditForwarding: Syslog error - $_"
        return $false
    }
}

#endregion

#region ── Unified Dispatcher ──────────────────────────────────────────────────

<#
.SYNOPSIS
    Unified audit forwarding dispatcher — routes to configured destinations.
.PARAMETER AuditLogPath Path to audit log file.
.PARAMETER SplunkConfig Hashtable with Splunk settings (Url, Token, Index, SourceType).
.PARAMETER SentinelConfig Hashtable with Azure Sentinel settings (WorkspaceId, WorkspaceKey, LogType).
.PARAMETER ElasticConfig Hashtable with Elasticsearch settings (Url, IndexName, Username, Password, ApiKey).
.PARAMETER SyslogConfig Hashtable with Syslog settings (Server, Port, Facility, Severity).
.PARAMETER DryRun If true, only simulates.
.OUTPUTS [PSCustomObject] with forwarding results.
#>
function Invoke-AuditForwarding {
    param(
        [Parameter(Mandatory)][string]$AuditLogPath,
        [hashtable]$SplunkConfig = @{},
        [hashtable]$SentinelConfig = @{},
        [hashtable]$ElasticConfig = @{},
        [hashtable]$SyslogConfig = @{},
        [bool]$DryRun = $false
    )
    
    $results = [PSCustomObject]@{
        Splunk = $null
        Sentinel = $null
        Elasticsearch = $null
        Syslog = $null
        Timestamp = Get-Date
    }
    
    Write-SectionHeader "Audit Log Forwarding"
    Write-Status "Audit log: $AuditLogPath" -Type "Info"
    
    # Forward to Splunk
    if ($SplunkConfig.Url -and $SplunkConfig.Token) {
        $results.Splunk = Send-ToSplunk -AuditLogPath $AuditLogPath `
            -SplunkUrl $SplunkConfig.Url `
            -SplunkToken $SplunkConfig.Token `
            -Index ($SplunkConfig.Index -or '') `
            -SourceType ($SplunkConfig.SourceType -or 'ufm:audit') `
            -DryRun $DryRun
    }
    
    # Forward to Azure Sentinel
    if ($SentinelConfig.WorkspaceId -and $SentinelConfig.WorkspaceKey) {
        $results.Sentinel = Send-ToAzureSentinel -AuditLogPath $AuditLogPath `
            -WorkspaceId $SentinelConfig.WorkspaceId `
            -WorkspaceKey $SentinelConfig.WorkspaceKey `
            -LogType ($SentinelConfig.LogType -or 'UserFolderMigrator_Audit') `
            -DryRun $DryRun
    }
    
    # Forward to Elasticsearch
    if ($ElasticConfig.Url) {
        $results.Elasticsearch = Send-ToElasticsearch -AuditLogPath $AuditLogPath `
            -ElasticUrl $ElasticConfig.Url `
            -IndexName ($ElasticConfig.IndexName -or 'ufm-audit') `
            -Username ($ElasticConfig.Username -or '') `
            -Password ($ElasticConfig.Password -or '') `
            -ApiKey ($ElasticConfig.ApiKey -or '') `
            -DryRun $DryRun
    }
    
    # Forward to Syslog
    if ($SyslogConfig.Server) {
        $results.Syslog = Send-ToSyslogServer -AuditLogPath $AuditLogPath `
            -SyslogServer $SyslogConfig.Server `
            -SyslogPort ($SyslogConfig.Port -or 514) `
            -Facility ($SyslogConfig.Facility -or 1) `
            -Severity ($SyslogConfig.Severity -or 5) `
            -DryRun $DryRun
    }
    
    $successCount = @(
        $results.Splunk,
        $results.Sentinel,
        $results.Elasticsearch,
        $results.Syslog
    ) | Where-Object { $_ -eq $true } | Measure-Object | Select-Object -ExpandProperty Count
    
    Write-Status "Audit forwarding: $successCount destination(s) successful" -Type $(if ($successCount -gt 0) { 'Success' } else { 'Warning' })
    Write-Log "AuditForwarding: $successCount destinations successful"
    
    return $results
}

#endregion

#region ── Hook System Wrappers ────────────────────────────────────────────────

<#
.SYNOPSIS
    Hook that forwards audit logs after session completes.
    Called automatically at PostSession hook point.
#>
function PostSession_ForwardAuditLogs {
    param($Context)

    $enableSIEM = $script:PluginInputs['EnableSIEM']
    if (-not $enableSIEM) {
        Write-Log "Audit forwarding: disabled via user input"
        return $true
    }

    # Collect SIEM details now (gated — only reached if user said Y)
    AuditForwarding_CollectSIEMDetails

    $auditLogPath = $global:GlobalAuditLogPath
    if (-not $auditLogPath -or -not (Test-Path $auditLogPath)) {
        Write-Log "Audit forwarding: log not found or unavailable — skipping silently" -Level "WARN"
        return $true
    }

    $splunkUrl   = $script:PluginInputs['SplunkUrl']
    $splunkToken = $script:PluginInputs['SplunkToken']
    $sentinelId  = $script:PluginInputs['SentinelWorkspaceId']
    $sentinelKey = $script:PluginInputs['SentinelSharedKey']

    $splunkConfig   = if ($splunkUrl)  { @{ Url = $splunkUrl; Token = $splunkToken } } else { @{} }
    $sentinelConfig = if ($sentinelId) { @{ WorkspaceId = $sentinelId; WorkspaceKey = $sentinelKey } } else { @{} }

    try {
        $results = Invoke-AuditForwarding -AuditLogPath $auditLogPath `
            -SplunkConfig   $splunkConfig `
            -SentinelConfig $sentinelConfig `
            -ElasticConfig  @{} `
            -SyslogConfig   @{} `
            -DryRun ($Context.DryRun ?? $false)
    } catch {
        Write-ErrorGuard -Operation "AuditForwarding" -ErrorType $_.Exception.Message `
            -Severity "Warning" `
            -SkipReason "Audit forwarding failed — migration result unaffected" `
            -Recovery @{ Hint = "Verify SIEM endpoint connectivity and credentials" }
    }
    return $true
}

<#
.SYNOPSIS
    Declares and collects required SIEM parameters interactively at script startup.
    Uses a Yes/No gate first before prompting for sensitive API configurations.
#>
function AuditForwarding_DeclareInputs {
    return @(
        @{
            Key               = 'EnableSIEM'
            Prompt            = 'Enable centralized SIEM log forwarding? (Y/N)'
            Type              = 'YesNo'
            Default           = 'N'
            UnattendedDefault = 'N'
        }
    )
}

function AuditForwarding_CollectSIEMDetails {
    # Called by PostSession_ForwardAuditLogs only if EnableSIEM=true
    # Collects Splunk/Sentinel details interactively at that point
    $splunkUrl = Read-Host "  [?] SplunkUrl - Splunk HEC URL (leave blank to skip)"
    if ($splunkUrl) {
        $splunkToken = Read-Host "  [>] SplunkToken (secure)" -AsSecureString
        $script:PluginInputs['SplunkUrl']   = $splunkUrl
        $script:PluginInputs['SplunkToken'] = $splunkToken
    }
    $sentinelId = Read-Host "  [?] SentinelWorkspaceId - Azure Sentinel Workspace ID (leave blank to skip)"
    if ($sentinelId) {
        $sentinelKey = Read-Host "  [>] SentinelSharedKey (secure)" -AsSecureString
        $script:PluginInputs['SentinelWorkspaceId'] = $sentinelId
        $script:PluginInputs['SentinelSharedKey']   = $sentinelKey
    }
}

# CRITICAL: Export the new input collection function along with the existing forwarding hook
Export-ModuleMember -Function 'PostSession_ForwardAuditLogs', 'AuditForwarding_DeclareInputs', 'AuditForwarding_CollectSIEMDetails'