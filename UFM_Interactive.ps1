#Requires -Version 7.0
#Requires -RunAsAdministrator

# ── Help System Plugin (optional — gracefully degrades if not present) ─────────
$script:HelpPlugin = $null
$_helpPluginPath = Join-Path $PSScriptRoot 'plugins\UFM_HelpSystem.ps1'
if (Test-Path $_helpPluginPath) {
    try {
        . $_helpPluginPath
        $script:HelpPlugin = $true
        Write-Host "  [+] Help System loaded — type '?' at any prompt for context help" -ForegroundColor DarkGreen
    } catch {
        Write-Host "  [!] Help System plugin failed to load: $_" -ForegroundColor DarkGray
    }
}
if (-not (Get-Command Read-HostWithHelp -ErrorAction SilentlyContinue)) {
    function Read-HostWithHelp {
        param([string]$Prompt, [string]$Topic='', [switch]$AsSecureString, [switch]$AllowEmpty)
        if ($AsSecureString) { return (Read-Host $Prompt -AsSecureString) }
        return (Read-Host $Prompt)
    }
}

# ============================================================
# USER FOLDER MIGRATOR - INTERACTIVE SETUP WITH AUTO-CLEANUP
# ============================================================

$script:ScriptVersion = "7.5.0"
$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:MainScriptPath = Join-Path $script:ScriptDir "UserFolderMigrator.ps1"
$script:ConfigFilePath = Join-Path $script:ScriptDir "UFM_Interactive_Config.json"

# Track if we stored credentials
$script:CredentialsStored = $false
$script:CredentialTargets = @("UFM_Smtp", "OneDriveMgmt_Smtp")

# ============================================================
# AUTO-CLEANUP FUNCTION
# ============================================================

function Clear-StoredCredentials {
    param(
        [string[]]$Targets = $script:CredentialTargets,
        [switch]$Quiet
    )
    
    if (-not $Quiet) {
        Write-Host ""
        Write-Status "Cleaning up stored credentials..." -Type "Info"
    }
    
    $deleted = 0
    foreach ($target in $Targets) {
        try {
            $result = cmdkey /delete:$target 2>&1
            if ($LASTEXITCODE -eq 0) {
                if (-not $Quiet) { Write-Status "  Deleted credential: $target" -Type "Success" }
                $deleted++
            }
        } catch {
            if (-not $Quiet) { Write-Status "  Could not delete: $target" -Type "Warning" }
        }
    }
    
    # Clear in-memory credential variables
    $script:CachedSmtpCred = $null
    $script:CachedOAuthToken = $null
    $script:OAuthTokenExpiry = [DateTime]::MinValue
    
    # Force garbage collection
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    
    if (-not $Quiet -and $deleted -gt 0) {
        Write-Status "Cleared $deleted credential(s) from Credential Manager and memory" -Type "Success"
    }
    
    $script:CredentialsStored = $false
}

# Register cleanup on script exit
Register-EngineEvent -SupportEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($script:CredentialsStored) {
        Clear-StoredCredentials -Quiet
    }
} | Out-Null

# ============================================================
# FUNCTIONS
# ============================================================

function Write-SectionHeader {
    param([string]$Title)
    $w = try { [Math]::Max(60, [Console]::WindowWidth - 4) } catch { 78 }
    $bar = '=' * $w
    Write-Host ''
    Write-Host "  $bar" -ForegroundColor DarkCyan
    Write-Host "  $Title"  -ForegroundColor Cyan
    Write-Host "  $bar" -ForegroundColor DarkCyan
    Write-Host ''
}

function Show-AppPasswordInstructions {
    param([string]$Domain)
    $d = $Domain.ToLower()
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host "  USE AN APP PASSWORD — NOT YOUR ACCOUNT PASSWORD" -ForegroundColor Yellow
    Write-Host "  Your email provider requires an App Password for SMTP access." -ForegroundColor Yellow
    Write-Host "  Using your real password will fail if 2FA/MFA is enabled." -ForegroundColor Yellow
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host ""

    switch -Wildcard ($d) {
        "gmail.com" {
            Write-Host "  Gmail App Password instructions:" -ForegroundColor Cyan
            Write-Host "    1. Go to: https://myaccount.google.com/apppasswords" -ForegroundColor White
            Write-Host "    2. Sign in and verify your identity" -ForegroundColor White
            Write-Host "    3. Select App: 'Mail'  |  Device: 'Windows Computer'" -ForegroundColor White
            Write-Host "    4. Click 'Generate' — copy the 16-character password" -ForegroundColor White
            Write-Host "    NOTE: Google Workspace accounts may need admin to enable App Passwords" -ForegroundColor Gray
        }
        "googlemail.com" {
            Write-Host "  Gmail (googlemail) App Password — same as gmail.com:" -ForegroundColor Cyan
            Write-Host "    https://myaccount.google.com/apppasswords" -ForegroundColor White
        }
        { $_ -in @("outlook.com","hotmail.com","live.com","microsoft.com") } {
            Write-Host "  Microsoft / Outlook App Password instructions:" -ForegroundColor Cyan
            Write-Host "    1. Go to: https://account.microsoft.com/security" -ForegroundColor White
            Write-Host "    2. Click 'Advanced security options'" -ForegroundColor White
            Write-Host "    3. Under 'App passwords' click 'Create a new app password'" -ForegroundColor White
            Write-Host "    4. Copy the generated password" -ForegroundColor White
            Write-Host "    NOTE: Microsoft 365 Business — use OAuth2 mode instead (no App Passwords)" -ForegroundColor Gray
        }
        "yahoo.com" {
            Write-Host "  Yahoo Mail App Password instructions:" -ForegroundColor Cyan
            Write-Host "    1. Go to: https://login.yahoo.com/myaccount/security" -ForegroundColor White
            Write-Host "    2. Click 'Generate app password'" -ForegroundColor White
            Write-Host "    3. Select 'Other App', name it (e.g. UFM), click 'Generate'" -ForegroundColor White
            Write-Host "    4. Copy the 16-character password shown" -ForegroundColor White
        }
        { $_ -in @("icloud.com","me.com","mac.com") } {
            Write-Host "  Apple iCloud App Password instructions:" -ForegroundColor Cyan
            Write-Host "    1. Go to: https://appleid.apple.com" -ForegroundColor White
            Write-Host "    2. Sign in → 'Sign-In and Security' → 'App-Specific Passwords'" -ForegroundColor White
            Write-Host "    3. Click '+' → name it (e.g. UFM) → click 'Create'" -ForegroundColor White
            Write-Host "    4. Copy the password in format: xxxx-xxxx-xxxx-xxxx" -ForegroundColor White
        }
        { $_ -in @("protonmail.com","proton.me") } {
            Write-Host "  ProtonMail — requires ProtonMail Bridge (desktop app):" -ForegroundColor Cyan
            Write-Host "    1. Download Bridge: https://proton.me/mail/bridge" -ForegroundColor White
            Write-Host "    2. Sign in to Bridge on this machine" -ForegroundColor White
            Write-Host "    3. In Bridge: go to your account → copy the Bridge password" -ForegroundColor White
            Write-Host "    4. Enter that Bridge password here (NOT your Proton login password)" -ForegroundColor White
            Write-Host "    SMTP: 127.0.0.1:1025  |  Bridge must be running when script executes" -ForegroundColor Gray
        }
        { $_ -in @("zoho.com","zohomail.com") } {
            Write-Host "  Zoho Mail App Password instructions:" -ForegroundColor Cyan
            Write-Host "    1. Go to: https://accounts.zoho.com/home#security" -ForegroundColor White
            Write-Host "    2. Click 'App Passwords' → 'Generate New Password'" -ForegroundColor White
            Write-Host "    3. Name it (e.g. UFM) and copy the generated password" -ForegroundColor White
        }
        { $_ -in @("fastmail.com","fastmail.fm") } {
            Write-Host "  Fastmail App Password instructions:" -ForegroundColor Cyan
            Write-Host "    1. Go to: https://www.fastmail.com/settings/security/devicekeys" -ForegroundColor White
            Write-Host "    2. Click 'New App Password'" -ForegroundColor White
            Write-Host "    3. Set access to 'Mail (IMAP/SMTP)' → name it → Save" -ForegroundColor White
            Write-Host "    4. Copy the generated password" -ForegroundColor White
        }
        { $_ -in @("yandex.com","yandex.ru") } {
            Write-Host "  Yandex Mail App Password instructions:" -ForegroundColor Cyan
            Write-Host "    1. Go to: https://id.yandex.com/security/app-passwords" -ForegroundColor White
            Write-Host "    2. Click 'Create app password'" -ForegroundColor White
            Write-Host "    3. Select 'Mail' → name it → Confirm with your Yandex password" -ForegroundColor White
            Write-Host "    4. Copy the 16-character app password" -ForegroundColor White
        }
        "sendgrid.net" {
            Write-Host "  SendGrid API Key instructions:" -ForegroundColor Cyan
            Write-Host "    1. Go to: https://app.sendgrid.com/settings/api_keys" -ForegroundColor White
            Write-Host "    2. Click 'Create API Key' → choose 'Restricted Access'" -ForegroundColor White
            Write-Host "    3. Enable 'Mail Send' permission → Create & View" -ForegroundColor White
            Write-Host "    4. Use 'apikey' as username and the API key as password" -ForegroundColor White
        }
        default {
            Write-Host "  App Password instructions:" -ForegroundColor Cyan
            Write-Host "    Check your email provider's security settings for 'App Passwords'" -ForegroundColor White
            Write-Host "    or 'Application-Specific Passwords' — never use your main password." -ForegroundColor White
        }
    }
    Write-Host ""
}



function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $symbol = switch ($Type) {
        "Success" { "[+]" }
        "Error"   { "[X]" }
        "Warning" { "[!]" }
        "Info"    { "[.]" }
        default   { "[.]" }
    }
    $color = switch ($Type) {
        "Success" { "Green" }
        "Error"   { "Red" }
        "Warning" { "Yellow" }
        default   { "Gray" }
    }
    Write-Host "  $symbol $Message" -ForegroundColor $color
}

function Test-AdminRight {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-UserProfiles {
    $profilesDir = Join-Path $env:SystemDrive "Users"
    $excludedUsers = @('Public', 'Default', 'Default User', 'Administrator', 'Guest', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SYSTEM')
    
    $users = @()
    try {
        $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
            Where-Object { $_.Special -eq $false -and $_.LocalPath -like "$profilesDir\*" }
        
        foreach ($profile in $profiles) {
            $username = Split-Path $profile.LocalPath -Leaf
            if ($username -notin $excludedUsers) {
                $users += [PSCustomObject]@{
                    Username = $username
                    ProfilePath = $profile.LocalPath
                    SID = $profile.SID
                    IsActive = $profile.Loaded
                    LastUseTime = $profile.LastUseTime
                }
            }
        }
    } catch {
        Write-Status "Failed to enumerate user profiles: $_" -Type "Warning"
    }
    return $users
}

function Save-Config {
    param([hashtable]$Settings)
    try {
        $Settings | ConvertTo-Json -Depth 10 | Set-Content -Path $script:ConfigFilePath -Encoding UTF8
        Write-Status "Settings saved to: $script:ConfigFilePath" -Type "Success"
    } catch {
        Write-Status "Failed to save config: $_" -Type "Warning"
    }
}

function Save-WizardStage {
    param([int]$Stage, [hashtable]$State)
    try {
        $checkpoint = @{ WizardStage = $Stage; State = $State; SavedAt = (Get-Date).ToString("o") }
        $checkpoint | ConvertTo-Json -Depth 10 | Set-Content -Path ($script:ConfigFilePath -replace '\.json$','_checkpoint.json') -Encoding UTF8
    } catch { }
}

function Load-WizardCheckpoint {
    $cpPath = $script:ConfigFilePath -replace '\.json$','_checkpoint.json'
    if (Test-Path $cpPath) {
        try {
            $cp = Get-Content $cpPath -Raw | ConvertFrom-Json
            if ($cp.WizardStage -and $cp.WizardStage -gt 1) {
                Write-Host ""
                Write-Status "Incomplete wizard found (saved at stage $($cp.WizardStage) — $(([datetime]$cp.SavedAt).ToString('g')))" -Type "Warning"
                $resume = Read-Host "  Resume from stage $($cp.WizardStage)? (Y/N)"
                if ($resume -eq 'Y' -or $resume -eq 'y') { return $cp }
            }
        } catch { }
    }
    return $null
}

function Clear-WizardCheckpoint {
    $cpPath = $script:ConfigFilePath -replace '\.json$','_checkpoint.json'
    Remove-Item $cpPath -Force -ErrorAction SilentlyContinue
}

function Load-Config {
    if (Test-Path $script:ConfigFilePath) {
        try {
            $config = Get-Content $script:ConfigFilePath -Raw | ConvertFrom-Json
            Write-Status "Loaded saved settings from: $script:ConfigFilePath" -Type "Info"
            return $config
        } catch {
            Write-Status "Failed to load config: $_" -Type "Warning"
        }
    }
    return $null
}


function Test-PathWriteable {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        $testFile = Join-Path $Path ".ufm_test_$(Get-Random).tmp"
        [System.IO.File]::WriteAllText($testFile, "test")
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

function Get-DiskFreeSpaceGB {
    param([string]$Path)
    try {
        $qualifier = (Split-Path $Path -Qualifier).TrimEnd(':')
        $driveInfo = Get-PSDrive -Name $qualifier -ErrorAction SilentlyContinue
        if ($driveInfo) { return [math]::Round($driveInfo.Free / 1GB, 2) }
    } catch { }
    return 0
}

function Store-CredentialInManager {
    param(
        [string]$Username,
        [string]$Password,
        [string]$Target = "UFM_Smtp"
    )
    
    try {
        cmdkey /generic:$Target /user:$Username /pass:$Password 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $script:CredentialsStored = $true
            return $true
        }
    } catch { }
    return $false
}

# ============================================================
# FUNCTION: START MAIN SCRIPT IN NEW WINDOW
# ============================================================

function Start-MainScriptInNewWindow {
    param(
        [string]$ScriptPath,
        [string[]]$Arguments,
        [switch]$WaitForExit,
        [int]$TimeoutSeconds = 0
    )
    
    # Build the command string
    $command = "& `"$ScriptPath`" $($Arguments -join ' ')"
    
    # Create a temporary script file for the new window
    $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
    $tempScript = $tempScript -replace '\.tmp\.ps1$', '.ps1'
    
    # Write the command to the temp script
    @"
# Auto-generated by UFM Interactive Wrapper
# Original script: $ScriptPath
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

`$exitCode = 0
try {
    $command
    `$exitCode = `$LASTEXITCODE
} catch {
    Write-Host "ERROR: `$(`$_.Exception.Message)" -ForegroundColor Red
    `$exitCode = 99
} finally {
    Write-Host ""
    Write-Host "Script completed with exit code: `$exitCode" -ForegroundColor Cyan
    Write-Host "Press Enter to close this window..."
    Read-Host
    exit `$exitCode
}
"@ | Out-File -FilePath $tempScript -Encoding UTF8
    
    # PowerShell window parameters
    $pwshPath = if ($PSVersionTable.PSVersion.Major -ge 6) { "pwsh.exe" } else { "powershell.exe" }
    
    # Window style
    $windowStyle = "Normal"  # Normal, Maximized, Minimized, Hidden
    
    # Start the new window
    if ($WaitForExit) {
        $process = Start-Process $pwshPath `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`"" `
            -WindowStyle $windowStyle `
            -PassThru `
            -Wait
        $exitCode = $process.ExitCode
    } else {
        Start-Process $pwshPath `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`"" `
            -WindowStyle $windowStyle
        $exitCode = 0
    }
    
    # Clean up temp file after delay (or immediately if waited)
    if ($WaitForExit) {
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    } else {
        # Schedule cleanup after 5 seconds
        Start-Sleep -Seconds 5
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    }
    
    return $exitCode
}

function Start-MainScriptInSameWindow {
    param(
        [string]$ScriptPath,
        [string[]]$Arguments
    )
    
    $command = "& `"$ScriptPath`" $($Arguments -join ' ')"
    Invoke-Expression $command
    return $LASTEXITCODE
}

function Show-FolderSelectionMenu {
    param([string[]]$AllFolders, [string[]]$CurrentSelection)
    
    Write-Host ""
    Write-Host "  Available folders to migrate:" -ForegroundColor Cyan
    Write-Host ""
    
    $folderDescriptions = @{
        "Desktop" = "Desktop files and shortcuts"
        "Documents" = "My Documents folder"
        "Downloads" = "Downloads folder"
        "Music" = "Music library"
        "Pictures" = "Pictures library"
        "Videos" = "Videos library"
        "Favorites" = "Browser favorites"
        "Contacts" = "Contacts list"
        "Links" = "Links folder"
        "SavedGames" = "Game saves"
        "Searches" = "Saved searches"
    }
    
    for ($i = 0; $i -lt $AllFolders.Count; $i++) {
        $folder = $AllFolders[$i]
        $selected = if ($CurrentSelection -contains $folder -or $CurrentSelection -contains "All") { "[X]" } else { "[ ]" }
        $desc = if ($folderDescriptions[$folder]) { " - $($folderDescriptions[$folder])" } else { "" }
        Write-Host "    $($i+1). $selected $folder$desc" -ForegroundColor Gray
    }
    Write-Host "    0. Select ALL folders" -ForegroundColor Cyan
    Write-Host "    A. Apply and continue" -ForegroundColor Green
    Write-Host "    C. Cancel"
    Write-Host ""
    
    while ($true) {
        $choice = Read-Host "  Enter folder number to toggle, 0 for ALL, A to apply, C to cancel"
        
        if ($choice -eq "A" -or $choice -eq "a") {
            return $CurrentSelection
        }
        elseif ($choice -eq "C" -or $choice -eq "c") {
            return $null
        }
        elseif ($choice -eq "0") {
            if ($CurrentSelection -contains "All") {
                $CurrentSelection = @()
                Write-Status "All folders deselected" -Type "Info"
            } else {
                $CurrentSelection = @("All")
                Write-Status "All folders selected" -Type "Success"
            }
            for ($i = 0; $i -lt $AllFolders.Count; $i++) {
                $folder = $AllFolders[$i]
                $selected = if ($CurrentSelection -contains "All") { "[X]" } elseif ($CurrentSelection -contains $folder) { "[X]" } else { "[ ]" }
                Write-Host "    $($i+1). $selected $folder" -ForegroundColor Gray
            }
        }
        elseif ($choice -match '^\d+$') {
            $idx = [int]$choice - 1
            if ($idx -ge 0 -and $idx -lt $AllFolders.Count) {
                $folder = $AllFolders[$idx]
                if ($CurrentSelection -contains "All") {
                    $CurrentSelection = @($AllFolders | Where-Object { $_ -ne $folder })
                    Write-Status "Removed $folder from selection" -Type "Info"
                } elseif ($CurrentSelection -contains $folder) {
                    $CurrentSelection = $CurrentSelection | Where-Object { $_ -ne $folder }
                    Write-Status "Removed $folder from selection" -Type "Info"
                } else {
                    $CurrentSelection += $folder
                    Write-Status "Added $folder to selection" -Type "Success"
                }
                for ($i = 0; $i -lt $AllFolders.Count; $i++) {
                    $f = $AllFolders[$i]
                    $selected = if ($CurrentSelection -contains "All") { "[X]" } elseif ($CurrentSelection -contains $f) { "[X]" } else { "[ ]" }
                    Write-Host "    $($i+1). $selected $f" -ForegroundColor Gray
                }
            } else {
                Write-Status "Invalid selection" -Type "Warning"
            }
        }
    }
}

# ============================================================
# MAIN INTERACTIVE SCRIPT
# ============================================================

# Clear screen and show banner
Clear-Host
$script:BannerWidth = try { [Math]::Max(60, [Console]::WindowWidth - 4) } catch { 78 }
$_bar  = '=' * $script:BannerWidth
$_line1 = "  USER FOLDER MIGRATOR  *  Interactive Setup  *  v$script:ScriptVersion"
$_line2 = "  Profiles  *  Wizard Resume  *  SMTP Auto-Detect  *  Credential Vault"
Write-Host ''
Write-Host "  +$_bar+" -ForegroundColor Cyan
Write-Host ("  |" + $_line1.PadRight($script:BannerWidth) + "|") -ForegroundColor Cyan
Write-Host ("  |" + $_line2.PadRight($script:BannerWidth) + "|") -ForegroundColor Cyan
Write-Host "  +$_bar+" -ForegroundColor Cyan
Write-Host ''

# Check admin rights
if (-not (Test-AdminRight)) {
    Write-Status "Administrator rights required! Please run PowerShell as Administrator." -Type "Error"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Status "Running as Administrator" -Type "Success"

# Check if main script exists
if (-not (Test-Path $script:MainScriptPath)) {
    Write-Status "Main script not found: $script:MainScriptPath" -Type "Error"
    Write-Status "Make sure UserFolderMigrator.ps1 is in the same directory as this script." -Type "Error"
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Status "Main script found: UserFolderMigrator.ps1" -Type "Success"

# Load saved configuration
$savedConfig = Load-Config
$script:WizardResume = Load-WizardCheckpoint
$script:WizardState  = @{}

# ============================================================
# PROFILE SELECTION MENU
# ============================================================
Write-SectionHeader "WHAT WOULD YOU LIKE TO DO?"

Write-Host ""
Write-Host "  Choose a profile below. Profiles run with safe defaults and only ask" -ForegroundColor Gray
Write-Host "  the questions that matter for that task. Custom lets you configure" -ForegroundColor Gray
Write-Host "  every option — including advanced and power-user settings." -ForegroundColor Gray
Write-Host ""
    Write-SectionHeader "EVERYDAY TASKS"
Write-Host "   [+] 1. Move My Files          Move Desktop/Docs/etc to a new drive" -ForegroundColor Green
Write-Host "   [+] 2. Preview (No Changes)   See exactly what would move — nothing is touched" -ForegroundColor White
Write-Host "   [+] 3. Backup My Profile      Full snapshot of files, settings, Wi-Fi and more" -ForegroundColor White
Write-Host "   [+] 4. Restore from Backup    Bring back a profile from a previous snapshot" -ForegroundColor White
Write-Host ""
Write-SectionHeader "IT / ENTERPRISE"
Write-Host "   [+] 5. Migrate All Users      Move files for all profiles with VSS and 4 parallel threads" -ForegroundColor White
Write-Host "   [+] 6. Overnight Backup       Back up all profiles throttled and scheduled as a task" -ForegroundColor White
Write-Host "   [+] 7. Audit Scan             Dry-run scan of all users with full verification" -ForegroundColor White
Write-Host ""
Write-SectionHeader "ADVANCED"
Write-Host "   [+] 8. Custom                 Configure every option individually (multi-stage wizard)" -ForegroundColor Cyan
Write-Host "   [+] 9. Compatibility Check    Test whether your destination drive is ready before migrating" -ForegroundColor DarkGray
Write-Host ""

$profileChoice = Read-Host "  Enter choice (1-9)"
if (-not $profileChoice -or $profileChoice -notmatch '^[1-9]$') { $profileChoice = '8' }

# ── Preset variable defaults ──────────────────────────────────────────────────
$Mode                    = 'Migrate'
$TargetUsername          = $env:USERNAME
$AllUsers                = $false
$Destination             = $null
$Folders                 = @('All')
$DryRun                  = $false
$Force                   = $false
$KeepSource              = $false
$UseVSS                  = $false
$DisableSmartVSS         = $false
$MaxParallel             = 1
$RobocopyThreads         = 0
$RobocopyRetries         = 3
$RobocopyWait            = 5
$UseRobocopyZ            = $false
$BandwidthLimitMbps      = 0
$MaxFailures             = 0
$SkipSupplementalExports = $false
$DisableChecksumVerify   = $false
$ChecksumAlgorithm       = 'SHA256'
$VerifyDestination       = $false
$BitLockerRequired       = $false
$NotificationEmail       = $null
$SmtpServer              = $null
$SmtpAuthMode            = 'Basic'
$SmtpFrom                = $null
$AutoCleanupCreds        = $true
$RollbackFile            = $null
$RegisterTask            = $false
$TaskName                = 'UserFolderMigrator'
$TaskTrigger             = 'Weekly'
$TaskTime                = '22:00'
$TaskDay                 = 'Sunday'
$TaskRunAs               = 'SYSTEM'
$userChoice              = '1'
$modeChoice              = '1'
$script:CredentialsStored = $false
$script:WanOptimized     = $false
$script:MaxRepairSizeGB  = -1
$script:IncrementalBackup = $false
$EnableCheckpoint        = $false
$script:OAuthTenantId    = $null
$script:OAuthClientId    = $null
$script:OAuthClientSecret = $null
$script:RestoreDestinationProfile = $null

# Power-user defaults
$Exclude                 = @()
$ExcludeFile             = $null
$DisableAutoExclusions   = $false
$SkipTestRestore         = $false
$TestRestoreSamplePct    = 10
$SkipLockedFileCheck     = $false
$SkipAutoPermissionFix   = $false
$SkipJunctionScan        = $false
$SecureWipeSource        = $false
$ValidateOnly            = $false
$PilotUser               = $null
$NetworkTimeout          = 30
$QuarantinePath          = $null
$QuarantineRetentionDays = 0
$WslInstallRoot          = 'C:\WSL'
$SkipGPOBlock            = $false
$ForceOneDrive           = $false
$SkipAccessCheck         = $false
$SkipBackupManifest      = $false
$OfflineMode             = $false
$ResetState              = $false
$DisableRestorePoint     = $false
$AutoEnableSystemProtection = $false
$DisableHtmlReport       = $false
$DisableAutoPerfTuning   = $false
$NoEventLog              = $false
$QuietMode               = $false
$LogPath                 = $null
$ReportPath              = $null
$NotificationTeamsWebhook = $null
$SmtpMaxRetries          = 3
$SmtpRetryDelayBase      = 5
$SecretVaultName         = $null
$script:SecretName       = $null
$SyslogServer            = $null
$EnableSyslog            = $false
$RollbackFullProfile     = $false
$RunSFCCheck             = $false
$DisableResume           = $false
$CheckpointFile          = $null
$CreateSyncTask          = $false

$usePreset = $profileChoice -notin @('8','9')

# ============================================================
# SHARED HELPER: COLLECT DESTINATION
# ============================================================
function Get-DestinationPath {
    param([string]$Default = 'Y:\UserData', [string]$Label = "Where should the files go?")
    Write-Host ""
    Write-Host "  $Label" -ForegroundColor Cyan
    Write-Host "  Examples: D:\UserData  or  \\server\share\Backups" -ForegroundColor Gray
    Write-Host ""
    $dest = Read-Host "  Path [$Default]"
    if (-not $dest) { $dest = $Default }
    $free = Get-DiskFreeSpaceGB -Path $dest
    Write-Status "Path       : $dest" -Type "Info"
    Write-Status "Free space : $free GB" -Type "Info"
    if ($free -lt 5) {
        Write-Status "WARNING: Less than 5 GB free!" -Type "Warning"
        $p = Read-Host "  Continue anyway? (Y/N)"
        if ($p -ne 'Y' -and $p -ne 'y') { Clear-StoredCredentials; exit 0 }
    }
    if ($dest -like '\\*') {
        $useZ = Read-Host "  Network path detected — use restartable copy mode (survives disconnects)? (Y/N) [Y]"
        if ($useZ -ne 'N' -and $useZ -ne 'n') { $script:_UseRobocopyZ = $true }
    }
    return $dest
}
$script:_UseRobocopyZ = $false

# ============================================================
# SHARED HELPER: QUICK EMAIL (PRESET MODE)
# ============================================================
function Add-QuickEmail {
    Write-Host ""
    $addEmail = Read-Host "  Get an email when it finishes? (Y/N)"
    if ($addEmail -ne 'Y' -and $addEmail -ne 'y') { return }
    $script:_Email = Read-Host "  Your email address"
    if (-not $script:_Email) { return }
    if ($script:_Email -match '@(.+)$') {
        $domain = $Matches[1].ToLower()
        $knownSmtp = @{
            "gmail.com" = "smtp.gmail.com"; "googlemail.com" = "smtp.gmail.com"
            "outlook.com" = "smtp.office365.com"; "hotmail.com" = "smtp.office365.com"
            "live.com" = "smtp.office365.com"; "microsoft.com" = "smtp.office365.com"
            "yahoo.com" = "smtp.mail.yahoo.com"; "yahoo.co.uk" = "smtp.mail.yahoo.com"
            "icloud.com" = "smtp.mail.me.com"; "me.com" = "smtp.mail.me.com"
            "mac.com" = "smtp.mail.me.com"
            "protonmail.com" = "127.0.0.1"; "proton.me" = "127.0.0.1"
            "zoho.com" = "smtp.zoho.com"; "fastmail.com" = "smtp.fastmail.com"
            "sendgrid.net" = "smtp.sendgrid.net"
        }
        if ($knownSmtp.ContainsKey($domain)) {
            $script:_SmtpServer = $knownSmtp[$domain]
            Write-Status "SMTP server: $($script:_SmtpServer)" -Type "Success"
        }
        Show-AppPasswordInstructions -Domain $domain
    }
    $secPwd = Read-Host "  App Password" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPwd)
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    if (Store-CredentialInManager -Username $script:_Email -Password $plain -Target "UFM_Smtp") {
        $script:CredentialsStored = $true
        Write-Status "Notification set up — credentials auto-deleted after run" -Type "Success"
    } else {
        Write-Status "Failed to store credentials. Falling back to Basic auth (will prompt at runtime)." -Type "Warning"
    }
    $plain = $null
}
$script:_Email      = $null
$script:_SmtpServer = $null

# ============================================================
# PRESET PROFILES
# ============================================================
if ($usePreset) {
    $defaultDest = if ($savedConfig -and $savedConfig.Destination) { $savedConfig.Destination } else { 'Y:\UserData' }

    switch ($profileChoice) {

        # ── 1. Move My Files ───────────────────────────────────────────────
        '1' {
            Write-SectionHeader "MOVE MY FILES"
            Write-Host "  Copies Desktop, Documents, Downloads, Pictures, Music, Videos" -ForegroundColor Gray
            Write-Host "  and other Windows folders to a drive you choose." -ForegroundColor Gray
            Write-Host "  Windows is updated so everything still works in the new place." -ForegroundColor Gray
            Write-Host "  Your original files stay put until you delete them yourself." -ForegroundColor Gray
            Write-Host ""

            $Mode = 'Migrate'; $modeChoice = '1'
            $TargetUsername = $env:USERNAME

            $Destination = Get-DestinationPath -Default $defaultDest -Label "Where should your files move to?"
            if ($script:_UseRobocopyZ) { $UseRobocopyZ = $true }

            Write-Host ""
            Write-Host "  Which folders should move?" -ForegroundColor Cyan
            Write-Host "    1. All of them (Desktop, Documents, Downloads, Pictures, Music, Videos + more)" -ForegroundColor White
            Write-Host "    2. Let me choose" -ForegroundColor White
            Write-Host ""
            $fChoice = Read-Host "  Enter choice (1-2) [1]"
            if ($fChoice -eq '2') {
                $allFolders = @("Desktop","Documents","Downloads","Music","Pictures","Videos","Favorites","Contacts","Links","SavedGames","Searches")
                $Folders = Show-FolderSelectionMenu -AllFolders $allFolders -CurrentSelection @('All')
                if (-not $Folders) { $Folders = @('All') }
            }

            Write-Host ""
            Write-Host "  Keep a copy of the original files after moving? (Y/N)" -ForegroundColor Cyan
            Write-Host "  N = original files stay on C: until you delete them (recommended)" -ForegroundColor Gray
            Write-Host "  Y = files exist in both places (uses extra space)" -ForegroundColor Gray
            Write-Host ""
            $kc = Read-Host "  Keep originals? (Y/N) [N]"
            $KeepSource = ($kc -eq 'Y' -or $kc -eq 'y')

            $UseVSS = $true   # always safe for active users
            $EnableCheckpoint = $true
            Add-QuickEmail
        }

        # ── 2. Preview (No Changes) ────────────────────────────────────────
        '2' {
            Write-SectionHeader "PREVIEW (NO CHANGES)"
            Write-Host "  Runs a complete simulation for your account — shows exactly what" -ForegroundColor Gray
            Write-Host "  would move and where. No files are copied, moved, or deleted." -ForegroundColor Gray
            Write-Host ""

            $Mode = 'Migrate'; $modeChoice = '1'
            $DryRun = $true
            $TargetUsername = $env:USERNAME

            $Destination = Get-DestinationPath -Default $defaultDest -Label "Destination to simulate (nothing will actually be written there)"
            if ($script:_UseRobocopyZ) { $UseRobocopyZ = $true }
            Add-QuickEmail
        }

        # ── 3. Backup My Profile ───────────────────────────────────────────
        '3' {
            Write-SectionHeader "BACKUP MY PROFILE"
            Write-Host "  Creates a full snapshot of your profile: all files, Windows" -ForegroundColor Gray
            Write-Host "  settings, saved Wi-Fi networks, printers, scheduled tasks," -ForegroundColor Gray
            Write-Host "  and WSL distros (if any). Nothing is deleted or moved." -ForegroundColor Gray
            Write-Host ""

            $Mode = 'FullProfileBackup'; $modeChoice = '4'
            $TargetUsername = $env:USERNAME

            $Destination = Get-DestinationPath -Default $defaultDest -Label "Where should the backup be saved?"
            if ($script:_UseRobocopyZ) { $UseRobocopyZ = $true }

            Write-Host ""
            Write-Host "  Backup type:" -ForegroundColor Cyan
            Write-Host "    1. Full backup (copy everything every time) — recommended first run" -ForegroundColor White
            Write-Host "    2. Incremental (only new or changed files) — faster for repeat runs" -ForegroundColor White
            Write-Host ""
            $btChoice = Read-Host "  Enter choice (1-2) [1]"
            if ($btChoice -eq '2') { $script:IncrementalBackup = $true }

            Write-Host ""
            Write-Host "  OneDrive cloud-only files:" -ForegroundColor Cyan
            Write-Host "  Files stored only in the cloud won't be in the backup unless you" -ForegroundColor Gray
            Write-Host "  download them first. Do you want to download them before backup?" -ForegroundColor Gray
            Write-Host ""
            $hod = Read-Host "  Download cloud-only OneDrive files before backup? (Y/N) [N]"
            $HydrateOneDrive = ($hod -eq 'Y' -or $hod -eq 'y')

            Add-QuickEmail
        }

        # ── 4. Restore from Backup ─────────────────────────────────────────
        '4' {
            Write-SectionHeader "RESTORE FROM BACKUP"
            Write-Host "  Restores a profile from a previous Full Profile Backup snapshot." -ForegroundColor Gray
            Write-Host "  Brings back your files, Windows settings, Wi-Fi, printers," -ForegroundColor Gray
            Write-Host "  scheduled tasks, and WSL distros." -ForegroundColor Gray
            Write-Host ""

            $Mode = 'RestoreProfile'; $modeChoice = '5'
            $TargetUsername = $env:USERNAME

            # Backup root (stored as -Source in main script)
            $backupRoot = Get-DestinationPath -Default $defaultDest -Label "Where is the backup folder?"
            $Destination = $backupRoot
            if ($script:_UseRobocopyZ) { $UseRobocopyZ = $true }

            Write-Host ""
            Write-Host "  Restore to which profile?" -ForegroundColor Cyan
            Write-Host "  Leave blank to restore to C:\Users\$($env:USERNAME) (your current profile)." -ForegroundColor Gray
            Write-Host ""
            $destProf = Read-Host "  Restore destination (blank = current profile)"
            if ($destProf) { $script:RestoreDestinationProfile = $destProf }

            Write-Host ""
            Write-Host "  What to restore:" -ForegroundColor Cyan
            Write-Host "    1. Everything (files, registry, Wi-Fi, printers, tasks, WSL)" -ForegroundColor White
            Write-Host "    2. Files only (skip settings/Wi-Fi/printers)" -ForegroundColor White
            Write-Host "    3. Let me choose what to skip" -ForegroundColor White
            Write-Host ""
            $restoreChoice = Read-Host "  Enter choice (1-3) [1]"
            $SkipFileRestore = $false; $SkipRegistryRestore = $false; $SkipAclRestore = $false
            $SkipWifiRestore = $false; $SkipPrinterRestore = $false; $SkipTaskRestore = $false
            $SkipWslRestore = $false; $SkipDriveRestore = $false
            switch ($restoreChoice) {
                '2' {
                    $SkipRegistryRestore = $true; $SkipWifiRestore = $true
                    $SkipPrinterRestore = $true; $SkipTaskRestore = $true; $SkipWslRestore = $true
                    $SkipDriveRestore = $true
                    Write-Status "Will restore files only" -Type "Info"
                }
                '3' {
                    Write-Host ""
                    Write-Host "  Answer Y to SKIP that component, N to restore it:" -ForegroundColor Gray
                    $SkipRegistryRestore = ((Read-Host "  Skip registry settings? (Y/N)") -in 'Y','y')
                    $SkipAclRestore      = ((Read-Host "  Skip file permissions (ACLs)? (Y/N)") -in 'Y','y')
                    $SkipWifiRestore     = ((Read-Host "  Skip Wi-Fi profiles? (Y/N)") -in 'Y','y')
                    $SkipPrinterRestore  = ((Read-Host "  Skip printers? (Y/N)") -in 'Y','y')
                    $SkipTaskRestore     = ((Read-Host "  Skip scheduled tasks? (Y/N)") -in 'Y','y')
                    $SkipWslRestore      = ((Read-Host "  Skip WSL distros? (Y/N)") -in 'Y','y')
                    $SkipDriveRestore    = ((Read-Host "  Skip mapped drives? (Y/N)") -in 'Y','y')
                }
            }
            $restored = @()
            if (-not $SkipFileRestore)     { $restored += "Files" }
            if (-not $SkipRegistryRestore) { $restored += "Registry" }
            if (-not $SkipAclRestore)      { $restored += "ACLs" }
            if (-not $SkipWifiRestore)     { $restored += "Wi-Fi" }
            if (-not $SkipPrinterRestore)  { $restored += "Printers" }
            if (-not $SkipTaskRestore)     { $restored += "Tasks" }
            if (-not $SkipWslRestore)      { $restored += "WSL" }
            if (-not $SkipDriveRestore)    { $restored += "Drives" }
            Write-Status "Will restore: $($restored -join ', ')" -Type "Success"
            Add-QuickEmail
        }

        # ── 5. Migrate All Users ───────────────────────────────────────────
        '5' {
            Write-SectionHeader "MIGRATE ALL USERS"
            Write-Status "Profile: ENTERPRISE — all users, VSS, 4 parallel workers" -Type "Warning"

            $Mode = 'Migrate'; $modeChoice = '1'
            $AllUsers = $true; $userChoice = '3'
            $UseVSS = $true; $MaxParallel = 4
            $EnableCheckpoint = $true

            $Destination = Get-DestinationPath -Default $defaultDest -Label "Destination for all user profiles"
            if ($script:_UseRobocopyZ) { $UseRobocopyZ = $true }
            Add-QuickEmail
        }

        # ── 6. Overnight Backup ────────────────────────────────────────────
        '6' {
            Write-SectionHeader "OVERNIGHT BACKUP"
            Write-Status "Profile: OVERNIGHT BACKUP — all users, 100 Mbps throttle" -Type "Info"

            $Mode = 'FullProfileBackup'; $modeChoice = '4'
            $AllUsers = $true; $userChoice = '3'
            $BandwidthLimitMbps = 100

            $Destination = Get-DestinationPath -Default $defaultDest -Label "Where should backups be saved?"
            if ($script:_UseRobocopyZ) { $UseRobocopyZ = $true }

            Write-Host ""
            Write-Host "  Set up a scheduled task to run this automatically? (Y/N)" -ForegroundColor Cyan
            $schedChoice = Read-Host "  Schedule it? (Y/N) [N]"
            if ($schedChoice -eq 'Y' -or $schedChoice -eq 'y') {
                $RegisterTask = $true
                $timeIn = Read-Host "  Run time (HH:MM) [02:00]"
                $TaskTime = if ($timeIn -match '^\d{1,2}:\d{2}$') { $timeIn } else { '02:00' }
                $TaskTrigger = 'Daily'
                Write-Status "Scheduled task: daily at $TaskTime" -Type "Success"
            }
            Add-QuickEmail
        }

        # ── 7. Audit Scan ──────────────────────────────────────────────────
        '7' {
            Write-SectionHeader "AUDIT SCAN (DRY RUN)"
            Write-Status "Profile: AUDIT — all users, no changes, full verify" -Type "Info"

            $Mode = 'Migrate'; $modeChoice = '1'
            $AllUsers = $true; $userChoice = '3'
            $DryRun = $true

            $Destination = Get-DestinationPath -Default $defaultDest -Label "Destination to simulate (nothing will be written)"
            if ($script:_UseRobocopyZ) { $UseRobocopyZ = $true }
            Add-QuickEmail
        }
    }

    # Apply quick email results back into main variables
    if ($script:_Email) {
        $NotificationEmail = $script:_Email
        if ($script:_SmtpServer) { $SmtpServer = $script:_SmtpServer }
        $SmtpAuthMode = if ($script:CredentialsStored) { "CredentialManager" } else { "Basic" }
    }
}

# ============================================================
# COMPATIBILITY CHECK (profile = 9)
# ============================================================
if ($profileChoice -eq '9') {
    Write-SectionHeader "COMPATIBILITY CHECK"
    Write-Host "  Runs pre-flight checks on a destination path — no files are moved." -ForegroundColor Gray
    Write-Host "  Checks drive format, free space, permissions, and path length limits." -ForegroundColor Gray
    Write-Host ""
    $defaultDest = if ($savedConfig -and $savedConfig.Destination) { $savedConfig.Destination } else { 'Y:\UserData' }
    $Destination = Get-DestinationPath -Default $defaultDest -Label "Destination path to check"
    $TestCompatibility = $true
    $DryRun = $true
    if ($script:_Email) {
        $NotificationEmail = $script:_Email
        if ($script:_SmtpServer) { $SmtpServer = $script:_SmtpServer }
        $SmtpAuthMode = if ($script:CredentialsStored) { "CredentialManager" } else { "Basic" }
    }
}

# ============================================================
# CUSTOM WIZARD (profile = 8)
# ============================================================
if (-not $usePreset) {

# ============================================================
# STEP 1: OPERATION MODE
# ============================================================
Write-SectionHeader "STEP 1: WHAT DO YOU WANT TO DO?"

Write-Host ""
Write-Host "   [+] 1. Move My Files         Copy Desktop/Docs/etc to a new drive. Windows is updated to point to the new location." -ForegroundColor Green
Write-Host "   [+] 2. Move Files Back       Return shell folders to C:\Users\<you>. Undoes a previous migration." -ForegroundColor White
Write-Host "   [+] 3. Update Windows Only   Tell Windows where files already are. Files stay put — registry only." -ForegroundColor White
Write-Host "   [+] 4. Backup My Profile     Full disaster-recovery snapshot: files, registry, Wi-Fi, printers, tasks, WSL." -ForegroundColor White
Write-Host "   [+] 5. Restore from Backup   Bring back a FullProfileBackup. Use after a rebuild or disk failure." -ForegroundColor White
Write-Host "   [+] 6. Finish Interrupted    Move files skipped during a migration that stopped partway through." -ForegroundColor White
Write-Host "   [+] 7. Undo (Registry Only)  Restore registry shell paths from a backup. Does NOT move files." -ForegroundColor White
Write-Host ""

$modeMap = @{
    "1" = "Migrate"
    "2" = "RestoreDefaults"
    "3" = "RedirectAndClean"
    "4" = "FullProfileBackup"
    "5" = "RestoreProfile"
    "6" = "RepairTransactions"
    "7" = "Rollback"
}

$defaultMode = if ($savedConfig) { $savedConfig.Mode } else { "1" }
$modeChoice = Read-Host "  Enter choice (1-7) [$defaultMode]"
if (-not $modeChoice) { $modeChoice = $defaultMode }
$Mode = $modeMap[$modeChoice]
if (-not $Mode) { $Mode = "Migrate" }
Write-Status "Operation: $Mode" -Type "Success"
Save-WizardStage -Stage 2 -State @{ Mode=$modeChoice; UserChoice=$defaultUserChoice; Destination=$null; Folders=@("All") }

# ============================================================
# STEP 2: WHO?
# ============================================================
Write-SectionHeader "STEP 2: WHOSE PROFILE?"

$users = Get-UserProfiles

Write-Host ""
Write-Host "  Detected profiles on this machine:" -ForegroundColor Cyan
Write-Host "    → $($env:USERNAME)  [you — currently logged in]" -ForegroundColor Green
for ($i = 0; $i -lt $users.Count; $i++) {
    $status = if ($users[$i].IsActive) { "active" } else { "inactive" }
    $color  = if ($users[$i].IsActive) { "Green" } else { "Yellow" }
    Write-Host "    → $($users[$i].Username)  [$status]" -ForegroundColor $color
}
Write-Host ""
Write-Host "  Who should this run for?" -ForegroundColor Cyan
Write-Host "    1. Just me ($env:USERNAME)" -ForegroundColor White
Write-Host "    2. A specific user (I'll type the name)" -ForegroundColor White
Write-Host "    3. Every user on this machine" -ForegroundColor White
Write-Host ""

$defaultUserChoice = if ($savedConfig) { $savedConfig.UserChoice } else { "1" }
$userChoice = Read-Host "  Enter choice (1-3) [$defaultUserChoice]"
if (-not $userChoice) { $userChoice = $defaultUserChoice }

$AllUsers = $false
$TargetUsername = $null

switch ($userChoice) {
    "1" {
        Write-Status "Running for current user: $env:USERNAME" -Type "Success"
        $TargetUsername = $env:USERNAME
    }
    "2" {
        $TargetUsername = Read-Host "  Username"
        if (-not $TargetUsername) {
            Write-Status "No username entered — using current user" -Type "Warning"
            $TargetUsername = $env:USERNAME
        } else {
            Write-Status "Running for: $TargetUsername" -Type "Success"
        }
    }
    "3" {
        $AllUsers = $true
        Write-Status "Running for ALL $($users.Count + 1) profile(s)" -Type "Warning"
    }
    default {
        Write-Status "Using current user" -Type "Success"
        $TargetUsername = $env:USERNAME
    }
}
Save-WizardStage -Stage 3 -State @{ Mode=$modeChoice; UserChoice=$userChoice; TargetUsername=$TargetUsername; AllUsers=$AllUsers }

# ============================================================
# STEP 3: DESTINATION
# ============================================================
$Destination = $null

if ($Mode -in @("Migrate","FullProfileBackup","RedirectAndClean","RepairTransactions","RestoreProfile")) {
    Write-SectionHeader "STEP 3: WHERE?"

    $defaultDest = if ($savedConfig -and $savedConfig.Destination) { $savedConfig.Destination } else { "Y:\UserData" }
    Write-Host ""
    $destLabel = switch ($Mode) {
        "Migrate"          { "Where should your files be moved to?" }
        "FullProfileBackup"{ "Where should the backup be saved?" }
        "RestoreProfile"   { "Where is the backup folder?" }
        default            { "Path to the data folder" }
    }
    Write-Host "  $destLabel" -ForegroundColor Cyan
    Write-Host "  Examples: D:\Data   E:\Backups   \\server\share\UserData" -ForegroundColor Gray
    Write-Host ""

    $Destination = Read-Host "  Path [$defaultDest]"
    if (-not $Destination) { $Destination = $defaultDest }

    $freeSpace = Get-DiskFreeSpaceGB -Path $Destination
    Write-Status "Path       : $Destination" -Type "Info"
    Write-Status "Free space : $freeSpace GB" -Type "Info"

    if ($freeSpace -lt 5) {
        Write-Status "WARNING: Less than 5 GB free!" -Type "Warning"
        $proceed = Read-Host "  Continue? (Y/N)"
        if ($proceed -ne "Y" -and $proceed -ne "y") { Clear-StoredCredentials; exit 0 }
    }

    if (-not (Test-PathWriteable -Path $Destination)) {
        Write-Status "Cannot write to path — check permissions." -Type "Error"
        $proceed = Read-Host "  Continue anyway? (Y/N)"
        if ($proceed -ne "Y" -and $proceed -ne "y") { Clear-StoredCredentials; exit 0 }
    } else {
        Write-Status "Path is writable" -Type "Success"
    }

    if ($Destination -like '\\*') {
        $useZ = Read-Host "  Network path — use restartable copy mode (survives disconnects)? (Y/N) [Y]"
        if ($useZ -ne 'N' -and $useZ -ne 'n') { $UseRobocopyZ = $true }
    }
}

# ============================================================
# STEP 4: FOLDERS (Migrate / Redirect / Repair)
# ============================================================
$Folders = @("All")

if ($Mode -in @("Migrate","RedirectAndClean","RepairTransactions")) {
    Write-SectionHeader "STEP 4: WHICH FOLDERS?"

    $allFolders = @("Desktop","Documents","Downloads","Music","Pictures","Videos","Favorites","Contacts","Links","SavedGames","Searches")
    $defaultFolders = if ($savedConfig -and $savedConfig.Folders) { $savedConfig.Folders } else { @("All") }

    Write-Host ""
    Write-Host "  Current selection: " -NoNewline -ForegroundColor Cyan
    if ($defaultFolders -contains "All") { Write-Host "ALL FOLDERS" -ForegroundColor Green }
    else { Write-Host ($defaultFolders -join ", ") -ForegroundColor Green }
    Write-Host ""
    Write-Host "  Includes: Desktop, Documents, Downloads, Pictures, Music, Videos, and more." -ForegroundColor Gray
    Write-Host ""

    $customize = Read-Host "  Move all folders? Y = all of them, N = let me pick (Y/N) [Y]"
    if ($customize -eq "N" -or $customize -eq "n") {
        $Folders = Show-FolderSelectionMenu -AllFolders $allFolders -CurrentSelection $defaultFolders
        if (-not $Folders) { $Folders = @("All") }
    } else {
        $Folders = $defaultFolders
    }

    if ($Folders -contains "All") { Write-Status "All shell folders will be processed" -Type "Success" }
    else                          { Write-Status "Selected: $($Folders -join ', ')" -Type "Success" }
}

# ============================================================
# STEP 5: NOTIFICATIONS
# ============================================================
Write-SectionHeader "STEP 5: NOTIFICATIONS (OPTIONAL)"

Write-Host ""
Write-Host "  Get an email when the job finishes? (success or failure)" -ForegroundColor Cyan
Write-Host ""
$enableEmail = Read-Host "  Set up email notifications? (Y/N)"

$NotificationEmail = $null
$SmtpServer        = $null
$SmtpAuthMode      = "Basic"
$SmtpFrom          = $null
$AutoCleanupCreds  = $true
$script:CredentialsStored = $false

if ($enableEmail -eq "Y" -or $enableEmail -eq "y") {
    $NotificationEmail = Read-Host "  Your email address"

    if ($NotificationEmail -and $NotificationEmail -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        Write-Status "Email format looks unusual — double-check before continuing." -Type "Warning"
    }

    Write-Host ""
    Write-Host "  How does your email account handle sign-in?" -ForegroundColor Cyan
    Write-Host "    1. App password (Gmail, Yahoo, iCloud, Fastmail) — most common" -ForegroundColor White
    Write-Host "    2. Microsoft 365 via OAuth2 (work/school accounts — no password stored)" -ForegroundColor White
    Write-Host "    3. Microsoft 365 via Certificate (enterprise — needs Entra app registration)" -ForegroundColor White
    Write-Host "    4. Secret Vault (Azure Key Vault / PSSecretManagement integration)" -ForegroundColor White
    Write-Host ""

    $authChoice = Read-Host "  Enter choice (1-4) [1]"

    switch ($authChoice) {
        "1" {
            $SmtpAuthMode = "Basic"
            Write-Status "Using app password authentication" -Type "Success"
            if ($NotificationEmail -match '@(.+)$') { Show-AppPasswordInstructions -Domain $Matches[1] }
            $securePassword = Read-Host "  App Password" -AsSecureString
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            if (Store-CredentialInManager -Username $NotificationEmail -Password $plainPassword -Target "UFM_Smtp") {
                Write-Status "Password stored securely (auto-deleted after run)" -Type "Success"
                $script:CredentialsStored = $true
            } else {
                Write-Status "Failed to store password. Falling back to Basic auth (will prompt at runtime)." -Type "Warning"
                $SmtpAuthMode = "Basic"
            }
            $plainPassword = $null
        }
        "2" {
            $SmtpAuthMode = "OAuth2"
            Write-Host ""
            Write-Host "  You need an Entra ID app registration with Mail.Send permission." -ForegroundColor Gray
            Write-Host "  See: https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app" -ForegroundColor Gray
            Write-Host ""
            $script:OAuthTenantId     = Read-Host "  Azure AD Tenant ID (GUID from Entra overview)"
            $script:OAuthClientId     = Read-Host "  App Client ID (from app registration)"
            $script:OAuthClientSecret = Read-Host "  Client Secret"
            Write-Status "OAuth2 configured — no password stored locally" -Type "Success"
        }
        "3" {
            $SmtpAuthMode = "Certificate"
            Write-Host ""
            Write-Host "  Certificate auth requires an Entra app registration with a certificate." -ForegroundColor Gray
            Write-Host ""
            $script:OAuthTenantId        = Read-Host "  Azure AD Tenant ID"
            $script:OAuthClientId        = Read-Host "  App Client ID"
            $script:OAuthCertThumbprint  = Read-Host "  Certificate Thumbprint (from local cert store)"
            Write-Status "Certificate auth configured" -Type "Success"
        }
        "4" {
            $SmtpAuthMode = "SecretVault"
            Write-Host ""
            Write-Host "  Requires PSSecretManagement module and a registered vault." -ForegroundColor Gray
            Write-Host ""
            $SecretVaultName     = Read-Host "  Vault name (as registered in PSSecretManagement)"
            $script:SecretName   = Read-Host "  Secret name inside the vault"
            Write-Status "SecretVault auth configured" -Type "Success"
        }
        default {
            $SmtpAuthMode = "Basic"
            Write-Status "Using Basic auth (default)" -Type "Info"
        }
    }

    # Auto-detect SMTP server
    if ($NotificationEmail -match '@(.+)$') {
        $domain = $Matches[1].ToLower()
        $knownSmtp = @{
            "gmail.com" = "smtp.gmail.com"; "googlemail.com" = "smtp.gmail.com"
            "outlook.com" = "smtp.office365.com"; "hotmail.com" = "smtp.office365.com"
            "live.com" = "smtp.office365.com"; "microsoft.com" = "smtp.office365.com"
            "yahoo.com" = "smtp.mail.yahoo.com"; "yahoo.co.uk" = "smtp.mail.yahoo.com"
            "icloud.com" = "smtp.mail.me.com"; "me.com" = "smtp.mail.me.com"; "mac.com" = "smtp.mail.me.com"
            "protonmail.com" = "127.0.0.1"; "proton.me" = "127.0.0.1"
            "zoho.com" = "smtp.zoho.com"; "zohomail.com" = "smtp.zoho.com"
            "fastmail.com" = "smtp.fastmail.com"; "fastmail.fm" = "smtp.fastmail.com"
            "yandex.com" = "smtp.yandex.com"; "tutanota.com" = $null
            "sendgrid.net" = "smtp.sendgrid.net"
        }
        if ($knownSmtp.ContainsKey($domain)) {
            if ($null -eq $knownSmtp[$domain]) {
                Write-Status "Tutanota does not support SMTP. Use a different email." -Type "Warning"
            } elseif ($knownSmtp[$domain] -eq "127.0.0.1") {
                Write-Status "ProtonMail requires ProtonMail Bridge running locally (port 1025)" -Type "Warning"
                $SmtpServer = "127.0.0.1"
            } else {
                $SmtpServer = $knownSmtp[$domain]
                Write-Status "SMTP auto-detected: $SmtpServer" -Type "Success"
            }
        }
    }
    $manualSmtp = Read-Host "  SMTP server (leave blank to use auto-detected: $SmtpServer)"
    if ($manualSmtp) { $SmtpServer = $manualSmtp }

    # Teams webhook (optional)
    Write-Host ""
    $teamsWh = Read-Host "  Microsoft Teams incoming webhook URL (blank = skip)"
    if ($teamsWh) { $NotificationTeamsWebhook = $teamsWh }

    # From address
    Write-Host ""
    $senderChoice = Read-Host "  Send FROM a different address? (Y/N) [N]"
    if ($senderChoice -eq 'Y' -or $senderChoice -eq 'y') {
        $SmtpFrom = Read-Host "  Sender address (e.g. noreply@company.com)"
    }

    # Auto-cleanup
    Write-Host ""
    $cleanupChoice = Read-Host "  Delete stored credentials automatically when done? (Y/N) [Y]"
    $AutoCleanupCreds = ($cleanupChoice -ne "N" -and $cleanupChoice -ne "n")
    if (-not $AutoCleanupCreds) {
        Write-Status "Auto-cleanup OFF — run 'cmdkey /delete:UFM_Smtp' later to clean up" -Type "Warning"
    }
} else {
    $AutoCleanupCreds = $false
}

# ============================================================
# STEP 6: STANDARD OPTIONS
# ============================================================
Write-SectionHeader "STEP 6: OPTIONS"

Write-Host ""
Write-Host "  Quick questions about how you want this to run." -ForegroundColor Gray
Write-Host "  Press Enter to accept the recommended answer shown in [brackets]." -ForegroundColor Gray
Write-Host ""

# Always collected regardless of mode
$dryRunChoice = Read-Host "  Simulation only — preview without making any changes? (Y/N) [N]"
$DryRun = ($dryRunChoice -eq "Y" -or $dryRunChoice -eq "y")
if ($DryRun) { Write-Status "DRY RUN — nothing will be changed" -Type "Warning" }

if ($Mode -eq "Migrate") {
    Write-Host ""
    Write-Host "  Leave a copy of files at the original location after moving?" -ForegroundColor Cyan
    Write-Host "  N = files exist only at the destination (saves space, recommended)" -ForegroundColor Gray
    Write-Host "  Y = files stay on C: AND are copied to the new drive" -ForegroundColor Gray
    Write-Host ""
    $keepChoice = Read-Host "  Keep originals? (Y/N) [N]"
    $KeepSource = ($keepChoice -eq "Y" -or $keepChoice -eq "y")

    Write-Host ""
    Write-Host "  Enable resume / checkpoint?" -ForegroundColor Cyan
    Write-Host "  Saves progress so the migration can continue if Windows restarts." -ForegroundColor Gray
    Write-Host ""
    $cpChoice = Read-Host "  Enable checkpoint/resume? (Y/N) [Y]"
    $EnableCheckpoint = ($cpChoice -ne "N" -and $cpChoice -ne "n")
}

Write-Host ""
Write-Host "  Copy locked/open files (e.g. Outlook, browser cache)?" -ForegroundColor Cyan
Write-Host "  Uses Windows VSS (Volume Shadow Copy) — recommended for live machines." -ForegroundColor Gray
Write-Host ""
$vssChoice = Read-Host "  Use VSS for locked files? (Y/N) [Y]"
$UseVSS = ($vssChoice -ne "N" -and $vssChoice -ne "n")

if ($AllUsers -and $Mode -in @("Migrate","FullProfileBackup")) {
    Write-Host ""
    Write-Host "  How many users to process at the same time?" -ForegroundColor Cyan
    Write-Host "  More = faster overall, but uses more RAM and CPU. Recommended: 2-4." -ForegroundColor Gray
    Write-Host ""
    $defaultParallel = if ($savedConfig -and $savedConfig.MaxParallel) { $savedConfig.MaxParallel } else { "2" }
    $maxParallelIn = Read-Host "  Parallel users (1-8) [$defaultParallel]"
    if ($maxParallelIn -match '^\d+$') { $MaxParallel = [Math]::Min(8,[int]$maxParallelIn) }
}

if ($Mode -eq "FullProfileBackup") {
    Write-Host ""
    Write-Host "  Backup type:" -ForegroundColor Cyan
    Write-Host "    1. Full (copy everything every time) — recommended for first run" -ForegroundColor White
    Write-Host "    2. Incremental (only changed files) — faster for repeat runs" -ForegroundColor White
    Write-Host ""
    $incChoice = Read-Host "  Enter choice (1-2) [1]"
    if ($incChoice -eq '2') { $script:IncrementalBackup = $true }

    Write-Host ""
    $hod = Read-Host "  Download OneDrive cloud-only files before backup? (Y/N) [N]"
    $HydrateOneDrive = ($hod -eq 'Y' -or $hod -eq 'y')
}

if ($Destination -or $Mode -in @("Migrate","FullProfileBackup","RedirectAndClean","RepairTransactions")) {
    Write-Host ""
    Write-Host "  Bandwidth limit (useful for network destinations)?" -ForegroundColor Cyan
    Write-Host "  0 = no limit (fastest). Enter a number in Mbps to throttle." -ForegroundColor Gray
    Write-Host ""
    $defaultBw = if ($savedConfig -and $savedConfig.BandwidthLimitMbps) { $savedConfig.BandwidthLimitMbps } else { "0" }
    $bwInput = Read-Host "  Bandwidth limit Mbps (0=unlimited) [$defaultBw]"
    if ($bwInput -match '^\d+$') { $BandwidthLimitMbps = [int]$bwInput }
}

# ============================================================
# STEP 6A: MIGRATE-SPECIFIC
# ============================================================
$SkipRegistryUpdate = $false
$SkipKFMBlock       = $false
$CreateSymlink      = $false
$EnableCheckpoint   = $EnableCheckpoint -eq $true
$DeployKFMPolicy    = $false
$RemoveKFMPolicy    = $false
$KFMTenantId        = $null

if ($Mode -eq "Migrate") {
    Write-SectionHeader "STEP 6A: MIGRATION SETTINGS"

    Write-Host ""
    Write-Host "  Create a shortcut at the old location pointing to the new one?" -ForegroundColor Cyan
    Write-Host "  Any old shortcuts or apps that use the old path will still work." -ForegroundColor Gray
    Write-Host ""
    $csyChoice = Read-Host "  Create symlink at source? (Y/N) [N]"
    $CreateSymlink = ($csyChoice -eq "Y" -or $csyChoice -eq "y")

    Write-Host ""
    Write-Host "  OneDrive KFM (Known Folder Move) — optional, skip if unsure" -ForegroundColor Cyan
    Write-Host "  KFM keeps Desktop/Documents/Pictures inside OneDrive." -ForegroundColor Gray
    Write-Host "  If active, the script detects and handles it automatically." -ForegroundColor Gray
    Write-Host ""
    Write-Host "    1. Auto (recommended — script handles KFM if detected)" -ForegroundColor White
    Write-Host "    2. Remove KFM policy before migrating (unlocks folders)" -ForegroundColor White
    Write-Host "    3. Deploy KFM policy after migrating (requires Entra Tenant ID)" -ForegroundColor White
    Write-Host ""
    $kfmPolicyChoice = Read-Host "  KFM policy action (1-3) [1]"
    switch ($kfmPolicyChoice) {
        "2" { $RemoveKFMPolicy = $true; Write-Status "KFM policy will be removed before migration" -Type "Info" }
        "3" {
            $DeployKFMPolicy = $true
            $KFMTenantId = Read-Host "  Azure AD Tenant GUID"
            Write-Status "KFM policy will be deployed after migration" -Type "Info"
        }
    }
}

# ============================================================
# STEP 6B: RESTORE-PROFILE SETTINGS
# ============================================================
$SkipFileRestore     = $false
$SkipRegistryRestore = $false
$SkipAclRestore      = $false
$SkipWifiRestore     = $false
$SkipPrinterRestore  = $false
$SkipTaskRestore     = $false
$SkipWslRestore      = $false
$SkipDriveRestore    = $false
$RestoreSource       = $null

if ($Mode -eq "RestoreProfile") {
    Write-SectionHeader "STEP 6B: RESTORE SETTINGS"

    Write-Host ""
    Write-Host "  The backup folder path was entered in Step 3." -ForegroundColor Gray
    Write-Host "  If the backup contains subfolders per user, enter the specific" -ForegroundColor Gray
    Write-Host "  subfolder path here — or leave blank to auto-detect." -ForegroundColor Gray
    Write-Host ""
    $RestoreSource = Read-Host "  Specific backup subfolder path (blank = auto)"
    if (-not $RestoreSource) { $RestoreSource = $null }

    Write-Host ""
    Write-Host "  Restore to which profile path?" -ForegroundColor Cyan
    Write-Host "  Leave blank to restore to C:\Users\$($TargetUsername ?? $env:USERNAME)" -ForegroundColor Gray
    Write-Host ""
    $destProfile = Read-Host "  Restore destination (blank = default)"
    if ($destProfile) { $script:RestoreDestinationProfile = $destProfile } else { $script:RestoreDestinationProfile = $null }

    Write-Host ""
    Write-Host "  What to restore?" -ForegroundColor Cyan
    Write-Host "    1. Everything (recommended)" -ForegroundColor White
    Write-Host "    2. Files only (skip settings, Wi-Fi, printers, tasks)" -ForegroundColor White
    Write-Host "    3. Choose what to skip" -ForegroundColor White
    Write-Host ""
    $restoreChoiceCustom = Read-Host "  Enter choice (1-3) [1]"
    switch ($restoreChoiceCustom) {
        "2" {
            $SkipRegistryRestore = $true; $SkipWifiRestore = $true
            $SkipPrinterRestore = $true; $SkipTaskRestore = $true
            $SkipWslRestore = $true; $SkipDriveRestore = $true
            Write-Status "Will restore files only" -Type "Info"
        }
        "3" {
            Write-Host "  Answer Y to SKIP, N to restore:" -ForegroundColor Gray
            $SkipRegistryRestore = ((Read-Host "  Skip registry settings? (Y/N)") -in 'Y','y')
            $SkipAclRestore      = ((Read-Host "  Skip file permissions (ACLs)? (Y/N)") -in 'Y','y')
            $SkipWifiRestore     = ((Read-Host "  Skip Wi-Fi profiles? (Y/N)") -in 'Y','y')
            $SkipPrinterRestore  = ((Read-Host "  Skip printers? (Y/N)") -in 'Y','y')
            $SkipTaskRestore     = ((Read-Host "  Skip scheduled tasks? (Y/N)") -in 'Y','y')
            $SkipWslRestore      = ((Read-Host "  Skip WSL distros? (Y/N)") -in 'Y','y')
            $SkipDriveRestore    = ((Read-Host "  Skip mapped drives? (Y/N)") -in 'Y','y')
        }
    }
    $restored = @()
    if (-not $SkipFileRestore)     { $restored += "Files" }
    if (-not $SkipRegistryRestore) { $restored += "Registry" }
    if (-not $SkipAclRestore)      { $restored += "ACLs" }
    if (-not $SkipWifiRestore)     { $restored += "Wi-Fi" }
    if (-not $SkipPrinterRestore)  { $restored += "Printers" }
    if (-not $SkipTaskRestore)     { $restored += "Tasks" }
    if (-not $SkipWslRestore)      { $restored += "WSL" }
    if (-not $SkipDriveRestore)    { $restored += "Drives" }
    Write-Status "Will restore: $($restored -join ', ')" -Type "Success"
}

# ============================================================
# STEP 6C: FULL PROFILE BACKUP SETTINGS (already collected above)
# ============================================================
$MaxProfileSizeGB   = 0
$SkipCloudOnlyCheck = $false

if ($Mode -eq "FullProfileBackup") {
    Write-SectionHeader "STEP 6C: BACKUP LIMITS (OPTIONAL)"
    Write-Host ""
    Write-Host "  Skip profiles larger than a size limit?" -ForegroundColor Cyan
    Write-Host "  Useful to avoid backing up huge developer machines. 0 = no limit." -ForegroundColor Gray
    Write-Host ""
    $mpsIn = Read-Host "  Max profile size GB to include (0=unlimited) [0]"
    if ($mpsIn -match '^\d+$') { $MaxProfileSizeGB = [int]$mpsIn }

    Write-Host ""
    $sccChoice = Read-Host "  Skip cloud-only file check (faster, may miss cloud files)? (Y/N) [N]"
    $SkipCloudOnlyCheck = ($sccChoice -eq "Y" -or $sccChoice -eq "y")
}

# ============================================================
# STEP 7: ROLLBACK
# ============================================================
$RollbackFile = $null

if ($Mode -eq "Rollback") {
    Write-SectionHeader "STEP 7: ROLLBACK"
    Write-Host ""
    Write-Status "Registry-only rollback. No files are moved." -Type "Info"
    Write-Host ""

    $backupDir = Join-Path $env:TEMP "UFM_Backups"
    if (Test-Path $backupDir) {
        $backupFiles = Get-ChildItem -Path $backupDir -Filter "RegistryBackup_*.reg" | Sort-Object LastWriteTime -Descending
        if ($backupFiles.Count -gt 0) {
            Write-Host "  Available registry backups:" -ForegroundColor Cyan
            for ($i = 0; $i -lt [Math]::Min(10, $backupFiles.Count); $i++) {
                $f = $backupFiles[$i]
                Write-Host "    $($i+1). $($f.Name)   [$($f.LastWriteTime)]" -ForegroundColor Gray
            }
            Write-Host ""
            $backupChoice = Read-Host "  Select backup (1-$([Math]::Min(10, $backupFiles.Count)))"
            if ($backupChoice -match '^\d+$') {
                $idx = [int]$backupChoice - 1
                if ($idx -ge 0 -and $idx -lt $backupFiles.Count) {
                    $RollbackFile = $backupFiles[$idx].FullName
                    Write-Status "Selected: $(Split-Path $RollbackFile -Leaf)" -Type "Success"
                }
            }
        } else {
            Write-Status "No registry backup files found in: $backupDir" -Type "Warning"
        }
    } else {
        Write-Status "No backup directory found: $backupDir" -Type "Warning"
    }

    Write-Host ""
    Write-Host "  Roll back a full profile backup instead of just registry?" -ForegroundColor Cyan
    Write-Host "  Only needed if you used FullProfileBackup and want to revert everything." -ForegroundColor Gray
    Write-Host ""
    $rfpChoice = Read-Host "  Full profile rollback? (Y/N) [N]"
    $RollbackFullProfile = ($rfpChoice -eq "Y" -or $rfpChoice -eq "y")
}

# ============================================================
# STEP 8: SCHEDULED TASK (OPTIONAL)
# ============================================================
$RegisterTask = $false

Write-SectionHeader "STEP 8: SCHEDULE (OPTIONAL)"

Write-Host ""
Write-Host "  Do you want Windows to run this automatically on a schedule?" -ForegroundColor Cyan
Write-Host "  (Creates a Windows Scheduled Task — runs as SYSTEM by default)" -ForegroundColor Gray
Write-Host ""
$taskChoice = Read-Host "  Schedule this task? (Y/N) [N]"
if ($taskChoice -eq "Y" -or $taskChoice -eq "y") {
    $RegisterTask = $true

    $tnIn = Read-Host "  Task name [UserFolderMigrator]"
    if ($tnIn) { $TaskName = $tnIn }

    Write-Host ""
    Write-Host "  How often?" -ForegroundColor Cyan
    Write-Host "    1. Daily"
    Write-Host "    2. Weekly (recommended)"
    Write-Host "    3. At every logon"
    Write-Host ""
    $trigIn = Read-Host "  Enter choice (1-3) [2]"
    $TaskTrigger = switch ($trigIn) { "1" { "Daily" } "3" { "AtLogon" } default { "Weekly" } }

    if ($TaskTrigger -ne "AtLogon") {
        $timeIn = Read-Host "  Run time (HH:MM) [22:00]"
        if ($timeIn -match '^\d{1,2}:\d{2}$') { $TaskTime = $timeIn }
    }

    if ($TaskTrigger -eq "Weekly") {
        Write-Host ""
        Write-Host "  Which day?   1.Sun  2.Mon  3.Tue  4.Wed  5.Thu  6.Fri  7.Sat" -ForegroundColor Cyan
        $dayIn = Read-Host "  Enter choice (1-7) [1=Sunday]"
        $TaskDay = switch ($dayIn) {
            "2" { "Monday" } "3" { "Tuesday" } "4" { "Wednesday" }
            "5" { "Thursday" } "6" { "Friday" } "7" { "Saturday" }
            default { "Sunday" }
        }
    }

    Write-Host ""
    Write-Host "  Run as which account?" -ForegroundColor Cyan
    Write-Host "    1. SYSTEM (recommended — no password required)"
    Write-Host "    2. Current user ($env:USERNAME)"
    Write-Host "    3. Custom account"
    Write-Host ""
    $runAsIn = Read-Host "  Enter choice (1-3) [1]"
    $TaskRunAs = switch ($runAsIn) {
        "2" { $env:USERNAME }
        "3" { Read-Host "  Account (DOMAIN\username or UPN)" }
        default { "SYSTEM" }
    }
    Write-Status "Task: $TaskName | $TaskTrigger$(if ($TaskTrigger -ne 'AtLogon') { " @ $TaskTime" }) | RunAs: $TaskRunAs" -Type "Success"
}

Write-Host ""
if ($Mode -eq "Migrate") {
    $cstChoice = Read-Host "  Create a logon sync task to keep shell folder paths current after migration? (Y/N) [N]"
    $CreateSyncTask = ($cstChoice -eq "Y" -or $cstChoice -eq "y")
    if ($CreateSyncTask) { Write-Status "Sync task will be created after migration completes." -Type "Info" }
}

# ============================================================
# STEP 9: POWER USER OPTIONS
# ============================================================
$Exclude                 = @()
$ExcludeFile             = $null
$DisableAutoExclusions   = $false
$SkipTestRestore         = $false
$TestRestoreSamplePct    = 10
$SkipLockedFileCheck     = $false
$SkipAutoPermissionFix   = $false
$SkipJunctionScan        = $false
$SecureWipeSource        = $false
$ValidateOnly            = $false
$PilotUser               = $null
$NetworkTimeout          = 30
$QuarantinePath          = $null
$QuarantineRetentionDays = 0
$WslInstallRoot          = 'C:\WSL'

Write-SectionHeader "STEP 9: POWER USER OPTIONS"
Write-Host "  These settings cover edge cases and advanced scenarios." -ForegroundColor DarkGray
Write-Host "  All defaults are safe — skip this step unless you have a specific need." -ForegroundColor DarkGray
Write-Host ""
$showPower = Read-Host "  Configure power user options? (Y/N) [N]"

if ($showPower -eq "Y" -or $showPower -eq "y") {

    Write-Host ""
    Write-Host "  ── File Transfer ──────────────────────────────────────────────" -ForegroundColor DarkCyan

    Write-Host "  Robocopy threads (0=auto, higher=faster on fast disks):" -ForegroundColor Gray
    $defaultThreads = if ($savedConfig -and $savedConfig.RobocopyThreads) { $savedConfig.RobocopyThreads } else { "0" }
    $roboIn = Read-Host "  Robocopy threads per folder (0-128) [$defaultThreads]"
    if ($roboIn -match '^\d+$') { $RobocopyThreads = [int]$roboIn }

    $rzChoice = Read-Host "  Use Robocopy /Z restartable mode (survives power cuts, slower)? (Y/N) [N]"
    $UseRobocopyZ = ($rzChoice -eq "Y" -or $rzChoice -eq "y")

    $wanOpt = Read-Host "  Optimize for high-latency network (WAN/VPN/satellite)? (Y/N) [N]"
    if ($wanOpt -eq "Y" -or $wanOpt -eq "y") { $script:WanOptimized = $true }

    $maxRepair = Read-Host "  Max profile size GB for auto permission repair (0=unlimited) [10]"
    if ($maxRepair -match '^\d+$') { $script:MaxRepairSizeGB = [int]$maxRepair }

    $roboRetIn = Read-Host "  Robocopy retries on file failure (1-30) [3]"
    if ($roboRetIn -match '^\d+$') { $RobocopyRetries = [Math]::Max(1,[int]$roboRetIn) }

    $roboWaitIn = Read-Host "  Robocopy wait between retries seconds (1-120) [5]"
    if ($roboWaitIn -match '^\d+$') { $RobocopyWait = [Math]::Max(1,[int]$roboWaitIn) }

    Write-Host ""
    Write-Host "  ── Exclusions ─────────────────────────────────────────────────" -ForegroundColor DarkCyan

    $excIn = Read-Host "  Exclude folders/patterns (comma-separated, blank=none)"
    if ($excIn) { $Exclude = $excIn -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }

    $efIn = Read-Host "  Exclusion list file path (blank=none)"
    if ($efIn -and (Test-Path $efIn)) { $ExcludeFile = $efIn }
    elseif ($efIn) { Write-Status "File not found — exclusion file ignored" -Type "Warning" }

    $daeChoice = Read-Host "  Disable auto-exclusions (AppData\Local\Temp etc)? (Y/N) [N]"
    $DisableAutoExclusions = ($daeChoice -eq "Y" -or $daeChoice -eq "y")

    Write-Host ""
    Write-Host "  ── Verification ───────────────────────────────────────────────" -ForegroundColor DarkCyan

    $dcvChoice = Read-Host "  Disable checksum verification (faster, less safe)? (Y/N) [N]"
    $DisableChecksumVerify = ($dcvChoice -eq "Y" -or $dcvChoice -eq "y")

    if (-not $DisableChecksumVerify) {
        Write-Host "  Checksum algorithm:" -ForegroundColor Gray
        Write-Host "    1. SHA256 — safest, slightly slower (recommended)" -ForegroundColor Gray
        Write-Host "    2. SHA1   — faster, still reliable" -ForegroundColor Gray
        Write-Host "    3. MD5    — fastest, small risk of missed corruption" -ForegroundColor Gray
        $csIn = Read-Host "  Enter choice (1-3) [1]"
        $ChecksumAlgorithm = switch ($csIn) { "2" { "SHA1" } "3" { "MD5" } default { "SHA256" } }
    }

    $vdChoice = Read-Host "  Verify destination after copy (re-reads all files, slower)? (Y/N) [N]"
    $VerifyDestination = ($vdChoice -eq "Y" -or $vdChoice -eq "y")

    $strChoice = Read-Host "  Skip test-restore sample check? (Y/N) [N]"
    $SkipTestRestore = ($strChoice -eq "Y" -or $strChoice -eq "y")

    if (-not $SkipTestRestore) {
        $pctIn = Read-Host "  Test restore sample percentage (1-20) [10]"
        if ($pctIn -match '^\d+$') { $TestRestoreSamplePct = [Math]::Min(20,[Math]::Max(1,[int]$pctIn)) }
    }

    Write-Host ""
    Write-Host "  ── Security ───────────────────────────────────────────────────" -ForegroundColor DarkCyan

    $blChoice = Read-Host "  Require BitLocker encryption on destination? (Y/N) [N]"
    $BitLockerRequired = ($blChoice -eq "Y" -or $blChoice -eq "y")

    $swsChoice = Read-Host "  Secure wipe source after migration (PERMANENT — uses SDelete)? (Y/N) [N]"
    $SecureWipeSource = ($swsChoice -eq "Y" -or $swsChoice -eq "y")
    if ($SecureWipeSource) { Write-Status "WARNING: Source will be permanently overwritten — cannot be undone!" -Type "Warning" }

    Write-Host ""
    Write-Host "  ── Safety Checks ──────────────────────────────────────────────" -ForegroundColor DarkCyan

    $slfc = Read-Host "  Skip locked file check before starting? (Y/N) [N]"
    $SkipLockedFileCheck = ($slfc -eq "Y" -or $slfc -eq "y")

    $sapf = Read-Host "  Skip auto permission fix on destination? (Y/N) [N]"
    $SkipAutoPermissionFix = ($sapf -eq "Y" -or $sapf -eq "y")

    $sjs  = Read-Host "  Skip junction/symlink scan warning? (Y/N) [N]"
    $SkipJunctionScan = ($sjs -eq "Y" -or $sjs -eq "y")

    $sGPO = Read-Host "  Skip GPO folder redirection block? (Y/N) [N]"
    $SkipGPOBlock = ($sGPO -eq "Y" -or $sGPO -eq "y")

    $fOD = Read-Host "  Force migration even if OneDrive is running? (Y/N) [N]"
    $ForceOneDrive = ($fOD -eq "Y" -or $fOD -eq "y")

    $sAC = Read-Host "  Skip AccessChk permission audit? (Y/N) [N]"
    $SkipAccessCheck = ($sAC -eq "Y" -or $sAC -eq "y")

    $sfcChoice = Read-Host "  Run SFC /verifyonly pre-flight check (adds 5-15 min)? (Y/N) [N]"
    $RunSFCCheck = ($sfcChoice -eq "Y" -or $sfcChoice -eq "y")

    Write-Host ""
    Write-Host "  ── Restore Point ──────────────────────────────────────────────" -ForegroundColor DarkCyan

    $drpChoice = Read-Host "  Disable Windows Restore Point creation before migration? (Y/N) [N]"
    $DisableRestorePoint = ($drpChoice -eq "Y" -or $drpChoice -eq "y")

    if (-not $DisableRestorePoint) {
        $aespChoice = Read-Host "  Auto-enable System Protection if needed (unattended)? (Y/N) [N]"
        $AutoEnableSystemProtection = ($aespChoice -eq "Y" -or $aespChoice -eq "y")
    }

    Write-Host ""
    Write-Host "  ── Staged Rollout ─────────────────────────────────────────────" -ForegroundColor DarkCyan

    $voChoice = Read-Host "  Validate-only mode (checks only, no copy)? (Y/N) [N]"
    $ValidateOnly = ($voChoice -eq "Y" -or $voChoice -eq "y")

    $puIn = Read-Host "  Pilot user (migrate only this one user as a test, blank=none)"
    if ($puIn) { $PilotUser = $puIn }

    Write-Host ""
    Write-Host "  ── Logging & Output ───────────────────────────────────────────" -ForegroundColor DarkCyan

    $logIn = Read-Host "  Custom log file path (blank = default in TEMP)"
    if ($logIn) { $LogPath = $logIn }

    $repIn = Read-Host "  Custom HTML report path (blank = default in TEMP)"
    if ($repIn) { $ReportPath = $repIn }

    $dhrChoice = Read-Host "  Disable HTML report generation? (Y/N) [N]"
    $DisableHtmlReport = ($dhrChoice -eq "Y" -or $dhrChoice -eq "y")

    $noeChoice = Read-Host "  Disable Windows Event Log entries? (Y/N) [N]"
    $NoEventLog = ($noeChoice -eq "Y" -or $noeChoice -eq "y")

    $quietChoice = Read-Host "  Quiet mode (suppress console output)? (Y/N) [N]"
    $QuietMode = ($quietChoice -eq "Y" -or $quietChoice -eq "y")

    Write-Host ""
    Write-Host "  ── Network & Storage ──────────────────────────────────────────" -ForegroundColor DarkCyan

    $ntIn = Read-HostWithHelp "  Network timeout seconds for UNC paths (10-300) [30]" -Topic "network_timeout"
    if ($ntIn -match '^\d+$') { $NetworkTimeout = [Math]::Min(300,[Math]::Max(10,[int]$ntIn)) }

    $qpIn = Read-Host "  Custom quarantine path for flagged files (blank=default)"
    if ($qpIn) { $QuarantinePath = $qpIn }

    $qrdIn = Read-Host "  Quarantine retention days (0=keep forever) [0]"
    if ($qrdIn -match '^\d+$') { $QuarantineRetentionDays = [int]$qrdIn }

    Write-Host ""
    Write-Host "  ── Backup-Specific ────────────────────────────────────────────" -ForegroundColor DarkCyan

    if ($Mode -eq "FullProfileBackup") {
        $sbmChoice = Read-Host "  Skip backup manifest generation? (Y/N) [N]"
        $SkipBackupManifest = ($sbmChoice -eq "Y" -or $sbmChoice -eq "y")

        $sseChoice = Read-Host "  Skip supplemental exports (Wi-Fi, printers, tasks, WSL)? (Y/N) [N]"
        $SkipSupplementalExports = ($sseChoice -eq "Y" -or $sseChoice -eq "y")
    }

    if ($Mode -eq "Rollback") {
        $rfpChoice2 = Read-Host "  Roll back a full profile backup? (Y/N) [N]"
        $RollbackFullProfile = ($rfpChoice2 -eq "Y" -or $rfpChoice2 -eq "y")
    }

    Write-Host ""
    Write-Host "  ── Resume & State ─────────────────────────────────────────────" -ForegroundColor DarkCyan

    $drChoice = Read-Host "  Disable resume (start fresh every run, ignore checkpoint)? (Y/N) [N]"
    $DisableResume = ($drChoice -eq "Y" -or $drChoice -eq "y")

    $cfIn = Read-Host "  Custom checkpoint file path (blank=default)"
    if ($cfIn) { $CheckpointFile = $cfIn }

    $rsChoice = Read-Host "  Clear state ledger before running (ResetState)? (Y/N) [N]"
    $ResetState = ($rsChoice -eq "Y" -or $rsChoice -eq "y")

    Write-Host ""
    Write-Host "  ── Environment ────────────────────────────────────────────────" -ForegroundColor DarkCyan

    $offChoice = Read-Host "  Offline mode (no internet, use pre-staged modules)? (Y/N) [N]"
    $OfflineMode = ($offChoice -eq "Y" -or $offChoice -eq "y")

    $daptChoice = Read-Host "  Disable automatic performance tuning? (Y/N) [N]"
    $DisableAutoPerfTuning = ($daptChoice -eq "Y" -or $daptChoice -eq "y")

    Write-Host ""
    Write-Host "  ── WSL ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan

    $wslIn = Read-HostWithHelp "  WSL install root on restore [C:\WSL]" -Topic "wsl_install_root"
    if ($wslIn) { $WslInstallRoot = $wslIn }

    Write-Host ""
    Write-Host "  ── Syslog ─────────────────────────────────────────────────────" -ForegroundColor DarkCyan

    $syslogChoice = Read-Host "  Enable Syslog forwarding? (Y/N) [N]"
    if ($syslogChoice -eq "Y" -or $syslogChoice -eq "y") {
        $EnableSyslog = $true
        $SyslogServer = Read-Host "  Syslog server address (hostname or IP)"
        $hmacIn = Read-Host "  HMAC signing secret for log integrity (blank = use machine SID)"
        if ($hmacIn) { $HmacSecret = $hmacIn }
    }

    Write-Host ""
    Write-Host "  ── Migration-Specific ─────────────────────────────────────────" -ForegroundColor DarkCyan

    if ($Mode -eq "Migrate") {
        Write-Host "  Skip registry update (move files only, Windows still points at old location)?" -ForegroundColor Gray
        $sruChoice = Read-Host "  Skip registry update? (Y/N) [N]"
        $SkipRegistryUpdate = ($sruChoice -eq "Y" -or $sruChoice -eq "y")

        $kfmChoice = Read-Host "  Skip OneDrive KFM block check entirely? (Y/N) [N]"
        $SkipKFMBlock = ($kfmChoice -eq "Y" -or $kfmChoice -eq "y")

        $dsmvss = Read-Host "  Disable smart VSS (use VSS for all files not just locked)? (Y/N) [N]"
        $DisableSmartVSS = ($dsmvss -eq "Y" -or $dsmvss -eq "y")

        $cstChoice = Read-Host "  Create scheduled delta-sync task after migration (keeps source in sync)? (Y/N) [N]"
        $CreateSyncTask = ($cstChoice -eq "Y" -or $cstChoice -eq "y")
    }

    $mfInput = Read-Host "  Max folder failures before aborting (0=never abort) [0]"
    if ($mfInput -match '^\d+$') { $MaxFailures = [int]$mfInput }
}

} # ── END CUSTOM WIZARD ────────────────────────────────────────────────────────

# ============================================================
# SUMMARY AND CONFIRMATION
# ============================================================
Write-SectionHeader "CONFIGURATION SUMMARY"

# ── Plain-English "what will happen" block ─────────────────────────────────
Write-Host ""
Write-SectionHeader "WHAT WILL HAPPEN WHEN YOU PRESS ENTER"
Write-Host ""

$targetDesc = if ($AllUsers) { "ALL user profiles on this machine" }
              elseif ($TargetUsername) { "user: $TargetUsername" }
              else { "current user: $env:USERNAME" }

switch ($Mode) {
    "Migrate" {
        $folderDesc = if ($Folders -contains "All") { "all shell folders (Desktop, Documents, Downloads, Music, Pictures, Videos, etc.)" } else { $Folders -join ", " }
        Write-Host "  The script will COPY $folderDesc" -ForegroundColor White
        Write-Host "  for $targetDesc" -ForegroundColor White
        Write-Host "  to: $Destination" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Windows will be updated to point to the new location." -ForegroundColor White
        if ($KeepSource) { Write-Host "  Original files will be KEPT at the old location." -ForegroundColor Yellow }
        else             { Write-Host "  Original files will remain until you manually delete them." -ForegroundColor Gray }
        if ($DryRun)     { Write-Host "  DRY RUN: No files will be moved. This is a simulation only." -ForegroundColor Yellow }
    }
    "RestoreDefaults" {
        Write-Host "  The script will MOVE shell folders for $targetDesc" -ForegroundColor White
        Write-Host "  back to their default location: C:\Users\<username>\..." -ForegroundColor Cyan
        Write-Host "  Windows registry will be updated to point to C: drive locations." -ForegroundColor White
        if ($DryRun) { Write-Host "  DRY RUN: No files will be moved. This is a simulation only." -ForegroundColor Yellow }
    }
    "FullProfileBackup" {
        Write-Host "  The script will CREATE A COMPLETE BACKUP of the profile for" -ForegroundColor White
        Write-Host "  $targetDesc" -ForegroundColor White
        Write-Host "  to: $Destination" -ForegroundColor Cyan
        Write-Host "  Includes: all files, registry, Wi-Fi, printers, tasks, WSL distros." -ForegroundColor Gray
        Write-Host "  Nothing will be deleted. This is a non-destructive read operation." -ForegroundColor Green
    }
    "RestoreProfile" {
        Write-Host "  The script will RESTORE the profile for $targetDesc" -ForegroundColor White
        Write-Host "  from: $Destination" -ForegroundColor Cyan
        Write-Host "  Includes restoring files, registry, Wi-Fi, printers, tasks, WSL." -ForegroundColor Gray
        $skippedItems = @()
        if ($SkipFileRestore)     { $skippedItems += "Files" }
        if ($SkipRegistryRestore) { $skippedItems += "Registry" }
        if ($SkipWifiRestore)     { $skippedItems += "Wi-Fi" }
        if ($skippedItems)        { Write-Host "  SKIPPING: $($skippedItems -join ', ')" -ForegroundColor Yellow }
    }
    "RedirectAndClean" {
        Write-Host "  The script will UPDATE the Windows registry for $targetDesc" -ForegroundColor White
        Write-Host "  to point shell folders at: $Destination" -ForegroundColor Cyan
        Write-Host "  NO FILES WILL BE COPIED. Your files must already be at the destination." -ForegroundColor Yellow
    }
    "RepairTransactions" {
        Write-Host "  The script will MOVE any leftover files for $targetDesc" -ForegroundColor White
        Write-Host "  to where the registry currently points." -ForegroundColor White
        Write-Host "  Use this after an interrupted migration to clean up remaining files." -ForegroundColor Gray
    }
    "Rollback" {
        Write-Host "  The script will RESTORE registry shell folder paths for $targetDesc" -ForegroundColor White
        Write-Host "  to the state saved before a previous migration." -ForegroundColor White
        Write-Host "  NOTE: This does NOT move any files — registry only." -ForegroundColor Yellow
        if ($RollbackFile) { Write-Host "  Backup file: $(Split-Path $RollbackFile -Leaf)" -ForegroundColor Cyan }
    }
}
Write-Host ""
if ($SecureWipeSource) {
    Write-Host "  ⚠  SECURE WIPE ENABLED: After copying, source files will be permanently" -ForegroundColor Red
    Write-Host "     overwritten and deleted. THIS CANNOT BE UNDONE." -ForegroundColor Red
    Write-Host ""
}
if ($ValidateOnly) {
    Write-Host "  VALIDATE ONLY MODE: The script will check everything but make no changes." -ForegroundColor Yellow
    Write-Host ""
}
Write-Host "  ─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

Write-Host ("  {0,-38} {1}" -f "Setting:", "Value:") -ForegroundColor Cyan
Write-Host ("  {0,-38} {1}" -f ("-" * 38), ("-" * 40)) -ForegroundColor Gray

# Core
Write-Host ("  {0,-38} {1}" -f "Operation Mode",       $Mode)                                                                              -ForegroundColor White
Write-Host ("  {0,-38} {1}" -f "Target Users",          $(if ($AllUsers) { "ALL USERS" } elseif ($TargetUsername) { $TargetUsername } else { "Current User" })) -ForegroundColor White
if ($Destination)    { Write-Host ("  {0,-38} {1}" -f "Destination",        $Destination)     -ForegroundColor White }
if ($Folders)        { Write-Host ("  {0,-38} {1}" -f "Folders",            $(if ($Folders -contains "All") { "ALL" } else { $Folders -join ", " })) -ForegroundColor White }

# Flags
Write-Host ("  {0,-38} {1}" -f "Dry Run",              $(if ($DryRun) { "YES" } else { "NO" }))  -ForegroundColor $(if ($DryRun) { "Yellow" } else { "White" })
Write-Host ("  {0,-38} {1}" -f "Force",                $(if ($Force)  { "YES" } else { "NO" }))  -ForegroundColor White
if ($KeepSource)        { Write-Host ("  {0,-38} YES" -f "Keep Source")                            -ForegroundColor Yellow }
if ($UseVSS)            { Write-Host ("  {0,-38} YES" -f "Use VSS")                                -ForegroundColor Green  }
if ($UseRobocopyZ)      { Write-Host ("  {0,-38} YES" -f "Robocopy /Z Restartable")                -ForegroundColor White  }
if ($MaxParallel -gt 1) { Write-Host ("  {0,-38} {1}" -f "Parallel Users",  $MaxParallel)          -ForegroundColor White  }
if ($RobocopyThreads -gt 0) { Write-Host ("  {0,-38} {1}" -f "Robocopy Threads", $RobocopyThreads) -ForegroundColor White  }
if ($RobocopyRetries -ne 3) { Write-Host ("  {0,-38} {1}" -f "Robocopy Retries", $RobocopyRetries) -ForegroundColor White  }
if ($RobocopyWait -ne 5)    { Write-Host ("  {0,-38} {1}s" -f "Robocopy Wait",   $RobocopyWait)    -ForegroundColor White  }
if ($BandwidthLimitMbps -gt 0) { Write-Host ("  {0,-38} {1} Mbps" -f "Bandwidth Limit", $BandwidthLimitMbps) -ForegroundColor White }
if ($MaxFailures -gt 0) { Write-Host ("  {0,-38} {1}" -f "Max Failures",    $MaxFailures)          -ForegroundColor White  }

# Verification
Write-Host ("  {0,-38} {1}" -f "Checksum Verify",      $(if ($DisableChecksumVerify) { "DISABLED" } else { $ChecksumAlgorithm })) -ForegroundColor $(if ($DisableChecksumVerify) { "Yellow" } else { "White" })
if ($VerifyDestination)  { Write-Host ("  {0,-38} YES" -f "Verify Destination")   -ForegroundColor Green }
if ($BitLockerRequired)  { Write-Host ("  {0,-38} YES (will block if unencrypted)" -f "BitLocker Required") -ForegroundColor Yellow }

# Mode-specific
if ($Mode -eq "Migrate") {
    if ($SkipRegistryUpdate) { Write-Host ("  {0,-38} YES (files only, no registry)" -f "Skip Registry Update") -ForegroundColor Yellow }
    if ($SkipKFMBlock)       { Write-Host ("  {0,-38} YES" -f "Skip KFM Block")      -ForegroundColor Yellow }
    if ($CreateSymlink)      { Write-Host ("  {0,-38} YES" -f "Create Symlink")       -ForegroundColor White  }
    if ($EnableCheckpoint)   { Write-Host ("  {0,-38} YES" -f "Enable Checkpoint")    -ForegroundColor Green  }
    if ($RemoveKFMPolicy)    { Write-Host ("  {0,-38} YES" -f "Remove KFM Policy")    -ForegroundColor Yellow }
    if ($DeployKFMPolicy)    { Write-Host ("  {0,-38} YES (TenantId: $KFMTenantId)" -f "Deploy KFM Policy") -ForegroundColor Green }
}

if ($Mode -eq "RestoreProfile") {
    $skipped = @()
    if ($SkipFileRestore)     { $skipped += "Files" }
    if ($SkipRegistryRestore) { $skipped += "Registry" }
    if ($SkipAclRestore)      { $skipped += "ACLs" }
    if ($SkipWifiRestore)     { $skipped += "Wi-Fi" }
    if ($SkipPrinterRestore)  { $skipped += "Printers" }
    if ($SkipTaskRestore)     { $skipped += "Tasks" }
    if ($SkipWslRestore)      { $skipped += "WSL" }
    if ($skipped.Count -gt 0) { Write-Host ("  {0,-38} {1}" -f "Skipping restore of", ($skipped -join ", ")) -ForegroundColor Yellow }
    else                      { Write-Host ("  {0,-38} ALL components" -f "Restoring") -ForegroundColor Green }
}

if ($Mode -eq "FullProfileBackup") {
    if ($MaxProfileSizeGB -gt 0)  { Write-Host ("  {0,-38} {1} GB" -f "Max Profile Size", $MaxProfileSizeGB) -ForegroundColor White }
    if ($HydrateOneDrive)         { Write-Host ("  {0,-38} YES" -f "Hydrate OneDrive") -ForegroundColor Green }
    if ($SkipCloudOnlyCheck)      { Write-Host ("  {0,-38} YES" -f "Skip Cloud-Only Check") -ForegroundColor Yellow }
}

# Scheduled Task
if ($RegisterTask) {
    Write-Host ("  {0,-38} {1}" -f "Scheduled Task", "$TaskName | $TaskTrigger$(if ($TaskTrigger -ne 'AtLogon') { " @ $TaskTime" }) | $TaskRunAs") -ForegroundColor Cyan
}

# Power user summary
if ($ValidateOnly)             { Write-Host ("  {0,-38} YES" -f "Validate Only")                          -ForegroundColor Yellow }
if ($PilotUser)                { Write-Host ("  {0,-38} {1}" -f "Pilot User", $PilotUser)                 -ForegroundColor Yellow }
if ($SecureWipeSource)         { Write-Host ("  {0,-38} YES — IRREVERSIBLE" -f "Secure Wipe Source")      -ForegroundColor Red    }
if ($Exclude.Count -gt 0)      { Write-Host ("  {0,-38} {1}" -f "Exclusions", ($Exclude -join ", "))      -ForegroundColor White  }
if ($ExcludeFile)              { Write-Host ("  {0,-38} {1}" -f "Exclusion File", $ExcludeFile)           -ForegroundColor White  }
if ($DisableAutoExclusions)    { Write-Host ("  {0,-38} YES" -f "Disable Auto-Exclusions")                -ForegroundColor Yellow }
if ($QuarantinePath)           { Write-Host ("  {0,-38} {1}" -f "Quarantine Path", $QuarantinePath)       -ForegroundColor White  }
if ($DisableRestorePoint)      { Write-Host ("  {0,-38} YES" -f "Skip Restore Point")                     -ForegroundColor Yellow }
if ($AutoEnableSystemProtection){ Write-Host ("  {0,-38} YES" -f "Auto-Enable System Protection")         -ForegroundColor Green  }
if ($RunSFCCheck)              { Write-Host ("  {0,-38} YES" -f "SFC Pre-Flight Check")                   -ForegroundColor White  }
if ($SkipGPOBlock)             { Write-Host ("  {0,-38} YES" -f "Skip GPO Block")                        -ForegroundColor Yellow }
if ($ForceOneDrive)            { Write-Host ("  {0,-38} YES" -f "Force OneDrive")                        -ForegroundColor Yellow }
if ($SkipAccessCheck)          { Write-Host ("  {0,-38} YES" -f "Skip Access Check")                     -ForegroundColor Yellow }
if ($SkipBackupManifest)       { Write-Host ("  {0,-38} YES" -f "Skip Backup Manifest")                  -ForegroundColor Yellow }
if ($OfflineMode)              { Write-Host ("  {0,-38} YES" -f "Offline Mode")                          -ForegroundColor Yellow }
if ($DisableAutoPerfTuning)    { Write-Host ("  {0,-38} YES" -f "Disable Auto Perf Tuning")              -ForegroundColor Yellow }
if ($NoEventLog)               { Write-Host ("  {0,-38} YES" -f "No Event Log")                          -ForegroundColor Yellow }
if ($QuietMode)                { Write-Host ("  {0,-38} YES" -f "Quiet Mode")                            -ForegroundColor Yellow }
if ($DisableHtmlReport)        { Write-Host ("  {0,-38} YES" -f "Disable HTML Report")                   -ForegroundColor Yellow }
if ($LogPath)                  { Write-Host ("  {0,-38} {1}" -f "Log Path", $LogPath)                    -ForegroundColor White  }
if ($ReportPath)               { Write-Host ("  {0,-38} {1}" -f "Report Path", $ReportPath)              -ForegroundColor White  }
if ($DisableResume)            { Write-Host ("  {0,-38} YES" -f "Disable Resume")                        -ForegroundColor Yellow }
if ($CheckpointFile)           { Write-Host ("  {0,-38} {1}" -f "Checkpoint File", $CheckpointFile)      -ForegroundColor White  }
if ($ResetState)               { Write-Host ("  {0,-38} YES" -f "Reset State Ledger")                    -ForegroundColor Yellow }
if ($EnableSyslog)             { Write-Host ("  {0,-38} {1}" -f "Syslog Server", $SyslogServer)          -ForegroundColor White  }
if ($RollbackFullProfile)      { Write-Host ("  {0,-38} YES" -f "Full Profile Rollback")                 -ForegroundColor Yellow }
if ($script:WanOptimized)      { Write-Host ("  {0,-38} YES" -f "WAN Optimized")                        -ForegroundColor White  }
if ($script:MaxRepairSizeGB -ge 0) { Write-Host ("  {0,-38} {1} GB" -f "Max Repair Size", $script:MaxRepairSizeGB) -ForegroundColor White }
if ($script:IncrementalBackup) { Write-Host ("  {0,-38} YES" -f "Incremental Backup")                   -ForegroundColor Green  }

# Email
if ($NotificationEmail) {
    Write-Host ("  {0,-38} {1}" -f "Email Notifications", $NotificationEmail)   -ForegroundColor White
    Write-Host ("  {0,-38} {1}" -f "Email Auth",          $SmtpAuthMode)        -ForegroundColor White
    if ($NotificationTeamsWebhook) { Write-Host ("  {0,-38} configured" -f "Teams Webhook") -ForegroundColor White }
}
Write-Host ("  {0,-38} {1}" -f "Auto-Cleanup Credentials", $(if ($AutoCleanupCreds) { "YES" } else { "NO" })) -ForegroundColor $(if ($AutoCleanupCreds) { "Green" } else { "Yellow" })
if ($RollbackFile) { Write-Host ("  {0,-38} {1}" -f "Rollback File", (Split-Path $RollbackFile -Leaf)) -ForegroundColor White }
Write-Host ""

# ── Safety check (Help System plugin) ─────────────────────────────────────────
if (Get-Command Test-RiskySettingCombination -ErrorAction SilentlyContinue) {
    $safetySettings = @{
        Mode                  = $Mode
        SecureWipeSource      = $SecureWipeSource
        SkipRegistryUpdate    = $SkipRegistryUpdate
        DisableChecksumVerify = $DisableChecksumVerify
        AllUsers              = $AllUsers
        DisableAutoExclusions = $DisableAutoExclusions
        DryRun                = $DryRun
    }
    if (-not (Test-RiskySettingCombination -Settings $safetySettings)) {
        Clear-StoredCredentials; exit 0
    }
}

$confirm = Read-HostWithHelp "Proceed with these settings? (Y/N)" -Topic "confirm_execute" -AllowEmpty
if ($confirm -ne "Y" -and $confirm -ne "y") {
    Write-Status "Operation cancelled by user" -Type "Error"
    Clear-StoredCredentials
    exit 0
}

# ============================================================
# SAVE CONFIGURATION
# ============================================================
$configToSave = @{
    Mode = $modeChoice
    UserChoice = $userChoice
    Destination = $Destination
    Folders = $Folders
    NotificationEmail = $NotificationEmail
    SmtpServer = $SmtpServer
    MaxParallel = $MaxParallel
    RobocopyThreads = $RobocopyThreads
    AutoCleanupCreds = $AutoCleanupCreds
    BandwidthLimitMbps = $BandwidthLimitMbps
    MaxFailures = $MaxFailures
    LastRun = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

Save-Config -Settings $configToSave

# ============================================================
# BUILD AND RUN COMMAND
# ============================================================
Clear-WizardCheckpoint
Write-SectionHeader "EXECUTING MIGRATION"

$arguments = @()

# ── Mode ──────────────────────────────────────────────────────────────────────
$arguments += "-Mode", $Mode

# ── Mode-specific destinations / files ───────────────────────────────────────
switch ($Mode) {
    "Migrate" {
        $arguments += "-Destination", "`"$Destination`""
        if ($Folders -and $Folders -notcontains "All") {
            foreach ($f in $Folders) { $arguments += "-Folders", $f }
        }
    }
    "RestoreDefaults" { }
    { $_ -in @("RedirectAndClean","RepairTransactions") } {
        $arguments += "-Destination", "`"$Destination`""
        if ($Folders -and $Folders -notcontains "All") {
            foreach ($f in $Folders) { $arguments += "-Folders", $f }
        }
    }
    "FullProfileBackup" {
        $arguments += "-Destination", "`"$Destination`""
    }
    "RestoreProfile" {
        # Main script expects -Source for the backup root folder
        $arguments += "-Source", "`"$Destination`""
        $destProfileArg = if ($script:RestoreDestinationProfile) { $script:RestoreDestinationProfile }
                          elseif ($RestoreSource)                { $RestoreSource }
                          else                                   { $null }
        if ($destProfileArg) { $arguments += "-DestinationProfile", "`"$destProfileArg`"" }
    }
    "Rollback" {
        if ($RollbackFile) { $arguments += "-RollbackFile", "`"$RollbackFile`"" }
    }
}

# ── Users ─────────────────────────────────────────────────────────────────────
if ($AllUsers)                        { $arguments += "-AllUsers" }
if ($TargetUsername -and -not $AllUsers) { $arguments += "-TargetUsername", "`"$TargetUsername`"" }

# ── Core flags ────────────────────────────────────────────────────────────────
if ($DryRun)                          { $arguments += "-DryRun" }
if ($Force)                           { $arguments += "-Force" }
if ($KeepSource)                      { $arguments += "-KeepSource" }
if ($UseVSS)                          { $arguments += "-UseVSS" }
if ($DisableSmartVSS)                 { $arguments += "-DisableSmartVSS" }
if ($MaxParallel -gt 1)               { $arguments += "-MaxParallel",        $MaxParallel }
if ($BandwidthLimitMbps -gt 0)        { $arguments += "-BandwidthLimitMbps", $BandwidthLimitMbps }
if ($MaxFailures -gt 0)               { $arguments += "-MaxFailures",         $MaxFailures }
if ($SkipSupplementalExports)         { $arguments += "-SkipSupplementalExports" }

# ── Robocopy ──────────────────────────────────────────────────────────────────
if ($RobocopyThreads -gt 0)           { $arguments += "-RobocopyThreads",  $RobocopyThreads }
if ($RobocopyRetries -ne 3)           { $arguments += "-RobocopyRetries",  $RobocopyRetries }
if ($RobocopyWait -ne 5)              { $arguments += "-RobocopyWait",     $RobocopyWait }
if ($UseRobocopyZ)                    { $arguments += "-UseRobocopyZ" }
if ($script:WanOptimized)             { $arguments += "-WanOptimized" }
if ($script:MaxRepairSizeGB -ge 0)    { $arguments += "-MaxRepairSizeGB", $script:MaxRepairSizeGB }

# ── Verification ──────────────────────────────────────────────────────────────
if ($DisableChecksumVerify)           { $arguments += "-DisableChecksumVerify" }
if (-not $DisableChecksumVerify -and $ChecksumAlgorithm -ne "SHA256") {
                                        $arguments += "-ChecksumAlgorithm", $ChecksumAlgorithm }
if ($VerifyDestination)               { $arguments += "-VerifyDestination" }
if ($BitLockerRequired)               { $arguments += "-BitLockerRequired" }

# ── Migrate-specific ──────────────────────────────────────────────────────────
if ($Mode -eq "Migrate") {
    if ($SkipRegistryUpdate)          { $arguments += "-SkipRegistryUpdate" }
    if ($SkipKFMBlock)                { $arguments += "-SkipKFMBlock" }
    if ($CreateSymlink)               { $arguments += "-CreateSymlink" }
    if ($EnableCheckpoint)            { $arguments += "-EnableCheckpoint" }
    if ($RemoveKFMPolicy)             { $arguments += "-RemoveKFMPolicy" }
    if ($DeployKFMPolicy)             { $arguments += "-DeployKFMPolicy"
        if ($KFMTenantId)             { $arguments += "-KFMTenantId", "`"$KFMTenantId`"" } }
}

# ── RestoreProfile-specific ───────────────────────────────────────────────────
if ($Mode -eq "RestoreProfile") {
    if ($SkipFileRestore)             { $arguments += "-SkipFileRestore" }
    if ($SkipRegistryRestore)         { $arguments += "-SkipRegistryRestore" }
    if ($SkipAclRestore)              { $arguments += "-SkipAclRestore" }
    if ($SkipWifiRestore)             { $arguments += "-SkipWifiRestore" }
    if ($SkipPrinterRestore)          { $arguments += "-SkipPrinterRestore" }
    if ($SkipTaskRestore)             { $arguments += "-SkipTaskRestore" }
    if ($SkipWslRestore)              { $arguments += "-SkipWslRestore" }
}

# ── FullProfileBackup-specific ────────────────────────────────────────────────
if ($Mode -eq "FullProfileBackup") {
    if ($MaxProfileSizeGB -gt 0)      { $arguments += "-MaxProfileSizeGB",   $MaxProfileSizeGB }
    if ($HydrateOneDrive)             { $arguments += "-HydrateOneDrive" }
    if ($SkipCloudOnlyCheck)          { $arguments += "-SkipCloudOnlyCheck" }
    if ($SkipSupplementalExports)     { $arguments += "-SkipSupplementalExports" }
    if ($script:IncrementalBackup)    { $arguments += "-IncrementalBackup" }
}

# ── Scheduled Task ────────────────────────────────────────────────────────────
if ($RegisterTask) {
    $arguments += "-RegisterTask"
    $arguments += "-TaskName",    "`"$TaskName`""
    $arguments += "-TaskTrigger", $TaskTrigger
    $arguments += "-TaskRunAs",   "`"$TaskRunAs`""
    if ($TaskTrigger -ne "AtLogon") {
        $arguments += "-TaskTime", $TaskTime
        if ($TaskTrigger -eq "Weekly") { $arguments += "-TaskDay", $TaskDay }
    }
}

# ── Power-user ────────────────────────────────────────────────────────────────
if ($Exclude.Count -gt 0)             { foreach ($e in $Exclude) { $arguments += "-Exclude", "`"$e`"" } }
if ($ExcludeFile)                     { $arguments += "-ExcludeFile",              "`"$ExcludeFile`"" }
if ($DisableAutoExclusions)           { $arguments += "-DisableAutoExclusions" }
if (-not $SkipTestRestore) {
    if ($TestRestoreSamplePct -ne 10) { $arguments += "-TestRestoreSamplePct",     $TestRestoreSamplePct }
} else                                { $arguments += "-SkipTestRestore" }
if ($SkipLockedFileCheck)             { $arguments += "-SkipLockedFileCheck" }
if ($SkipAutoPermissionFix)           { $arguments += "-SkipAutoPermissionFix" }
if ($SkipJunctionScan)                { $arguments += "-SkipJunctionScan" }
if ($SecureWipeSource)                { $arguments += "-SecureWipeSource" }
if ($ValidateOnly)                    { $arguments += "-ValidateOnly" }
if ($TestCompatibility)               { $arguments += "-TestCompatibility" }
if ($PilotUser)                       { $arguments += "-PilotUser",                "`"$PilotUser`"" }
if ($NetworkTimeout -ne 30)           { $arguments += "-NetworkTimeout",            $NetworkTimeout }
if ($QuarantinePath)                  { $arguments += "-QuarantinePath",            "`"$QuarantinePath`"" }
if ($QuarantineRetentionDays -gt 0)   { $arguments += "-QuarantineRetentionDays",   $QuarantineRetentionDays }
if ($WslInstallRoot -ne "C:\WSL")     { $arguments += "-WslInstallRoot",            "`"$WslInstallRoot`"" }

# ── Safety / restore point ────────────────────────────────────────────────────
if ($DisableRestorePoint)             { $arguments += "-DisableRestorePoint" }
if ($AutoEnableSystemProtection)      { $arguments += "-AutoEnableSystemProtection" }
if ($RunSFCCheck)                     { $arguments += "-RunSFCCheck" }

# ── GPO / OneDrive / access ───────────────────────────────────────────────────
if ($SkipGPOBlock)                    { $arguments += "-SkipGPOBlock" }
if ($ForceOneDrive)                   { $arguments += "-ForceOneDrive" }
if ($SkipAccessCheck)                 { $arguments += "-SkipAccessCheck" }

# ── Backup-specific ───────────────────────────────────────────────────────────
if ($SkipBackupManifest)              { $arguments += "-SkipBackupManifest" }

# ── Resume / state ────────────────────────────────────────────────────────────
if ($DisableResume)                   { $arguments += "-DisableResume" }
if ($CheckpointFile)                  { $arguments += "-CheckpointFile",            "`"$CheckpointFile`"" }
if ($ResetState)                      { $arguments += "-ResetState" }

# ── Environment ───────────────────────────────────────────────────────────────
if ($OfflineMode)                     { $arguments += "-OfflineMode" }
if ($DisableAutoPerfTuning)           { $arguments += "-DisableAutoPerfTuning" }
if ($NoEventLog)                      { $arguments += "-NoEventLog" }
if ($QuietMode)                       { $arguments += "-QuietMode" }

# ── Logging ───────────────────────────────────────────────────────────────────
if ($LogPath)                         { $arguments += "-LogPath",                   "`"$LogPath`"" }
if ($ReportPath)                      { $arguments += "-ReportPath",                "`"$ReportPath`"" }
if ($DisableHtmlReport)               { $arguments += "-DisableHtmlReport" }

# ── Rollback ──────────────────────────────────────────────────────────────────
if ($RollbackFullProfile)             { $arguments += "-RollbackFullProfile" }

# ── Syslog ────────────────────────────────────────────────────────────────────
if ($EnableSyslog)                    { $arguments += "-EnableSyslog" }
if ($SyslogServer)                    { $arguments += "-SyslogServer",              "`"$SyslogServer`"" }
if ($HmacSecret)                      { $arguments += "-HmacSecret",                "`"$HmacSecret`"" }
if ($CreateSyncTask)                  { $arguments += "-CreateSyncTask" }

# ── RestoreProfile: SkipDriveRestore ─────────────────────────────────────────
if ($Mode -eq "RestoreProfile") {
    if ($SkipDriveRestore)            { $arguments += "-SkipDriveRestore" }
}

# ── Email ─────────────────────────────────────────────────────────────────────
if ($NotificationEmail) {
    $arguments += "-NotificationEmail", "`"$NotificationEmail`""
    switch ($SmtpAuthMode) {
        "Basic" {
            if ($script:CredentialsStored) {
                $arguments += "-SmtpAuthMode", "CredentialManager"
                $arguments += "-SecretName",   "UFM_Smtp"
                Write-Status "Using Credential Manager for SMTP" -Type "Info"
            } else {
                $arguments += "-SmtpAuthMode", "Basic"
                Write-Status "No stored credentials — main script will prompt for password." -Type "Warning"
            }
        }
        "OAuth2" {
            $arguments += "-SmtpAuthMode", "OAuth2"
            if ($script:OAuthTenantId)     { $arguments += "-OAuthTenantId",     "`"$($script:OAuthTenantId)`"" }
            if ($script:OAuthClientId)     { $arguments += "-OAuthClientId",     "`"$($script:OAuthClientId)`"" }
            if ($script:OAuthClientSecret) { $arguments += "-OAuthClientSecret", "`"$($script:OAuthClientSecret)`"" }
        }
        "Certificate" {
            $arguments += "-SmtpAuthMode", "Certificate"
            if ($script:OAuthTenantId)       { $arguments += "-OAuthTenantId",       "`"$($script:OAuthTenantId)`"" }
            if ($script:OAuthClientId)       { $arguments += "-OAuthClientId",       "`"$($script:OAuthClientId)`"" }
            if ($script:OAuthCertThumbprint) { $arguments += "-OAuthCertThumbprint", "`"$($script:OAuthCertThumbprint)`"" }
        }
        "SecretVault" {
            $arguments += "-SmtpAuthMode", "SecretVault"
            if ($SecretVaultName)          { $arguments += "-SecretVaultName",    "`"$SecretVaultName`"" }
            if ($script:SecretName)        { $arguments += "-SecretName",         "`"$($script:SecretName)`"" }
        }
        default {
            $arguments += "-SmtpAuthMode", $SmtpAuthMode
        }
    }
    if ($SmtpServer)                          { $arguments += "-SmtpServer",  "`"$SmtpServer`"" }
    if ($SmtpFrom)                            { $arguments += "-SmtpFrom",    "`"$SmtpFrom`"" }
    if ($SmtpPort -and $SmtpPort -ne 587)     { $arguments += "-SmtpPort",    $SmtpPort }
    if ($SmtpMaxRetries -ne 3)                { $arguments += "-SmtpMaxRetries",       $SmtpMaxRetries }
    if ($SmtpRetryDelayBase -ne 5)            { $arguments += "-SmtpRetryDelayBase",   $SmtpRetryDelayBase }
    if ($NotificationTeamsWebhook)            { $arguments += "-NotificationTeamsWebhook", "`"$NotificationTeamsWebhook`"" }
}
if ($AutoCleanupCreds) { $arguments += "-AutoCleanupCreds" }

# ── Always unattended (interactive questions already answered above) ───────────
if ($Mode -ne "RestoreProfile") { $arguments += "-Unattended" }

$command = "& `"$script:MainScriptPath`" $($arguments -join ' ')"

# ============================================================
# ASK HOW TO RUN THE MAIN SCRIPT
# ============================================================

Write-Host ""
Write-Host "  How would you like to run the main script?" -ForegroundColor Cyan
Write-Host "    1. In CURRENT window (output visible here)"
Write-Host "    2. In NEW window (separate PowerShell window, non-blocking)"
Write-Host "    3. In NEW window and WAIT (this window waits for completion)"
Write-Host ""

$runChoice = Read-Host "  Enter choice (1-3)"

Write-Status "Command prepared" -Type "Info"
Write-Host ""
Write-Host "  $command" -ForegroundColor Gray
Write-Host ""

switch ($runChoice) {
    "1" {
        Write-Status "Running in CURRENT window..." -Type "Info"
        Remove-Item (Join-Path $env:TEMP "UFM_Wizard_Checkpoint.json") -Force -ErrorAction SilentlyContinue
        try {
            Invoke-Expression $command
            $exitCode = $LASTEXITCODE
        } catch {
            Write-Status "Error executing migration: $($_.Exception.Message)" -Type "Error"
            $exitCode = 99
        }

        
        Write-Host ""
        if ($exitCode -eq 0) {
            Write-Status "Migration completed SUCCESSFULLY!" -Type "Success"
        } elseif ($exitCode -in @(1,2)) {
            Write-Status "Migration completed with PARTIAL success (exit $exitCode)" -Type "Warning"
        } elseif ($exitCode -eq 6) {
            Write-Status "MIGRATION BLOCKED: OneDrive Known Folder Move (KFM) is active." -Type "Error"
            Write-Status "KFM prevents safe migration because OneDrive would revert the changes." -Type "Error"
            Write-Status "To fix: Disable KFM in OneDrive settings or via Group Policy, then re-run." -Type "Info"
            Write-Status "If you are certain KFM is disabled, re-run and select Custom -> Skip KFM block." -Type "Warning"
        } else {
            Write-Status "Migration FAILED with exit code: $exitCode" -Type "Error"
        }
        if (Get-Command Show-ErrorRecoveryHelp -ErrorAction SilentlyContinue) {
            $logPath = (Get-Item (Join-Path $env:TEMP "UFM_*.log") -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
            Show-ErrorRecoveryHelp -ExitCode $exitCode -LogPath ($logPath ?? '')
        }
    }

    "2" {
        # ============================================================
        # OPTION 2: RUN IN NEW WINDOW (NON-BLOCKING)
        # ============================================================
        Write-Status "Launching in NEW window (non-blocking)..." -Type "Info"

        # Create temporary script file
        $tempScript = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.ps1'
        $tempScript = $tempScript -replace '\.tmp\.ps1$', '.ps1'
        
        # Build the full command for the new window
        $fullCommand = @"
# Auto-generated by UFM Interactive Wrapper
# Original script: $($script:MainScriptPath)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

`$host.UI.RawUI.WindowTitle = "UserFolderMigrator - Running"

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  USER FOLDER MIGRATOR - RUNNING IN SEPARATE WINDOW" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Command: $command" -ForegroundColor Gray
Write-Host ""
Write-Host "  IMPORTANT: Do not close this window until the script completes!" -ForegroundColor Yellow
Write-Host ""

try {
    $command
    `$exitCode = `$LASTEXITCODE
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    if (`$exitCode -eq 0) {
        Write-Host "  MIGRATION COMPLETED SUCCESSFULLY! (Exit code: `$exitCode)" -ForegroundColor Green
    } elseif (`$exitCode -in @(1,2)) {
        Write-Host "  MIGRATION COMPLETED WITH PARTIAL SUCCESS (Exit code: `$exitCode)" -ForegroundColor Yellow
    } elseif (`$exitCode -eq 6) {
        Write-Host "  MIGRATION BLOCKED: OneDrive KFM is active. Disable KFM and re-run." -ForegroundColor Red
        Write-Host "  To fix: Disable KFM in OneDrive settings or via Group Policy, then re-run." -ForegroundColor Yellow
        Write-Host "  Expert only: re-run Custom mode and answer Y to Skip KFM block." -ForegroundColor Yellow
    } else {
        Write-Host "  MIGRATION FAILED (Exit code: `$exitCode)" -ForegroundColor Red
    }
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "ERROR: `$(`$_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: `$(`$_.ScriptStackTrace)" -ForegroundColor Gray
    `$exitCode = 99
}

Write-Host ""
Write-Host "Press Enter to close this window..."
Read-Host
exit `$exitCode
"@
        
        $fullCommand | Out-File -FilePath $tempScript -Encoding UTF8
        
        # Determine PowerShell executable
        $pwshPath = if ($PSVersionTable.PSVersion.Major -ge 6) { "pwsh.exe" } else { "powershell.exe" }
        
        # Launch new window
        Start-Process $pwshPath -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`"" -WindowStyle Normal
        
        Write-Status "New window launched! The main script is running separately." -Type "Success"
        Write-Status "This interactive window can be closed or used for other tasks." -Type "Info"
        Write-Status "Temp script: $tempScript" -Type "Info"
        
        # Schedule cleanup of temp script after 10 seconds
        Start-Job -ScriptBlock {
            Start-Sleep -Seconds 10
            Remove-Item $using:tempScript -Force -ErrorAction SilentlyContinue
        } | Out-Null
        
        $exitCode = 0
    }
    
    "3" {
        # ============================================================
        # OPTION 3: RUN IN NEW WINDOW AND WAIT (BLOCKING)
        # ============================================================
        Write-Status "Launching in NEW window and WAITING for completion..." -Type "Info"
        
        # Create temporary script file
        $tempScript = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.ps1'
        $tempScript = $tempScript -replace '\.tmp\.ps1$', '.ps1'
        
        # Build the full command for the new window
        $fullCommand = @"
# Auto-generated by UFM Interactive Wrapper
# Original script: $($script:MainScriptPath)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

`$host.UI.RawUI.WindowTitle = "UserFolderMigrator - Running"

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  USER FOLDER MIGRATOR - RUNNING IN SEPARATE WINDOW" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Command: $command" -ForegroundColor Gray
Write-Host ""
Write-Host "  IMPORTANT: Do not close this window until the script completes!" -ForegroundColor Yellow
Write-Host ""

try {
    $command
    `$exitCode = `$LASTEXITCODE
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    if (`$exitCode -eq 0) {
        Write-Host "  MIGRATION COMPLETED SUCCESSFULLY! (Exit code: `$exitCode)" -ForegroundColor Green
    } elseif (`$exitCode -in @(1,2)) {
        Write-Host "  MIGRATION COMPLETED WITH PARTIAL SUCCESS (Exit code: `$exitCode)" -ForegroundColor Yellow
    } elseif (`$exitCode -eq 6) {
        Write-Host "  MIGRATION BLOCKED: OneDrive KFM is active. Disable KFM and re-run." -ForegroundColor Red
        Write-Host "  To fix: Disable KFM in OneDrive settings or via Group Policy, then re-run." -ForegroundColor Yellow
        Write-Host "  Expert only: re-run Custom mode and answer Y to Skip KFM block." -ForegroundColor Yellow
    } else {
        Write-Host "  MIGRATION FAILED (Exit code: `$exitCode)" -ForegroundColor Red
    }
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "ERROR: `$(`$_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: `$(`$_.ScriptStackTrace)" -ForegroundColor Gray
    `$exitCode = 99
}

Write-Host ""
Write-Host "Press Enter to close this window..."
Read-Host
exit `$exitCode
"@
        
        $fullCommand | Out-File -FilePath $tempScript -Encoding UTF8
        
        # Determine PowerShell executable
        $pwshPath = if ($PSVersionTable.PSVersion.Major -ge 6) { "pwsh.exe" } else { "powershell.exe" }
        
        # Launch new window and wait for it to complete
        Write-Status "Waiting for main script to complete..." -Type "Info"
        
        $process = Start-Process $pwshPath `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`"" `
            -WindowStyle Normal `
            -PassThru `
            -Wait
        
        $exitCode = $process.ExitCode
        
        # Clean up temp script
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
        
        Write-Host ""
        if ($exitCode -eq 0) {
            Write-Status "Migration completed SUCCESSFULLY! (Exit code: $exitCode)" -Type "Success"
        } elseif ($exitCode -in @(1,2)) {
            Write-Status "Migration completed with PARTIAL success (Exit code: $exitCode)" -Type "Warning"
        } elseif ($exitCode -eq 6) {
            Write-Status "MIGRATION BLOCKED: OneDrive Known Folder Move (KFM) is active." -Type "Error"
            Write-Status "KFM prevents safe migration because OneDrive would revert the changes." -Type "Error"
            Write-Status "To fix: Disable KFM in OneDrive settings or via Group Policy, then re-run." -Type "Info"
            Write-Status "If you are certain KFM is disabled, re-run and select Custom -> Skip KFM block." -Type "Warning"
        } else {
            Write-Status "Migration FAILED with exit code: $exitCode" -Type "Error"
        }
    }
    
    default {
        # ============================================================
        # DEFAULT: RUN IN CURRENT WINDOW
        # ============================================================
        Write-Status "Invalid choice. Running in CURRENT window..." -Type "Warning"
        
        try {
            Invoke-Expression $command
            $exitCode = $LASTEXITCODE
        } catch {
            Write-Status "Error executing migration: $($_.Exception.Message)" -Type "Error"
            $exitCode = 99
        }
        
        Write-Host ""
        if ($exitCode -eq 0) {
            Write-Status "Migration completed SUCCESSFULLY!" -Type "Success"
        } elseif ($exitCode -in @(1,2)) {
            Write-Status "Migration completed with PARTIAL success (exit $exitCode)" -Type "Warning"
        } elseif ($exitCode -eq 6) {
            Write-Status "MIGRATION BLOCKED: OneDrive Known Folder Move (KFM) is active." -Type "Error"
            Write-Status "KFM prevents safe migration because OneDrive would revert the changes." -Type "Error"
            Write-Status "To fix: Disable KFM in OneDrive settings or via Group Policy, then re-run." -Type "Info"
            Write-Status "If you are certain KFM is disabled, re-run and select Custom -> Skip KFM block." -Type "Warning"
        } else {
            Write-Status "Migration FAILED with exit code: $exitCode" -Type "Error"
        }
    }
}

# ============================================================
# AUTO-CLEANUP CREDENTIALS
# ============================================================
if ($AutoCleanupCreds -and $runChoice -eq "1") {
    Clear-StoredCredentials
} elseif ($NotificationEmail) {
    Write-Host ""
    Write-Status "Auto-cleanup was disabled. Credentials may still be stored." -Type "Warning"
    Write-Status "To manually clean up, run: cmdkey /delete:UFM_Smtp" -Type "Info"
}

Write-Host ""
Write-Host "Press Enter to exit..."
Read-Host
exit $exitCode