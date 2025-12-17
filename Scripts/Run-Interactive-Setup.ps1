<#
.SYNOPSIS
  Interactive setup helper to provision an Exchange Online SMTP OAuth2 App via prompts.

.DESCRIPTION
  Designed to be run directly from the web (iex (irm ...)) or downloaded and executed.
  Prompts the operator for required values, optionally installs missing modules, and
  calls `New-ExoOauthSmtpAppIdentity` (module or v3 script) with the supplied choices.

USAGE
  iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Run-Interactive-Setup.ps1')

LOGGING NOTE
  - Console output is always displayed to the operator so you can follow progress and warnings in real time.
  - File logging is optional: pass `-LogPath <path>` to append timestamped logs to a file. Secrets are redacted
    before being written to disk and the one-time client secret is shown on-screen only when applicable.
  - Command tracing is opt-in: pass `-TraceCommands` to enable extra (VERBOSE) trace entries.

EXAMPLES
  # Console-only dry-run (default)
  iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Run-Interactive-Setup.ps1') ; \
    Run-Interactive-Setup -ConfigPath ./config/smtp-app.json -NonInteractive -DryRun

  # Console + file logging
  iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Run-Interactive-Setup.ps1') ; \
    Run-Interactive-Setup -ConfigPath ./config/smtp-app.json -NonInteractive -LogPath 'C:\logs\exo-setup.log'

NOTE
  - For security, prefer download-then-inspect. This script will *ask* before installing modules
    or writing secret files.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)][string]$ConfigPath,
    [Parameter(Mandatory=$false)][string]$ConfigUrl,
    [Parameter(Mandatory=$false)][string]$DisplayName,
    [Parameter(Mandatory=$false)][string]$TenantId,
    [Parameter(Mandatory=$false)][string[]]$Mailboxes,
    [Parameter(Mandatory=$false)][ValidateSet('ShowOnce','DPAPI','SecretStore','None')]
        [string]$SecretStorage = 'ShowOnce',
    [Parameter(Mandatory=$false)][string]$ExportProtectedPath,
    [Parameter(Mandatory=$false)][switch]$UseSecretManagement,
    [Parameter(Mandatory=$false)][switch]$RotateSecret,
    [Parameter(Mandatory=$false)][switch]$ShowSecret,
    [Parameter(Mandatory=$false)][switch]$NonInteractive,
    [Parameter(Mandatory=$false)][switch]$Force,
    [Parameter(Mandatory=$false)][switch]$DryRun,
    [Parameter(Mandatory=$false)][string]$LogPath,
    [Parameter(Mandatory=$false)][switch]$TraceCommands
) 

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Optional file logging (console output always present). Provide -LogPath to enable file logging.
if ($PSBoundParameters.ContainsKey('LogPath')) { $Global:LogPath = $LogPath } else { $Global:LogPath = $null }
$Global:TraceCommands = [bool]$TraceCommands

function Write-Log([string]$Message, [ValidateSet('INFO','WARN','ERROR','VERBOSE')][string]$Level = 'INFO') {
    switch ($Level) {
        'INFO'  { Write-Information -MessageData $Message -InformationAction Continue }
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message }
        'VERBOSE' { Write-Verbose $Message }
    }

    if ($Global:LogPath) {
        try {
            # Prevent secrets and sensitive tokens from being written to disk
            if ($Message -match '(?i)client secret|client_secret|\bsecret\b') {
                $safeMsg = '[REDACTED: secret not written to log]'
            } else { $safeMsg = $Message }
            $line = ('[{0}] [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('o'), $Level, $safeMsg)
            $dir = Split-Path -Path $Global:LogPath -Parent
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Add-Content -Path $Global:LogPath -Value $line -Encoding UTF8
        } catch {
            Write-Warning "Failed to write to log file $($Global:LogPath): $($_.Exception.Message)"
        }
    }
} 

function Read-YesNo([string]$msg, [bool]$defaultYes = $true) {
    $yn = Read-Host "$msg $([string]::Format('({0}/{1})', ($defaultYes ? 'Y' : 'y'), ($defaultYes ? 'n' : 'N')))"
    if ([string]::IsNullOrWhiteSpace($yn)) { return $defaultYes }
    return $yn.ToLower().StartsWith('y')
} 

function Get-Config([string]$Path) {
    # Support local path, http(s) URL, or raw JSON/YAML string
    if ($Path -match '^https?://') {
        try {
            $raw = Invoke-RestMethod -Uri $Path -UseBasicParsing -ErrorAction Stop
            if ($raw -is [System.Management.Automation.PSCustomObject] -or $raw -is [hashtable]) { $raw = $raw | ConvertTo-Json -Depth 10 }
        } catch {
            throw "Failed to download config from $Path : $($_.Exception.Message)"
        }
    } elseif (Test-Path $Path) {
        $raw = Get-Content -Path $Path -Raw
    } elseif ($Path.TrimStart() -match '^[\[{]') {
        # Treat Path as raw JSON/YAML content passed directly
        $raw = $Path
    } else {
        throw "Config file not found: $Path"
    }

    if ($Path -match '\.ya?ml$') {
        if (-not (Get-Module -ListAvailable powershell-yaml)) { Install-Module -Name powershell-yaml -Scope CurrentUser -Force -AllowClobber }
        Import-Module powershell-yaml -ErrorAction Stop
        return ConvertFrom-Yaml $raw
    } else {
        try { return $raw | ConvertFrom-Json } catch { throw "Config is not valid JSON or YAML: $($_.Exception.Message)" }
    }
} 

function Install-ModuleWithConsent([string]$name) {
    if (-not (Get-Module -ListAvailable -Name $name)) {
        if (Read-YesNo "Module '$name' is not installed. Install now?" $true) {
            if ($Global:TraceCommands) { Write-Log "Trace: invoking Install-Module -Name $name" 'VERBOSE' }
            Install-Module -Name $name -Scope CurrentUser -Force -AllowClobber
        } else {
            Write-Log "Skipping install of $name. Script may fail if required." 'WARN'
        }
    }
}  

function Start-InteractiveSetup {
    [CmdletBinding()]
    Param(
        [string]$ConfigPath,
        [string]$ConfigUrl,
        [string]$DisplayName,
        [string]$TenantId,
        [string[]]$Mailboxes,
        [string]$SecretStorage = 'ShowOnce',
        [string]$ExportProtectedPath,
        [switch]$UseSecretManagement,
        [switch]$RotateSecret,
        [switch]$ShowSecret,
        [switch]$NonInteractive,
        [switch]$Force,
        [switch]$DryRun
    )

    Write-Log "Interactive EXO OAuth2 SMTP provisioning helper" 'INFO'
    Write-Log "This will create an App Registration and Service Principal and optionally store secrets." 'INFO' 

    # Initialize defaults and normalize parameters
    $showSecret = $false
    $useSecretManagement = $false
    $exportProtectedPath = $null
    $configPath = $ConfigPath
    $configUrl = $ConfigUrl
    if ($null -eq $Mailboxes) { $Mailboxes = @() } 

    Install-ModuleWithConsent -name 'Microsoft.Graph'
    Install-ModuleWithConsent -name 'ExchangeOnlineManagement' 

    # Ensure we have the implementation available so helper functions like Get-ExoConfig are present
    if (Get-Module -ListAvailable -Name ExoOauthSmtp) { Import-Module ExoOauthSmtp -ErrorAction Stop } else {
        # Try to dot-source v3 if available
        $v3 = Join-Path -Path $PSScriptRoot -ChildPath 'New-ExoOauthSmtpAppIdentity_v3.ps1'
        if (Test-Path $v3) { . $v3 } else { Write-Error "Cannot find module or v3 script. Please ensure 'ExoOauthSmtp' module or 'New-ExoOauthSmtpAppIdentity_v3.ps1' is present."; return }
    }

    # Load existing example config if available
    $existing = if (Test-Path (Join-Path -Path $PSScriptRoot -ChildPath '..\config\smtp-app.json')) { Get-Content -Raw -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\config\smtp-app.json') | ConvertFrom-Json } else { $null }

    # If NonInteractive mode and ConfigUrl or ConfigPath provided, skip prompts
    if ($NonInteractive -and ($ConfigPath -or $ConfigUrl -or ($DisplayName -and $TenantId))) {
        # prefer config file/url
        if ($ConfigPath) {
            $cfg = Load-Config -Path $ConfigPath
        } elseif ($ConfigUrl) {
            $cfg = Load-Config -Path $ConfigUrl
        } else {
            $cfg = @{ DisplayName = $DisplayName; TenantId = $TenantId; Mailboxes = $Mailboxes }
        }
        if ($cfg.DisplayName) { $DisplayName = $cfg.DisplayName }
        if ($cfg.TenantId) { $TenantId = $cfg.TenantId }
        if ($cfg.Mailboxes) { $Mailboxes = $cfg.Mailboxes }
    }

    # Validate required items in non-interactive mode
    if ($NonInteractive) {
        if (-not $DisplayName) { Throw 'DisplayName is required in NonInteractive mode.' }
        if (-not $TenantId) { Throw 'TenantId is required in NonInteractive mode.' }
        if (-not $Mailboxes -or $Mailboxes.Count -eq 0) { Throw 'Mailboxes list is required in NonInteractive mode; provide -Mailboxes or a config file with Mailboxes.' }
    }
    
    if ($DryRun) { Write-Log "Running as dry-run: validation only, no resources will be created." 'INFO' }


    # CONFIG ENTRY
    if (-not $NonInteractive) {
        Write-Log "How would you like to provide configuration details?" 'INFO'
        Write-Log "1) Use existing local config file (e.g., ./config/smtp-app.json)" 'INFO'
        Write-Log "2) Provide a remote config URL (raw JSON/YAML) — the script will download it" 'INFO'
        Write-Log "3) Enter values interactively now (prompts)" 'INFO' 
        $cfgChoice = Read-Host "Choose 1/2/3" -Default '3'

        switch ($cfgChoice) {
            '1' {
                $configPath = Read-Host "Enter local config path (relative or absolute)" -Default './config/smtp-app.json'
                if (-not (Test-Path $configPath)) { Write-Log "Config not found at $configPath" 'ERROR'; return }
                        $cfg = Get-Config -Path $configPath
                    $DisplayName = $cfg.DisplayName
                    $TenantId = $cfg.TenantId
                    $Mailboxes = $cfg.Mailboxes
            }
            '2' {
                $configUrl = Read-Host "Enter config URL (http(s) raw JSON/YAML)"
                try {
                    $cfg = Get-Config -Path $configUrl
                } catch {
                    Write-Log "Failed to download/parse config: $($_.Exception.Message)" 'ERROR'; return
                }
                # write to temp file to pass into provisioning if needed
                $tmp = [IO.Path]::GetTempFileName() + '.json'
                $cfg | ConvertTo-Json -Depth 10 | Out-File -FilePath $tmp -Encoding utf8
                $configPath = $tmp
                $DisplayName = $cfg.DisplayName
                $TenantId = $cfg.TenantId
                $Mailboxes = $cfg.Mailboxes
            }
            default {
                $defaultDisplay = if ($existing -and $existing.DisplayName) { $existing.DisplayName } else { '' }
                $defaultTenant = if ($existing -and $existing.TenantId) { $existing.TenantId } else { '' }
                $defaultMailboxes = if ($existing -and $existing.Mailboxes) { ($existing.Mailboxes -join ',') -replace '\s','' } else { '' }

                $DisplayName = Read-Host "Display Name for App (e.g. 'Organization SMTP Service')" -Default $defaultDisplay
                $TenantId = Read-Host "Tenant ID (GUID)" -Default $defaultTenant
                $mailboxesRaw = Read-Host "Comma-separated list of mailbox addresses to validate/assign (e.g. no-reply@contoso.com,notify@contoso.com)" -Default $defaultMailboxes
                $Mailboxes = if ($mailboxesRaw) { $mailboxesRaw.Split(',') | ForEach-Object { $_.Trim() } } else { @() }
                # create a temp config file to pass to provisioning for improved traceability
                $tmp = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ("smtp-app-{0}.json" -f ([guid]::NewGuid().ToString()))
                @{ DisplayName = $DisplayName; TenantId = $TenantId; Mailboxes = $Mailboxes; SecretValidityYears = 2 } | ConvertTo-Json -Depth 6 | Out-File -FilePath $tmp -Encoding utf8
                $configPath = $tmp
            }
        }
    } else {
        # Non-interactive but ensure required items are present
        if ($ConfigPath) {
            $cfg = Load-Config -Path $ConfigPath; $DisplayName = $cfg.DisplayName; $TenantId = $cfg.TenantId; $Mailboxes = $cfg.Mailboxes
            if ($NonInteractive -and -not $TenantId) { Throw "Config at $ConfigPath must include TenantId in NonInteractive mode." }
        }
        elseif ($ConfigUrl) {
            $cfg = Load-Config -Path $ConfigUrl; $DisplayName = $cfg.DisplayName; $TenantId = $cfg.TenantId; $Mailboxes = $cfg.Mailboxes; $tmp = [IO.Path]::GetTempFileName() + '.json'; $cfg | ConvertTo-Json -Depth 10 | Out-File -FilePath $tmp -Encoding utf8; $configPath = $tmp
            if ($NonInteractive -and -not $TenantId) { Throw "Config at $ConfigUrl must include TenantId in NonInteractive mode." }
        }
        else { if (-not ($DisplayName -and $TenantId)) { Throw 'In NonInteractive mode you must provide -ConfigPath, -ConfigUrl, or supply -DisplayName and -TenantId parameters.' } }
    }

if ($PSBoundParameters.ContainsKey('RotateSecret')) {
    $rotate = [bool]$RotateSecret
} elseif ($NonInteractive) {
    # Default in NonInteractive mode to creating/rotating secret unless explicit flag provided
    $rotate = $true
} else {
    $rotate = Read-YesNo "Create or rotate client secret now?" $true
} 

if ($NonInteractive) {
    switch ($SecretStorage) {
        'ShowOnce' { $showSecret = $true }
        'DPAPI' { $showSecret = $false; if ($ExportProtectedPath) { $exportProtectedPath = $ExportProtectedPath } }
        'SecretStore' { $showSecret = $false; $useSecretManagement = $true }
        'None' { $showSecret = $false }
        default { $showSecret = $true }
    }
    # If SecretStore selected in non-interactive mode, ensure modules are available (try auto-install if Force set)
    if ($useSecretManagement) {
        if (-not (Get-Module -ListAvailable Microsoft.PowerShell.SecretManagement)) {
            if ($Force) { Install-Module -Name Microsoft.PowerShell.SecretManagement -Scope CurrentUser -Force -AllowClobber }
            else { Write-Log "SecretManagement not available. Rerun interactive to install or set -Force to auto-install." 'WARN'; return }
        }
        if (-not (Get-Module -ListAvailable Microsoft.PowerShell.SecretStore)) {
            if ($Force) { Install-Module -Name Microsoft.PowerShell.SecretStore -Scope CurrentUser -Force -AllowClobber; Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault -ErrorAction SilentlyContinue }
            else { Write-Log "SecretStore not available. Rerun interactive to install or set -Force to auto-install." 'WARN'; return }
        }
    }
} else {
    Write-Log "How would you like to store the created client secret? Choose one option:" 'INFO'
    Write-Log "  1) Show on screen once (operator must copy)" 'INFO'
    Write-Log "  2) Export a DPAPI-protected file (local, CurrentUser)" 'INFO'
    Write-Log "  3) Store in SecretManagement (SecretStore or configured vault)" 'INFO'
    Write-Log "  4) Do not store; operator will set env var or other vault manually" 'INFO' 
    $choice = Read-Host "Choose 1/2/3/4" -Default '1'

    $exportProtectedPath = $null
    $useSecretManagement = $false
    switch ($choice) {
        '1' { $showSecret = $true }
        '2' {
            $showSecret = $false
            $exportProtectedPath = Read-Host "Enter full path to write protected file (e.g. C:\secrets\smtp_secret.prot)"
        }
        '3' {
            $showSecret = $false
            $useSecretManagement = $true
            # Offer to register SecretStore if missing
            if (-not (Get-Module -ListAvailable Microsoft.PowerShell.SecretManagement)) {
                if (Read-YesNo "SecretManagement not found. Install and register local SecretStore?" $true) {
                    Install-Module -Name Microsoft.PowerShell.SecretManagement -Scope CurrentUser -Force -AllowClobber
                    Install-Module -Name Microsoft.PowerShell.SecretStore -Scope CurrentUser -Force -AllowClobber
                    Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault -ErrorAction SilentlyContinue
                } else { Write-Log "Proceeding without SecretManagement; secret will not be stored." 'WARN' }
            }
        }
        default { $showSecret = $true }
    }
}

Write-Log "Summary:" 'INFO'
Write-Log " DisplayName: $DisplayName" 'INFO'
Write-Log " TenantId:    $TenantId" 'INFO'
Write-Log " Mailboxes:   $($Mailboxes -join ', ')" 'INFO'
Write-Log " RotateSecret:$rotate, SecretStore:$useSecretManagement, ExportProtectedPath:$exportProtectedPath" 'INFO'

if (-not (Read-YesNo "Proceed with provisioning?" $true)) { Write-Log "Cancelled by user." 'WARN'; return }

    # Validate TenantId appears to be a GUID
    if ($TenantId -and ($TenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')) {
        if (-not (Read-YesNo "TenantId does not look like a GUID. Proceed anyway?" $false)) { Write-Log "Cancelled due to invalid TenantId." 'ERROR'; return }
    }

    # Confirm mailboxes if any
    if ($Mailboxes -and $Mailboxes.Count -gt 0) {
        Write-Log "Mailboxes to validate/assign: $($Mailboxes -join ', ')" 'INFO'
        if (-not $Force -and -not $NonInteractive) {
            if (-not (Read-YesNo "Continue and attempt to register/assign permissions for these mailboxes?" $true)) { Write-Log "Cancelled by user." 'WARN'; return }
        }
    } else {
        Write-Log "Warning: No mailboxes provided. The script will create the app and SP but will not assign mailbox permissions." 'WARN'
        if (-not $NonInteractive -and -not (Read-YesNo "Continue anyway?" $false)) { Write-Log "Cancelled by user." 'WARN'; return }
    }



try {
    # If we have a configPath (local temp or user-provided), pass it in to prefer file-driven configuration
    $callArgs = @{ DisplayName = $DisplayName; TenantId = $TenantId; Mailboxes = $Mailboxes; RotateSecret = $rotate; ExportProtectedPath = $exportProtectedPath; UseSecretManagement = $useSecretManagement; ShowSecret = $showSecret; NonInteractive = $true; DryRun = $DryRun }
    if ($configPath) { $callArgs.Add('ConfigPath',$configPath) }

    # Log the planned invocation (sanitized: redact potential secrets)
    $logArgs = @{}
    foreach ($k in $callArgs.Keys) {
        if ($k -match 'Secret|Password') { $logArgs[$k] = '***REDACTED***' } else { $logArgs[$k] = $callArgs[$k] }
    }
    try { $s = $logArgs | ConvertTo-Json -Depth 4 -Compress } catch { $s = $logArgs -join ',' }
    Write-Log "Calling New-ExoOauthSmtpAppIdentity with args: $s" 'INFO'
    if ($Global:TraceCommands) { Write-Log "Trace: invoking New-ExoOauthSmtpAppIdentity" 'VERBOSE' }

    $res = New-ExoOauthSmtpAppIdentity @callArgs
    Write-Log "Provisioning completed." 'INFO'
    if ($res.ClientSecret) {
        if ($showSecret) {
            Write-Log "ONE-TIME CLIENT SECRET (copy now): $($res.ClientSecret)" 'WARN'
        } elseif ($exportProtectedPath) {
            Write-Log "Client secret exported to: $exportProtectedPath" 'INFO'
        } elseif ($useSecretManagement) {
            Write-Log "Client secret stored in SecretManagement vault (SecretStore or configured vault)." 'INFO'
        } else {
            Write-Log "Client secret created but not stored. Set env var EXO_SMTP_CLIENT_SECRET or store in your preferred vault." 'WARN'
        }
    } else {
        Write-Log "No new client secret was created (existing secret kept)." 'WARN'
    }
    Write-Log "Next: if admin consent is required for 'SMTP.SendAsApp', grant it in Azure Portal or via tenant admin flows." 'INFO' 
} catch {
    Write-Error "Provisioning failed: $($_.Exception.Message)"
}
}

# If script invoked directly (including via iex/irm), call the helper with any passed parameters
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Start-InteractiveSetup @PSBoundParameters
    } catch {
        Write-Error "Run-Interactive-Setup failed: $($_.Exception.Message)"
        exit 1
    }
}
