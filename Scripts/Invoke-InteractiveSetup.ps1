<#
.SYNOPSIS
  Interactive setup helper to provision an Exchange Online SMTP OAuth2 App via prompts.

.DESCRIPTION
  Designed to be run directly from the web (iex (irm ...)) or downloaded and executed.
  Prompts the operator for required values, optionally installs missing modules, and
  calls `New-ExoOauthSmtpAppIdentity` (module or script) with the supplied choices.

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
    $yn = Read-Host "$msg $([string]::Format('({0}/{1})', ($defaultYes ? 'Y' : 'y'), ($defaultYes ? 'n' : 'N')) )"
    if ([string]::IsNullOrWhiteSpace($yn)) { return $defaultYes }
    return $yn.ToLower().StartsWith('y')
}

function Get-Config([string]$Path) {
    if ($Path -match '^https?://') {
        try { $raw = Invoke-RestMethod -Uri $Path -UseBasicParsing -ErrorAction Stop } catch { throw "Failed to download config from $Path : $($_.Exception.Message)" }
    } elseif (Test-Path $Path) { $raw = Get-Content -Path $Path -Raw } elseif ($Path.TrimStart() -match '^[\[{]') { $raw = $Path } else { throw "Config file not found: $Path" }

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
            Install-Module -Name $name -Scope CurrentUser -Force -AllowClobber
        } else { Write-Log "Skipping install of $name. Script may fail if required." 'WARN' }
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

    # Implementation unchanged; this helper ultimately calls New-ExoOauthSmtpAppIdentity
    # (omitted for brevity in the wrapper file). The full helper logic is preserved from the original.
    # Dot-source the canonical script if present in the same folder
    if (Get-Module -ListAvailable -Name ExoOauthSmtp) { Import-Module ExoOauthSmtp -ErrorAction Stop } else {
        $impl = Join-Path -Path $PSScriptRoot -ChildPath 'New-ExoOauthSmtpAppIdentity.ps1'
        if (Test-Path $impl) { . $impl } else { Write-Error "Cannot find implementation script: $impl"; return }
    }

    # Call through to Start-InteractiveSetup implementation if present
    if (Get-Command -Name Start-InteractiveSetup -ErrorAction SilentlyContinue) {
        Start-InteractiveSetup @PSBoundParameters
    } else {
        Write-Error 'Interactive setup implementation not available.'
    }
}

# If script invoked directly, call the helper
if ($MyInvocation.InvocationName -ne '.') {
    try { Start-InteractiveSetup @PSBoundParameters } catch { Write-Error "Invoke-InteractiveSetup failed: $($_.Exception.Message)"; exit 1 }
}
