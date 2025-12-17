<#
.SYNOPSIS
  Quick wrapper to run the interactive provisioning script via a single `iex (irm)` invocation.

.DESCRIPTION
  This script is intended to be run directly from the web, e.g.:

  iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/quick-run.ps1') ; \
    Quick-Run -TenantId '<tenant-guid>' -DisplayName 'My SMTP App' -Mailboxes 'no-reply@contoso.com,notify@contoso.com' -DryRun

  It downloads the canonical `Run-Interactive-Setup.ps1` script (from the same repo) to a temp file, dot-sources it, and invokes the `Start-InteractiveSetup` helper non-interactively.

.PARAMETER TenantId
  Tenant GUID (required for non-interactive runs).

.PARAMETER DisplayName
  App display name.

.PARAMETER Mailboxes
  Comma-separated list of mailbox addresses.

.PARAMETER SecretStorage
  One of: ShowOnce (default), DPAPI, SecretStore, None

.PARAMETER ExportProtectedPath
  Path to write DPAPI-protected secret file when SecretStorage=DPAPI.

.PARAMETER DryRun
  Validate only, no resources created.

.PARAMETER Force
  Auto-accept module installs in non-interactive mode.

.PARAMETER LogPath
  Optional path to append log file.

.PARAMETER TraceCommands
  Switch to enable verbose command trace (opt-in).
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)][string]$ScriptUrl = 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Run-Interactive-Setup.ps1',
    [Parameter(Mandatory=$false)][string]$TenantId,
    [Parameter(Mandatory=$false)][string]$DisplayName = 'Organization SMTP Service',
    [Parameter(Mandatory=$false)][string]$Mailboxes,
    [Parameter(Mandatory=$false)][ValidateSet('ShowOnce','DPAPI','SecretStore','None')][string]$SecretStorage = 'ShowOnce',
    [Parameter(Mandatory=$false)][string]$ExportProtectedPath,
    [Parameter(Mandatory=$false)][switch]$DryRun,
    [Parameter(Mandatory=$false)][switch]$Force,
    [Parameter(Mandatory=$false)][string]$LogPath,
    [Parameter(Mandatory=$false)][switch]$TraceCommands
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log([string]$Message, [ValidateSet('INFO','WARN','ERROR','VERBOSE')][string]$Level = 'INFO') {
    switch ($Level) {
        'INFO'  { Write-Information -MessageData $Message -InformationAction Continue }
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message }
        'VERBOSE' { Write-Verbose $Message }
    }
} 

# Fetch the main interactive script to a temp file and dot-source it
$TempFile = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ("Run-Interactive-Setup-{0}.ps1" -f ([guid]::NewGuid().ToString()))
Write-Log "Downloading provisioning helper from $ScriptUrl to $TempFile" 'INFO'
try {
    (Invoke-RestMethod -Uri $ScriptUrl -UseBasicParsing -ErrorAction Stop) | Out-File -FilePath $TempFile -Encoding UTF8
} catch {
    Write-Log "Failed to download provisioning helper: $($_.Exception.Message)" 'ERROR'; throw
}

# Dot-source the downloaded script so Start-InteractiveSetup is available
try {
    . $TempFile
} catch {
    Write-Log "Failed to load provisioning helper: $($_.Exception.Message)" 'ERROR'; throw
}

# Prepare parameters
$mbArray = @()
if ($Mailboxes) { $mbArray = $Mailboxes.Split(',') | ForEach-Object { $_.Trim() } }

$invokeParams = @{
    TenantId = $TenantId
    DisplayName = $DisplayName
    Mailboxes = $mbArray
    SecretStorage = $SecretStorage
    ExportProtectedPath = $ExportProtectedPath
    NonInteractive = $true
    Force = $Force.IsPresent
}
if ($DryRun.IsPresent) { $invokeParams['DryRun'] = $true }
if ($LogPath) { $invokeParams['LogPath'] = $LogPath }
if ($TraceCommands.IsPresent) { $invokeParams['TraceCommands'] = $true }

# Validate minimal required values for non-interactive
if ($invokeParams['NonInteractive'] -and -not $invokeParams.TenantId) {
    Write-Log "TenantId is required for NonInteractive mode. Provide -TenantId or use interactive mode." 'ERROR'
    throw 'TenantId missing'
}

Write-Log "Invoking Start-InteractiveSetup (non-interactive) with provided parameters..." 'INFO'
try {
    Start-InteractiveSetup @invokeParams
} catch {
    Write-Log "Provisioning failed: $($_.Exception.Message)" 'ERROR'
    throw
} finally {
    # Cleanup
    try { Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue } catch { }
}
