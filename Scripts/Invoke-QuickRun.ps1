<#
.SYNOPSIS
  Quick wrapper to run the interactive provisioning script via a single `iex (irm)` invocation.

.DESCRIPTION
  Downloads the canonical `Invoke-InteractiveSetup.ps1` script, dot-sources it, and invokes the
  `Start-InteractiveSetup` helper non-interactively.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)][string]$ScriptUrl = 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Invoke-InteractiveSetup.ps1',
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
$TempFile = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ("Invoke-InteractiveSetup-{0}.ps1" -f ([guid]::NewGuid().ToString()))
Write-Log "Downloading provisioning helper from $ScriptUrl to $TempFile" 'INFO'
try {
    (Invoke-RestMethod -Uri $ScriptUrl -UseBasicParsing -ErrorAction Stop) | Out-File -FilePath $TempFile -Encoding UTF8
} catch { Write-Log "Failed to download provisioning helper: $($_.Exception.Message)" 'ERROR'; throw }

# Dot-source the downloaded script so Start-InteractiveSetup is available
try { . $TempFile } catch { Write-Log "Failed to load provisioning helper: $($_.Exception.Message)" 'ERROR'; throw }

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

if ($invokeParams['NonInteractive'] -and -not $invokeParams.TenantId) { Write-Log "TenantId is required for NonInteractive mode. Provide -TenantId or use interactive mode." 'ERROR'; throw 'TenantId missing' }

Write-Log "Invoking Start-InteractiveSetup (non-interactive) with provided parameters..." 'INFO'
try { Start-InteractiveSetup @invokeParams } catch { Write-Log "Provisioning failed: $($_.Exception.Message)" 'ERROR'; throw } finally { try { Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue } catch { } }
