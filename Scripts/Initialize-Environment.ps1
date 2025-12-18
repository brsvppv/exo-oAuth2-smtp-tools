<#
.SYNOPSIS
  Prepare a clean Windows machine to run the provisioning scripts.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log([string]$Message, [ValidateSet('INFO','WARN','ERROR','VERBOSE')][string]$Level = 'INFO') { switch ($Level) { 'INFO' { Write-Information -MessageData $Message -InformationAction Continue } 'WARN' { Write-Warning $Message } 'ERROR' { Write-Error $Message } 'VERBOSE' { Write-Verbose $Message } } }

function Install-ModuleIfMissing { param([string]$Name) if (-not (Get-Module -ListAvailable -Name $Name)) { Write-Log "Installing module: $Name" 'INFO'; Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber } else { Write-Log "Module $Name already present" 'INFO' } }

if ($PSVersionTable.PSVersion.Major -lt 7) { Write-Warning "PowerShell 7+ is recommended. Consider installing from https://aka.ms/powershell" }

$modules = @('Microsoft.Graph','ExchangeOnlineManagement','Microsoft.PowerShell.SecretManagement','Microsoft.PowerShell.SecretStore','powershell-yaml')
foreach ($m in $modules) { Install-ModuleIfMissing -Name $m }

$example = Join-Path -Path $PSScriptRoot -ChildPath '..\config\smtp-app.example.json' | Resolve-Path -ErrorAction SilentlyContinue
$dest = Join-Path -Path $PSScriptRoot -ChildPath '..\config\smtp-app.json'
if (-not (Test-Path $dest)) { Copy-Item -Path $example -Destination $dest; Write-Log "Created config/smtp-app.json from example. Edit it to set your tenant, displayname, and mailboxes." 'INFO' } else { Write-Log "Config file already exists at config/smtp-app.json" 'INFO' }

Write-Log "Bootstrap complete. Next steps:" 'INFO'
Write-Log "1) Edit 'config/smtp-app.json' and set 'DisplayName', 'TenantId' and 'Mailboxes' (array of email addresses)." 'INFO'
Write-Log "2) Save your client secret securely: either set env var 'EXO_SMTP_CLIENT_SECRET' or use 'SecretManagement' or set 'ExportProtectedPath' in config to write a DPAPI-protected file." 'INFO'
Write-Log "3) Run the provisioning (examples):" 'INFO'
Write-Log "   - Dot-source & call function (recommended):" 'INFO'
Write-Log "       iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/New-ExoOauthSmtpAppIdentity.ps1')" 'INFO'
Write-Log "       New-ExoOauthSmtpAppIdentity -ConfigPath ./config/smtp-app.json -NonInteractive" 'INFO'
Write-Log "   - Or call script directly:" 'INFO'
Write-Log "       pwsh .\Scripts\New-ExoOauthSmtpAppIdentity.ps1; New-ExoOauthSmtpAppIdentity -ConfigPath ./config/smtp-app.json -NonInteractive" 'INFO'
