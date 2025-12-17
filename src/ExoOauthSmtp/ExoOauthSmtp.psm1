Import-Module -Name Microsoft.Graph -ErrorAction SilentlyContinue

function Write-Log {
    Param([string]$Message, [ValidateSet('INFO','WARN','ERROR','VERBOSE')] [string]$Level = 'INFO')
    switch ($Level) {
        'INFO'  { Write-Information -MessageData $Message -InformationAction Continue }
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message }
        'VERBOSE' { Write-Verbose $Message }
    }

    if ($Global:LogPath) {
        try {
            $safeMsg = if ($Message -match '(?i)client secret|client_secret|\bsecret\b') { '[REDACTED: secret not written to log]' } else { $Message }
            $line = ('[{0}] [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('o'), $Level, $safeMsg)
            $dir = Split-Path -Path $Global:LogPath -Parent
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Add-Content -Path $Global:LogPath -Value $line -Encoding UTF8
        } catch {
            Write-Warning "Failed to write to log file $($Global:LogPath): $($_.Exception.Message)"
        }
    }
}

# Public function wrappers. The heavy-lifting implementation is placed in private helper functions
# to make the public API concise and testable.

function Get-ExoConfig {
    <#
    .SYNOPSIS
      Retrieve JSON or YAML config with basic validation and environment overrides.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][string]$Path
    )
    # Support: local path, http(s) URL, or raw JSON/YAML string
    if ($Path -match '^https?://') {
        try {
            $raw = Invoke-RestMethod -Uri $Path -UseBasicParsing -ErrorAction Stop
            # If a complex object is returned, convert back to JSON text
            if ($raw -is [System.Management.Automation.PSCustomObject] -or $raw -is [hashtable]) { $raw = $raw | ConvertTo-Json -Depth 10 }
        } catch {
            throw "Failed to download config from $Path : $($_.Exception.Message)"
        }
    } elseif (Test-Path $Path) {
        $raw = Get-Content -Path $Path -Raw
    } else {
        # Treat Path as raw JSON/YAML content passed directly
        $raw = $Path
    }
    if ($Path -match '\.ya?ml$') {
        if (-not (Get-Module -ListAvailable powershell-yaml)) { Install-Module -Name powershell-yaml -Scope CurrentUser -Force -AllowClobber }
        Import-Module powershell-yaml -ErrorAction Stop
        return ConvertFrom-Yaml $raw
    } else {
        try { return $raw | ConvertFrom-Json } catch { throw "Config is not valid JSON or YAML: $($_.Exception.Message)" }
    }
} 

function Test-ConfigWithSchema {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)][object]$Config)
    $schemaPath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\config\schema\smtp-config.schema.json'
    if (-not (Test-Path $schemaPath)) { throw "Schema not found: $schemaPath" }
    $schema = Get-Content -Path $schemaPath -Raw | ConvertFrom-Json
    if ($schema.required) {
        foreach ($req in $schema.required) {
            if (-not $Config.PSObject.Properties.Name -contains $req) { throw "Config is missing required property: $req" }
        }
    }
    return $true
} 

function Install-ModuleIfMissing {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)][string]$Name)
    $mod = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $mod) {
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $Name -ErrorAction Stop
} 

function Protect-SecretToFile {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)][string]$SecretPlainText, [Parameter(Mandatory=$true)][string]$Path)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($SecretPlainText)
    $prot = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $b64 = [Convert]::ToBase64String($prot)
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $b64 | Out-File -FilePath $Path -Encoding ascii -Force
    return $Path
}

function Export-SecretToFilePlain {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)][string]$SecretPlainText, [Parameter(Mandatory=$true)][string]$Path)
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $SecretPlainText | Out-File -FilePath $Path -Encoding ascii -Force
    return $Path
}

function New-ExoOauthSmtpAppIdentity {
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true)][string]$DisplayName,
        [Parameter(Mandatory=$true)][string]$TenantId,
        [Parameter(Mandatory=$false)][string[]]$Mailboxes = @(),
        [int]$SecretValidityYears = 2,
        [switch]$RotateSecret,
        [string]$ConfigPath,
        [string]$ExportProtectedPath,
        [string]$ExportSecretPath,
        [switch]$UseSecretManagement,
        [switch]$ShowSecret,
        [switch]$DryRun,
        [switch]$NonInteractive
    )

    # Basic environment and module setup
    Install-ModuleIfMissing -Name 'Microsoft.Graph'
    if ($UseSecretManagement) { Install-ModuleIfMissing -Name 'Microsoft.PowerShell.SecretManagement'; Install-ModuleIfMissing -Name 'Microsoft.PowerShell.SecretStore' }

    if ($ConfigPath) {
        $cfg = Get-ExoConfig -Path $ConfigPath
        Test-ConfigWithSchema -Config $cfg | Out-Null
        if ($cfg.DisplayName) { $DisplayName = $cfg.DisplayName }
        if ($cfg.TenantId) { $TenantId = $cfg.TenantId }
        if ($cfg.Mailboxes) { $Mailboxes = $cfg.Mailboxes }
        if ($cfg.SecretValidityYears) { $SecretValidityYears = $cfg.SecretValidityYears }
        if ($cfg.ExportProtectedPath) { $ExportProtectedPath = $cfg.ExportProtectedPath }
        if ($cfg.ExportSecretPath) { $ExportSecretPath = $cfg.ExportSecretPath }
        if ($cfg.UseSecretManagement -eq $true) { $UseSecretManagement = $true }
    }
    if ($DryRun) {
        Write-Log "Dry run: validating configuration and mailbox availability..." 'INFO'
        # Validate Graph connectivity (best-effort)
        try {
            $ctx = Get-MgContext -ErrorAction SilentlyContinue
            if (-not $ctx) { Write-Log "Not connected to Microsoft Graph; run 'Connect-MgGraph' interactively to fully validate permissions." 'WARN' }
            else { Write-Log "Microsoft Graph context present." 'INFO' }
        } catch { Write-Log "Unable to query Microsoft Graph context: $($_.Exception.Message)" 'WARN' }

        # Validate mailboxes
        foreach ($mb in $Mailboxes) {
            try {
                $exists = Get-Mailbox -Identity $mb -ErrorAction Stop
                Write-Log "Mailbox exists: $mb" 'INFO'
            } catch {
                Write-Log "Mailbox not found or cannot be validated: $mb" 'WARN'
            }
        }

        Write-Log "Dry run complete — no changes were made." 'INFO'
        return @{ DryRun = $true; DisplayName = $DisplayName; TenantId = $TenantId; Mailboxes = $Mailboxes }
    }

    # Idempotent app creation
    $existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    if ($existing) { $app = $existing } else { $app = New-MgApplication -DisplayName $DisplayName }

    $sp = Get-MgServicePrincipal -Filter "AppId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
    if (-not $sp) { $sp = New-MgServicePrincipal -AppId $app.AppId }

    # secrets
    $clientSecret = $null
    if ($RotateSecret -or -not ($app.PasswordCredentials) -or $app.PasswordCredentials.Count -eq 0) {
        $end = (Get-Date).AddYears($SecretValidityYears)
        $secret = New-MgApplicationPassword -ApplicationId $app.Id -DisplayName "Provisioned-$(Get-Date -Format yyyyMMddHHmm)" -EndDateTime $end
        $clientSecret = $secret.SecretText
        if ($ExportProtectedPath) { Protect-SecretToFile -SecretPlainText $clientSecret -Path $ExportProtectedPath | Out-Null }
        if ($ExportSecretPath) { Export-SecretToFilePlain -SecretPlainText $clientSecret -Path $ExportSecretPath | Out-Null }
        if ($UseSecretManagement) { try { Set-Secret -Name "${DisplayName}_ClientSecret" -Secret $clientSecret -Vault SecretStore -ErrorAction Stop } catch { } }
    }

    return @{ Application = $app; ServicePrincipal = $sp; ClientSecret = $clientSecret }
}

function Get-ProtectedSecretFromFile {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true)][string]$Path)
    $b64 = Get-Content -Path $Path -Raw
    $bytes = [Convert]::FromBase64String($b64)
    $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}

# Note: the previous wrapper that delegated to the v3 script was removed so the
# in-module implementation (which supports -DryRun) is the active command. If
# a single-sourcing strategy is desired in the future, consider refactoring
# shared logic into private helper functions instead of redefining the public
# cmdlet here.


Export-ModuleMember -Function *
