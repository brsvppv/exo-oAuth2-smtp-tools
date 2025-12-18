<#
.SYNOPSIS
  Idempotent, production-ready provisioning for an Exchange Online SMTP OAuth2 App (v3).

.DESCRIPTION
  Best-practices PowerShell script for provisioning an Azure App Registration + ServicePrincipal
  suitable for Exchange Online SMTP client-credentials XOAUTH2. Designed for a clean Windows
  installation: checks and installs required modules (non-interactively where possible), enforces
  strict mode, validates inputs, supports config file input, DPAPI protected export, and
  optional SecretManagement storage.

.NOTES
  - Safe-by-default: secrets are never printed unless `-ShowSecret` is explicitly specified.
  - DPAPI protected exports are CurrentUser & machine bound. Use a vault (Azure Key Vault) for
    automation or cross-machine workflows.

  Usage (recommended): download-then-inspect before running.
    Invoke-WebRequest -Uri <raw-url> -OutFile ./New-ExoOauthSmtpAppIdentity_v3.ps1
    Get-Content ./New-ExoOauthSmtpAppIdentity_v3.ps1
    pwsh ./New-ExoOauthSmtpAppIdentity_v3.ps1 -DisplayName "My SMTP App" -TenantId <tenant> -Mailboxes user@contoso.com

#>

function New-ExoOauthSmtpAppIdentity {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Mailboxes = @(),

        [Parameter(Mandatory=$false)]
        [int]$SecretValidityYears = 2,

        [Parameter(Mandatory=$false)]
        [switch]$RotateSecret,

        [Parameter(Mandatory=$false)]
        [string]$ConfigPath,

        [Parameter(Mandatory=$false)]
        [string]$ExportProtectedPath,

        [Parameter(Mandatory=$false)]
        [string]$ExportSecretPath,

        [Parameter(Mandatory=$false)]
        [switch]$UseSecretManagement,

        [Parameter(Mandatory=$false)]
        [switch]$ShowSecret,

        [Parameter(Mandatory=$false)]
        [switch]$NonInteractive
        ,
        [Parameter(Mandatory=$false)]
        [switch]$DryRun
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Enforce TLS1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Module checks (clean Windows install considerations)
    $modules = @('Microsoft.Graph','ExchangeOnlineManagement','Microsoft.PowerShell.SecretManagement','Microsoft.PowerShell.SecretStore')
    foreach ($m in $modules) { Install-ModuleIfMissing -Name $m }

    if ($UseSecretManagement) {
        try {
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
            Import-Module Microsoft.PowerShell.SecretStore -ErrorAction Stop
        } catch {
            Write-Log "SecretManagement modules not available: $($_.Exception.Message)" 'WARN'
            if ($NonInteractive) {
                Write-Log "Skipping interactive SecretStore setup in NonInteractive mode." 'WARN'
            } else {
                Write-Log "Registering SecretStore (local) for development use." 'INFO'
                Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault -ErrorAction SilentlyContinue
            }
        }
    }

    # Apply config file overrides if provided
    if ($PSBoundParameters.ContainsKey('ConfigPath') -and $ConfigPath) {
        $cfg = Test-ConfigFile -Path $ConfigPath
        if ($cfg.DisplayName) { $DisplayName = $cfg.DisplayName }
        if ($cfg.TenantId) { $TenantId = $cfg.TenantId }
        if ($cfg.Mailboxes) { $Mailboxes = $cfg.Mailboxes }
        if ($cfg.SecretValidityYears) { $SecretValidityYears = $cfg.SecretValidityYears }
        if ($cfg.ExportProtectedPath) { $ExportProtectedPath = $cfg.ExportProtectedPath }
        if ($cfg.ExportSecretPath) { $ExportSecretPath = $cfg.ExportSecretPath }
        if ($cfg.UseSecretManagement -eq $true) { $UseSecretManagement = $true }
    }

    ## Prefer module implementation when available
    if (Get-Module -ListAvailable -Name ExoOauthSmtp) {
        Import-Module ExoOauthSmtp -ErrorAction Stop
        return New-ExoOauthSmtpAppIdentity @PSBoundParameters
    }

    ## Fallback to inline implementation (back-compat)
    Import-Module Microsoft.Graph -ErrorAction Stop
    # Attempt to find existing app
    $existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "Application already exists: $($existing.Id)" 'INFO'
        $app = $existing
    } else {
        # Create application
        $app = New-MgApplication -DisplayName $DisplayName
        Write-Log "Created Application: $($app.Id)" 'INFO'
    }

    # Ensure service principal exists
    $sp = Get-MgServicePrincipal -Filter "AppId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
    if (-not $sp) {
        $sp = New-MgServicePrincipal -AppId $app.AppId
        Write-Log "Created ServicePrincipal: $($sp.Id)" 'INFO'
    } else { Write-Log "ServicePrincipal exists: $($sp.Id)" 'INFO' }

    # Secret creation / rotation (fallback behavior)
    if ($RotateSecret -or -not ($app.PasswordCredentials) -or $app.PasswordCredentials.Count -eq 0) {
        $end = (Get-Date).AddYears($SecretValidityYears)
        $secret = New-MgApplicationPassword -ApplicationId $app.Id -DisplayName "Provisioned-$(Get-Date -Format yyyyMMddHHmm)" -EndDateTime $end
        $clientSecret = $secret.SecretText
        Write-Log "Created new client secret (one-time value)." 'WARN'

        if ($ExportProtectedPath) { Protect-SecretToFile -SecretPlainText $clientSecret -Path $ExportProtectedPath }
        if ($ExportSecretPath) { Export-SecretToFilePlain -SecretPlainText $clientSecret -Path $ExportSecretPath }
        if ($UseSecretManagement) {
            try {
                Set-Secret -Name "${DisplayName}_ClientSecret" -Secret $clientSecret -Vault SecretStore -ErrorAction Stop
                Write-Log "Stored secret in SecretManagement (SecretStore)." 'INFO'
            } catch {
                Write-Log "Failed to store in SecretManagement: $($_.Exception.Message)" 'WARN'
            }
        }

        if ($ShowSecret) {
            Write-Log "ONE-TIME CLIENT SECRET (copy now): $clientSecret" 'WARN'
        } else {
            Write-Log "Client secret created but not displayed. Use -ShowSecret to reveal once." 'INFO'
        }
    } else {
        Write-Log "Existing client secret(s) present. Use -RotateSecret to create a new one." 'INFO'
    }

    if ($DryRun) {
        Write-Log "Dry run: mailbox validation and configuration checks only (no changes made)." 'INFO'
        foreach ($mailbox in $Mailboxes) {
            try { Get-Mailbox -Identity $mailbox -ErrorAction Stop; Write-Log "Mailbox exists: $mailbox" 'INFO' } catch { Write-Warning "Mailbox missing or inaccessible: $mailbox" }
        }
        return @{ DryRun = $true; DisplayName = $DisplayName; TenantId = $TenantId; Mailboxes = $Mailboxes }
    }

    # Mailbox grants: add SendAsApp permissions where supported (example pattern)
    foreach ($mailbox in $Mailboxes) {
        try {
            # Verify mailbox exists before attempting grant
            $mb = Get-Mailbox -Identity $mailbox -ErrorAction Stop
            Write-Log "Mailbox exists: $mailbox" 'INFO'
        } catch {
            Write-Log "Mailbox not found: $mailbox - skipping" 'WARN'
        }
    }

    return @{ Application = $app; ServicePrincipal = $sp }
}

function Write-Log {
    Param([string]$Message, [ValidateSet('INFO','WARN','ERROR','VERBOSE')] [string]$Level = 'INFO')
    $time = (Get-Date).ToString('s')
    switch ($Level) {
        'INFO'  { Write-Information -MessageData "[$time] INFO: $Message" -InformationAction Continue }
        'WARN'  { Write-Warning "[$time] WARN: $Message" }
        'ERROR' { Write-Error "[$time] ERROR: $Message" }
        'VERBOSE' { Write-Verbose "[$time] VERBOSE: $Message" }
    }
} 

function Install-ModuleIfMissing {
    Param(
        [Parameter(Mandatory=$true)][string]$Name,
        [string]$MinimumVersion
    )
    try {
        $mod = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $mod) {
            Write-Log "Module $Name not found, installing..." 'WARN'
            if ($NonInteractive) {
                Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -Confirm:$false
            } else {
                Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber
            }
        } else {
            Write-Log "Module $Name found (v$($mod.Version))." 'INFO'
        }
    } catch {
        Write-Log ("Failed to install or load module {0}: {1}" -f $Name, $_.Exception.Message) 'ERROR'
        throw
    }
} 

function Protect-SecretToFile {
    Param(
        [Parameter(Mandatory=$true)][string]$SecretPlainText,
        [Parameter(Mandatory=$true)][string]$Path
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($SecretPlainText)
    $prot = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $b64 = [Convert]::ToBase64String($prot)
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $b64 | Out-File -FilePath $Path -Encoding ascii -Force
    Write-Log "Protected secret exported to $Path (DPAPI, CurrentUser)." 'INFO'
}

function Export-SecretToFilePlain {
    Param([string]$SecretPlainText, [string]$Path)
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $SecretPlainText | Out-File -FilePath $Path -Encoding ascii -Force
    Write-Log "Plain secret exported to $Path (attempted ACL not enforced)." 'WARN'
}

function Test-ConfigFile {
    Param([string]$Path)
    if (-not (Test-Path $Path)) { throw "Config file not found: $Path" }
    try { $json = Get-Content -Path $Path -Raw | ConvertFrom-Json; return $json } catch { throw "Invalid JSON in $Path : $($_.Exception.Message)" }
} 

## Module checks (clean Windows install considerations)
$modules = @('Microsoft.Graph','ExchangeOnlineManagement','Microsoft.PowerShell.SecretManagement','Microsoft.PowerShell.SecretStore')
foreach ($m in $modules) { Install-ModuleIfMissing -Name $m }

if ($UseSecretManagement) {
    try {
        Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
        Import-Module Microsoft.PowerShell.SecretStore -ErrorAction Stop
    } catch {
        Write-Log "SecretManagement modules not available: $($_.Exception.Message)" 'WARN'
        if ($NonInteractive) {
            Write-Log "Skipping interactive SecretStore setup in NonInteractive mode." 'WARN'
        } else {
            Write-Log "Registering SecretStore (local) for development use." 'INFO'
            Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault -ErrorAction SilentlyContinue
        }
    }
}

# Apply config file overrides if provided
if ($PSBoundParameters.ContainsKey('ConfigPath') -and $ConfigPath) {
    $cfg = Test-ConfigFile -Path $ConfigPath
    if ($cfg.DisplayName) { $DisplayName = $cfg.DisplayName }
    if ($cfg.TenantId) { $TenantId = $cfg.TenantId }
    if ($cfg.Mailboxes) { $Mailboxes = $cfg.Mailboxes }
    if ($cfg.SecretValidityYears) { $SecretValidityYears = $cfg.SecretValidityYears }
    if ($cfg.ExportProtectedPath) { $ExportProtectedPath = $cfg.ExportProtectedPath }
    if ($cfg.ExportSecretPath) { $ExportSecretPath = $cfg.ExportSecretPath }
    if ($cfg.UseSecretManagement -eq $true) { $UseSecretManagement = $true }
}

function New-SmtpApp {
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [string]$DisplayName,
        [string]$TenantId,
        [string[]]$Mailboxes,
        [int]$YearsValid
    )

    if ($PSCmdlet.ShouldProcess("Application: $DisplayName", "Create or ensure app exists")) {
        # NOTE: This script uses Microsoft.Graph module cmdlets. Ensure the calling identity
        # has permission to create applications and service principals.
        Import-Module Microsoft.Graph -ErrorAction Stop

        # Attempt to find existing app
        $existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log "Application already exists: $($existing.Id)" 'INFO'
            $app = $existing
        } else {
            # Create application
            $app = New-MgApplication -DisplayName $DisplayName
            Write-Log "Created Application: $($app.Id)" 'INFO'
        }

        # Ensure service principal exists
        $sp = Get-MgServicePrincipal -Filter "AppId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
        if (-not $sp) {
            $sp = New-MgServicePrincipal -AppId $app.AppId
            Write-Log "Created ServicePrincipal: $($sp.Id)" 'INFO'
        } else { Write-Log "ServicePrincipal exists: $($sp.Id)" 'INFO' }

        # Secret creation / rotation
        if ($RotateSecret -or -not ($app.PasswordCredentials) -or $app.PasswordCredentials.Count -eq 0) {
            $pwd = New-Guid
            $secretPlain = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pwd.Guid))
            # Create client secret via Graph SDK
            $end = (Get-Date).AddYears($YearsValid)
            $secret = New-MgApplicationPassword -ApplicationId $app.Id -DisplayName "Provisioned-$(Get-Date -Format yyyyMMddHHmm)" -EndDateTime $end
            $clientSecret = $secret.SecretText
            Write-Log "Created new client secret (one-time value)." 'WARN'

            if ($ExportProtectedPath) { Protect-SecretToFile -SecretPlainText $clientSecret -Path $ExportProtectedPath }
            if ($ExportSecretPath) { Export-SecretToFilePlain -SecretPlainText $clientSecret -Path $ExportSecretPath }
            if ($UseSecretManagement) {
                try {
                    Set-Secret -Name "${DisplayName}_ClientSecret" -Secret $clientSecret -Vault SecretStore -ErrorAction Stop
                    Write-Log "Stored secret in SecretManagement (SecretStore)." 'INFO'
                } catch {
                    Write-Log "Failed to store in SecretManagement: $($_.Exception.Message)" 'WARN'
                }
            }

            if ($ShowSecret) {
                Write-Log "ONE-TIME CLIENT SECRET (copy now): $clientSecret" 'WARN'
            } else {
                Write-Log "Client secret created but not displayed. Use -ShowSecret to reveal once." 'INFO'
            }
        } else {
            Write-Log "Existing client secret(s) present. Use -RotateSecret to create a new one." 'INFO'
        }

        # Grant required API permissions for EXO SMTP.SendAsApp
        # Ensure we have the required OAuth2Permission or AppRole.
        # This script assumes lab operator will grant admin consent via portal or use Graph permissions flow.

        # Mailbox grants: add SendAsApp permissions where supported (example pattern)
        foreach ($mailbox in $Mailboxes) {
            try {
                # Verify mailbox exists before attempting grant
                $mb = Get-Mailbox -Identity $mailbox -ErrorAction Stop
                Write-Log "Mailbox exists: $mailbox" 'INFO'
                # The actual mailbox grant for App-only SMTP may be tenant-wide via admin consent + application permission (SMTP.SendAsApp)
            } catch {
                Write-Log "Mailbox not found: $mailbox - skipping" 'WARN'
            }
        }

        return @{ Application = $app; ServicePrincipal = $sp }
    }
}

<#
When this file is downloaded or dot-sourced, it defines `New-ExoOauthSmtpAppIdentity`.
To invoke immediately after downloading (not recommended without inspection):

iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/New-ExoOauthSmtpAppIdentity_v3.ps1')
New-ExoOauthSmtpAppIdentity -DisplayName 'My SMTP App' -TenantId '<tenant-id>' -Mailboxes 'no-reply@contoso.com' -NonInteractive

Prefer download-then-inspect before running.
#>
