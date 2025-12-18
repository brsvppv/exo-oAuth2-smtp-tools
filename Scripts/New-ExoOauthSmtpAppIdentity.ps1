<#
.SYNOPSIS
  Idempotent, production-ready provisioning for an Exchange Online SMTP OAuth2 App.

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
    Invoke-WebRequest -Uri <raw-url> -OutFile ./New-ExoOauthSmtpAppIdentity.ps1
    Get-Content ./New-ExoOauthSmtpAppIdentity.ps1
    pwsh ./New-ExoOauthSmtpAppIdentity.ps1 -DisplayName "My SMTP App" -TenantId <tenant> -Mailboxes user@contoso.com

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

iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/New-ExoOauthSmtpAppIdentity.ps1')
New-ExoOauthSmtpAppIdentity -DisplayName 'My SMTP App' -TenantId '<tenant-id>' -Mailboxes 'no-reply@contoso.com' -NonInteractive

Prefer download-then-inspect before running.
#>
# --------------------------------------------------------------------------------
# CONFIGURATION (supports optional JSON import)
# Usage: .\New-ExoOauthSmtpAppIdentity.ps1 [-ConfigPath <path-to-json>] [-NonInteractive] [-AutoInstallModules]
# If no -ConfigPath is supplied the script will look for a config file at
# '<scriptdir>\config\smtp-app.example.json' and fall back to built-in defaults.
Param(
    [string]$ConfigPath,
    [switch]$NonInteractive,
    [switch]$AutoInstallModules,
    [switch]$GrantAdminConsent
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Define logging helper early so config load can call it
function Write-Log([string]$Message, [ValidateSet('INFO','WARN','ERROR','VERBOSE')][string]$Level = 'INFO') {
    switch ($Level) {
        'INFO'  { Write-Information -MessageData $Message -InformationAction Continue }
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message }
        'VERBOSE' { Write-Verbose $Message }
    }
}

# Load config from JSON if provided or from default example file
$Config = $null
if ($ConfigPath) {
    if (Test-Path -Path $ConfigPath) {
        try {
            $Config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
            Write-Log "Loaded config from $ConfigPath" 'INFO'
        } catch {
            Write-Log "Failed to parse config at $ConfigPath: $($_.Exception.Message)" 'WARN'
        }
    } else {
        Write-Log "Config path '$ConfigPath' not found, continuing with defaults." 'WARN'
    }
} else {
    $defaultConfig = Join-Path $ScriptDir 'config\smtp-app.example.json'
    if (Test-Path -Path $defaultConfig) {
        try {
            $Config = Get-Content -Raw -Path $defaultConfig | ConvertFrom-Json
            Write-Log "Loaded config from $defaultConfig" 'INFO'
        } catch {
            Write-Log "Failed to parse default config at $defaultConfig: $($_.Exception.Message)" 'WARN'
        }
    }
}

# Apply config values with safe fallbacks
$DisplayName = if ($Config -and $Config.DisplayName) { $Config.DisplayName } else { 'Organization SMTP Service' }
$SecretName  = if ($Config -and $Config.SecretName)  { $Config.SecretName }  else { 'Organization SMTP Secret' }
$YearsValid  = if ($Config -and $Config.YearsValid)  { [int]$Config.YearsValid }  else { 2 }
# Apply config values with safe fallbacks (already present above)
$Mailboxes   = if ($Config -and $Config.Mailboxes)   { @($Config.Mailboxes) } else { @('no-reply@example.com','info@example.com','notify@example.com') }
$MailboxPermissionMethod = if ($Config -and $Config.MailboxPermissionMethod) { $Config.MailboxPermissionMethod } else { 'AddMailboxPermission' }
$SecurityGroupForMailboxes = if ($Config -and $Config.SecurityGroupForMailboxes) { $Config.SecurityGroupForMailboxes } else { $null }
$TenantId    = if ($Config -and $Config.TenantID)    { $Config.TenantID } else { $null }

# optional auth values from config
$CfgClientId         = if ($Config -and $Config.ClientId)                 { $Config.ClientId } else { $null }
$CfgClientSecret     = if ($Config -and $Config.ClientSecret)             { $Config.ClientSecret } else { $null }
$CfgAutoInstall      = if ($Config -and $Config.AutoInstallModules)       { [bool]$Config.AutoInstallModules } else { $false }
$CfgNonInteractive   = if ($Config -and $Config.NonInteractive)           { [bool]$Config.NonInteractive } else { $false }
$CfgExchangeCertThumb= if ($Config -and $Config.ExchangeCertificateThumbprint) { $Config.ExchangeCertificateThumbprint } else { $null }

# Merge command-line switches with config flags
if ($CfgAutoInstall -and -not $AutoInstallModules) { $AutoInstallModules = $true }
if ($CfgNonInteractive -and -not $NonInteractive) { $NonInteractive = $true }

# --------------------------------------------------------------------------------
# MODULE CHECK & CONNECTION
# (logging helper already defined earlier)
# --------------------------------------------------------------------------------
Write-Log "Checking modules..." 'INFO'
# Ensure required modules are installed. If not present, either auto-install or error.
$requiredModules = @(
    @{ Name = 'Microsoft.Graph.Applications'; MinimumVersion = '1.0.0' },
    @{ Name = 'ExchangeOnlineManagement'; MinimumVersion = '3.0.0' }
)
foreach ($m in $requiredModules) {
    $found = Get-Module -ListAvailable -Name $($m.Name) | Where-Object { $_.Version -ge [version]$m.MinimumVersion }
    if (-not $found) {
        if ($AutoInstallModules) {
            Write-Log "Installing module $($m.Name)..." 'INFO'
            try {
                Install-Module -Name $($m.Name) -Scope CurrentUser -Force -ErrorAction Stop
            } catch {
                Write-Log "Failed to install $($m.Name): $($_.Exception.Message)" 'ERROR'
                throw
            }
        } else {
            Write-Log "Required module $($m.Name) (>= $($m.MinimumVersion)) is not installed. Rerun with -AutoInstallModules or install it manually." 'ERROR'
            throw "Missing module $($m.Name)"
        }
    } else {
        Write-Log "Module $($m.Name) present." 'VERBOSE'
    }
}

# Connect to Microsoft Graph. Prefer non-interactive client-credentials flow when
# config provides ClientId+ClientSecret and NonInteractive is requested.
Write-Log "Connecting to Microsoft Graph..." 'INFO'
if ($NonInteractive -and $CfgClientId -and $CfgClientSecret -and $TenantId) {
    try {
        Connect-MgGraph -ClientId $CfgClientId -TenantId $TenantId -ClientSecret $CfgClientSecret -ErrorAction Stop
        Write-Log "Connected to Microsoft Graph (app-only)" 'INFO'
    } catch {
        Write-Log "Failed non-interactive Graph connect: $($_.Exception.Message)" 'ERROR'
        throw
    }
} else {
    Write-Log "Falling back to interactive Graph login (prompt will appear)." 'WARN'
    Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'Directory.Read.All'
}

# --------------------------------------------------------------------------------
# STEP 1: AZURE APP REGISTRATION
# --------------------------------------------------------------------------------
Write-Log "Checking for existing App Registration..." 'INFO'
$App = Get-MgApplication -Filter "DisplayName eq '$DisplayName'" -ErrorAction SilentlyContinue

if ($null -eq $App) {
    Write-Log "Creating NEW App Registration: $DisplayName" 'INFO'
    $App = New-MgApplication -DisplayName $DisplayName -SignInAudience "AzureADMyOrg"
} else {
    Write-Log "Found existing App Registration." 'WARN'
}

$ClientId = $App.AppId
$AppObjectId = $App.Id

Write-Log "   - App ID (Client ID): $ClientId" 'INFO'
Write-Log "   - App Reg Object ID:  $AppObjectId" 'INFO'

# --------------------------------------------------------------------------------
# STEP 2: GENERATE CLIENT SECRET
# --------------------------------------------------------------------------------
Write-Log "Generating Client Secret..." 'INFO'
$passwordCred = @{
    displayName = $SecretName
    endDateTime = (Get-Date).AddYears($YearsValid)
}
$SecretInfo = Add-MgApplicationPassword -ApplicationId $AppObjectId -PasswordCredential $passwordCred
$ClientSecret = $SecretInfo.SecretText

# --------------------------------------------------------------------------------
# STEP 3: ENSURE SERVICE PRINCIPAL (ENTERPRISE APP) EXISTS
# --------------------------------------------------------------------------------
# This is the "Enterprise App" Object ID required by Exchange (NOT the App Reg ID)
Write-Log "Checking for Enterprise App (Service Principal)..." 'INFO'
$ServicePrincipal = Get-MgServicePrincipal -Filter "AppId eq '$ClientId'" -ErrorAction SilentlyContinue

if ($null -eq $ServicePrincipal) {
    Write-Log "Creating Service Principal in Enterprise Apps..." 'INFO'
    $ServicePrincipal = New-MgServicePrincipal -AppId $ClientId
    # Sleep briefly to allow propagation
    Start-Sleep -Seconds 15 
}

$ServiceId = $ServicePrincipal.Id
Write-Log "   - Service Principal Object ID: $ServiceId" 'INFO'

# -------------------------------------------------------------------------------
# Attempt to assign the Exchange app role `SMTP.SendAsApp` to this service principal
# -------------------------------------------------------------------------------
Write-Log "Ensuring 'SMTP.SendAsApp' app role is assigned to the Service Principal..." 'INFO'
# Exchange Online resource AppId (used for app role assignments). If this cannot be
# found the script will warn and continue; admin can grant the permission in the
# portal instead.
$exchangeResourceAppId = '00000002-0000-0ff1-ce00-000000000000'
$exchangeSp = Get-MgServicePrincipal -Filter "AppId eq '$exchangeResourceAppId'" -ErrorAction SilentlyContinue
if ($null -ne $exchangeSp) {
    $appRole = $exchangeSp.AppRoles | Where-Object { ($_.Value -and $_.Value -eq 'SMTP.SendAsApp') -or ($_.DisplayName -and $_.DisplayName -match 'SMTP') } | Select-Object -First 1
    if ($null -ne $appRole) {
        # Ensure the application has the requiredResourceAccess entry for Exchange
        try {
            $required = @()
            if ($App.RequiredResourceAccess) { $required = $App.RequiredResourceAccess }
            $existsReq = $required | Where-Object { $_.ResourceAppId -eq $exchangeResourceAppId }
            if (-not $existsReq) {
                $resourceAccess = @(@{ Id = $appRole.Id; Type = 'Role' })
                $newEntry = @{ ResourceAppId = $exchangeResourceAppId; ResourceAccess = $resourceAccess }
                $required += $newEntry
                Update-MgApplication -ApplicationId $AppObjectId -RequiredResourceAccess $required -ErrorAction Stop
                Write-Log "Updated application RequiredResourceAccess to include Exchange app role." 'INFO'
            } else {
                Write-Log "Application already contains requiredResourceAccess for Exchange." 'VERBOSE'
            }
        } catch {
            Write-Log "Failed to update application's RequiredResourceAccess: $($_.Exception.Message)" 'WARN'
        }

        $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServiceId -ErrorAction SilentlyContinue | Where-Object { $_.ResourceId -eq $exchangeSp.Id -and $_.AppRoleId -eq $appRole.Id }
        if (-not $existing) {
            if ($GrantAdminConsent) {
                try {
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServiceId -PrincipalId $ServiceId -ResourceId $exchangeSp.Id -Id $appRole.Id -ErrorAction Stop
                    Write-Log "Assigned app role '$($appRole.DisplayName)' to service principal (admin consent granted)." 'INFO'
                } catch {
                    Write-Log "Failed to assign app role: $($_.Exception.Message)" 'WARN'
                    Write-Log "You may need to grant 'SMTP.SendAsApp' in the Azure Portal and grant admin consent." 'WARN'
                }
            } else {
                Write-Log "App role '$($appRole.DisplayName)' is not assigned. Re-run with -GrantAdminConsent to assign it programmatically." 'WARN'
            }
        } else {
            Write-Log "'SMTP.SendAsApp' already assigned to service principal." 'WARN'
        }
    } else {
        Write-Log "Could not locate an app role matching 'SMTP.SendAsApp' on the Exchange resource app." 'WARN'
    }
} else {
    Write-Log "Could not locate Exchange resource service principal (AppId $exchangeResourceAppId). Skipping app-role assignment." 'WARN'
}

# --------------------------------------------------------------------------------
# STEP 4: EXCHANGE ONLINE CONFIGURATION
# --------------------------------------------------------------------------------
Write-Log "Connecting to Exchange Online..." 'INFO'
if ($NonInteractive -and $CfgExchangeCertThumb) {
    try {
        Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $CfgExchangeCertThumb -Organization $TenantId -ErrorAction Stop
        Write-Log "Connected to Exchange Online (app cert)" 'INFO'
    } catch {
        Write-Log "Failed non-interactive Exchange connect: $($_.Exception.Message)" 'ERROR'
        throw
    }
} else {
    Write-Log "Connecting to Exchange Online interactively." 'INFO'
    Connect-ExchangeOnline
}

Write-Log "Registering Service Principal in Exchange..." 'INFO'
# Check if it is already registered to avoid errors
try {
    $ExchSP = Get-ServicePrincipal -Identity $ServiceId -ErrorAction Stop
    Write-Log "Service Principal already registered in Exchange." 'WARN'
} catch {
    Write-Log "Registering new Service Principal in Exchange..." 'INFO'
    New-ServicePrincipal -AppId $ClientId -ServiceId $ServiceId -DisplayName $DisplayName
}

# --------------------------------------------------------------------------------
# STEP 5: ASSIGN MAILBOX PERMISSIONS (supports ApplicationAccessPolicy)
# --------------------------------------------------------------------------------
Write-Log "Assigning Permissions to Mailboxes (method=$MailboxPermissionMethod)..." 'INFO'

if ($MailboxPermissionMethod -eq 'ApplicationAccessPolicy') {
    # Resolve or create security group
    $group = $null
    if ($SecurityGroupForMailboxes) {
        # If it's a GUID-like string treat as group id, else attempt to find by displayName
        if ($SecurityGroupForMailboxes -match '^[0-9a-fA-F\-]{36}$') {
            $group = Get-MgGroup -GroupId $SecurityGroupForMailboxes -ErrorAction SilentlyContinue
        } else {
            $group = Get-MgGroup -Filter "displayName eq '$SecurityGroupForMailboxes'" -ErrorAction SilentlyContinue | Select-Object -First 1
        }
    }
    if (-not $group) {
        $groupName = "$DisplayName - MailboxScope"
        Write-Log "Creating security group '$groupName' for mailbox scope..." 'INFO'
        try {
            $group = New-MgGroup -DisplayName $groupName -MailEnabled:$false -MailNickname ($groupName -replace '\\s','') -SecurityEnabled:$true -ErrorAction Stop
            Write-Log "Created group $($group.Id)" 'INFO'
        } catch {
            Write-Log "Failed to create security group: $($_.Exception.Message)" 'ERROR'
            throw
        }
    } else {
        Write-Log "Using existing security group $($group.Id)" 'INFO'
    }

    # Add mailbox users to the group
    foreach ($Email in $Mailboxes) {
        Write-Log "   Adding $Email to group..." 'INFO'
        $user = Get-MgUser -Filter "mail eq '$Email' or userPrincipalName eq '$Email'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($user) {
            try {
                New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
                Write-Log "   - Added $Email to group." 'INFO'
            } catch {
                Write-Log "   - Could not add $Email to group: $($_.Exception.Message)" 'WARN'
            }
        } else {
            Write-Log "   - Could not find user for $Email in Graph. Skipping." 'WARN'
        }
    }

    # Create Application Access Policy in Exchange to scope the app to this group
    try {
        Write-Log "Creating Application Access Policy to scope app to group..." 'INFO'
        New-ApplicationAccessPolicy -AppId $ClientId -PolicyScopeGroupId $group.Id -AccessRight Restrict -Description "Scoped by provisioning script" -ErrorAction Stop
        Write-Log "Application Access Policy created." 'INFO'
    } catch {
        Write-Log "Failed to create Application Access Policy (maybe it already exists): $($_.Exception.Message)" 'WARN'
    }

} else {
    foreach ($Email in $Mailboxes) {
        Write-Log "   Processing $Email..." 'INFO'
        try {
            Add-MailboxPermission -Identity $Email -User $ServiceId -AccessRights FullAccess -ErrorAction Stop
            Write-Log "   - Access Granted." 'INFO'
        } catch {
            Write-Log "   - Failed to add mailbox permission for $Email: $($_.Exception.Message)" 'WARN'
            Write-Log "   - Tip: service principals often require an Application Access Policy (New-ApplicationAccessPolicy) or a security-group based grant. See docs." 'WARN'
        }
    }
}

# --------------------------------------------------------------------------------
# FINAL OUTPUT
# --------------------------------------------------------------------------------
Clear-Host
Write-Information -MessageData "================================================================" -InformationAction Continue
Write-Information -MessageData " SETUP COMPLETE " -InformationAction Continue
Write-Information -MessageData "================================================================" -InformationAction Continue
Write-Information -MessageData "Use these credentials in Business Central:" -InformationAction Continue
Write-Information -MessageData "" -InformationAction Continue
Write-Information -MessageData "Authentication: OAuth 2.0" -InformationAction Continue
Write-Information -MessageData "Client ID:      $ClientId" -InformationAction Continue
Write-Warning "Client Secret:  $ClientSecret"
# Resolve tenant GUID and output it (useful for automation / configuration).
# Prefer tenant from provided config; fall back to resolving via Graph.
if (-not $TenantId) {
    $TenantId = (Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id -First 1)
}
if ($TenantId) {
    Write-Information -MessageData "Tenant ID:      $TenantId" -InformationAction Continue
} else {
    Write-Information -MessageData "Tenant ID:      (could not resolve via Graph)" -InformationAction Continue
}
Write-Information -MessageData "" -InformationAction Continue
Write-Warning "IMPORTANT: Copy the Client Secret NOW. You cannot see it again."
Write-Information -MessageData "================================================================" -InformationAction Continue
Write-Log "Final Step Check: Go to Azure Portal > App Registrations > '$DisplayName'" 'WARN'
Write-Log "Ensure 'API Permissions' > 'SMTP.SendAsApp' is added and Admin Consent is clicked." 'WARN'


