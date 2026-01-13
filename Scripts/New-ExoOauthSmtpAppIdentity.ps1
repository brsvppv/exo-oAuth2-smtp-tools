<#
.SYNOPSIS
  Sets up an Entra app + EXO service principal for SMTP OAuth (XOAUTH2).
  Can be run locally, or remotely via 'irm ... | iex'.

.DESCRIPTION
  Modular setup script for Business Central SMTP OAuth.
  - Creates App Registration & Service Principal
  - Generates Secrets
  - Assigns Permissions (SMTP.Send/SendAs)
  - Remediates SMTP Client Auth posture
  
  Remote Usage (Parameter Object):
  $params = @{ Mailboxes = "info@contoso.com"; AddSendAs = $true }
  $res = irm <url> | iex

  Remote Usage (One-Liner):
  irm <url> | iex; New-ExoOauthSmtpAppIdentity -Mailboxes "info@contoso.com" -AddSendAs

.PARAMETER DisplayName
  App registration display name.
.PARAMETER SecretName
  Friendly name for the client secret.
.PARAMETER YearsValid
  Validity period for the secret.
.PARAMETER Mailboxes
  List of SMTP addresses to authorize.
.PARAMETER MultiTenant
  Multi-tenant app registration.
.PARAMETER AddSendAs
  Grant SendAs permission in addition to FullAccess.
.PARAMETER GrantSmtpPermission
  Automate admin consent for SMTP.Send/SendAsApp.
.PARAMETER SmtpPermission
  Specific permission string (SMTP.Send vs SMTP.SendAsApp).
.PARAMETER EnableOrgSmtp
  Enable global SMTP Client Auth.
.PARAMETER FixMailboxSmtp
  Enable mailbox-specific SMTP Client Auth.
.PARAMETER RetryMax
  Retry attempts for Service Principal propagation.

.EXAMPLE
  # 1. Basic Usage (Minimal)
  # Creates app, secret, and grants FullAccess.
  New-ExoOauthSmtpAppIdentity -Mailboxes "info@contoso.com"

.EXAMPLE
  # 2. Recommended for Business Central (Full Setup)
  # Grants FullAccess AND SendAs, and ensures SMTP Auth is enabled on the mailbox.
  New-ExoOauthSmtpAppIdentity -Mailboxes "sales@contoso.com" -AddSendAs -FixMailboxSmtp

.EXAMPLE
  # 3. Custom Names & Secret Validity
  # Use specific names for the Azure App and Secret, and set secret to expire in 5 years.
  New-ExoOauthSmtpAppIdentity -DisplayName "My ERP Mailer" -SecretName "BC_Secret_2024" -YearsValid 5 -Mailboxes "admin@contoso.com"

.EXAMPLE
  # 4. Global Smtp Fix (Legacy Support)
  # If the tenant has SMTP Auth disabled globally, this switch enables it (use with caution).
  New-ExoOauthSmtpAppIdentity -Mailboxes "legacy@contoso.com" -EnableOrgSmtp

.EXAMPLE
  # 5. Remote "One-Liner" Execution
  # Download and run in memory without saving the file.
  irm https://raw.githubusercontent.com/username/repo/main/New-ExoOauthSmtpAppIdentity.ps1 | iex; New-ExoOauthSmtpAppIdentity -Mailboxes "info@contoso.com" -AddSendAs
#>

function New-ExoOauthSmtpAppIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DisplayName = "Organization SMTP Service",

        [Parameter(Mandatory = $false)]
        [string]$SecretName = "Organization SMTP Secret",

        [Parameter(Mandatory = $false)]
        [int]$YearsValid = 2,

        [Parameter(Mandatory = $true)]
        [string[]]$Mailboxes,

        [Parameter(Mandatory = $false)]
        [switch]$MultiTenant,

        [Parameter(Mandatory = $false)]
        [switch]$AddSendAs,

        [Parameter(Mandatory = $false)]
        [bool]$GrantSmtpPermission = $true,

        [Parameter(Mandatory = $false)]
        [ValidateSet("SMTP.Send", "SMTP.SendAsApp")]
        [string]$SmtpPermission = "SMTP.Send",

        [Parameter(Mandatory = $false)]
        [switch]$EnableOrgSmtp,

        [Parameter(Mandatory = $false)]
        [switch]$FixMailboxSmtp,

        [Parameter(Mandatory = $false)]
        [int]$RetryMax = 8
    )

    # -------------------------------------------------------------------
    # Nested Helpers (Private)
    # -------------------------------------------------------------------
    function Write-Log {
        param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'OK', 'STEP')][string]$Level = 'INFO')
        $ts = (Get-Date).ToString('u')
        $color = switch ($Level) {
            'INFO' { 'Gray' }
            'WARN' { 'DarkYellow' }
            'ERROR' { 'Red' }
            'OK' { 'Green' }
            'STEP' { 'Cyan' }
        }
        # In a function returning data, we use Write-Host for status to avoid polluting the output stream
        # unless checking for non-interactive scenarios.
        Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
    }

    function Initialize-RequiredModule {
        param([string]$Name)
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Write-Log "Installing module: $Name" 'INFO'
            Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
        }
        Import-Module $Name -ErrorAction Stop | Out-Null
        Write-Log "Module loaded: $Name" 'OK'
    }

    # -------------------------------------------------------------------
    # Execution Logic
    # -------------------------------------------------------------------
    try {
        $ErrorActionPreference = 'Stop'
        
        # 1. Module Checks
        Write-Log "Checking required modules..." 'STEP'
        Initialize-RequiredModule -Name Microsoft.Graph.Applications
        Initialize-RequiredModule -Name Microsoft.Graph.Identity.DirectoryManagement
        Initialize-RequiredModule -Name ExchangeOnlineManagement

        # 2. Connect to Graph
        Write-Log "Connecting to Microsoft Graph..." 'STEP'
        $graphScopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Directory.Read.All')
        try {
            # Check existing context or connect
            $ctx = Get-MgContext -ErrorAction SilentlyContinue
            if (-not $ctx) { Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop | Out-Null }
        }
        catch {
            throw "Failed to connect to Microsoft Graph: $_"
        }
        
        $ctx = Get-MgContext
        $org = Get-MgOrganization | Select-Object -First 1 DisplayName, Id, VerifiedDomains
        $TenantName = $org.DisplayName
        $TenantIdGuid = if ($ctx.TenantId) { $ctx.TenantId } else { $org.Id }
        Write-Log "Connected. Tenant: $TenantName ($TenantIdGuid)" 'OK'

        # 3. App Registration
        Write-Log "Creating/Locating App: $DisplayName" 'STEP'
        $existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
        if (-not $existing) {
            $audience = if ($MultiTenant) { 'AzureADMultipleOrgs' } else { 'AzureADMyOrg' }
            $app = New-MgApplication -DisplayName $DisplayName -SignInAudience $audience
            Write-Log "Created App. AppId: $($app.AppId)" 'OK'
        }
        else {
            $app = $existing
            Write-Log "Found Existing App. AppId: $($app.AppId)" 'WARN'
        }
        $ClientId = $app.AppId
        $AppObjectId = $app.Id

        # 4. Client Secret
        Write-Log "Creating Client Secret..." 'STEP'
        $secretParams = @{
            ApplicationId      = $AppObjectId
            PasswordCredential = @{
                displayName = $SecretName
                endDateTime = (Get-Date).AddYears($YearsValid)
            }
        }
        $secret = Add-MgApplicationPassword @secretParams
        $ClientSecret = $secret.SecretText
        Write-Log "Secret created." 'OK'

        # 5. Service Principal
        Write-Log "Ensuring Service Principal..." 'STEP'
        $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue
        if (-not $sp) {
            $sp = New-MgServicePrincipal -AppId $ClientId
            Write-Log "Created Service Principal: $($sp.Id)" 'OK'
        }
        else {
            Write-Log "Found Service Principal: $($sp.Id)" 'WARN'
        }
        $ServiceId = $sp.Id

        # 6. Permissions (SMTP)
        if ($GrantSmtpPermission) {
            Write-Log "Granting SMTP Permission ($SmtpPermission)..." 'STEP'
            $exoSp = Get-MgServicePrincipal -Filter "displayName eq 'Office 365 Exchange Online'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $exoSp) { throw "Could not find 'Office 365 Exchange Online' Service Principal." }

            $smtpRole = $exoSp.AppRoles | Where-Object { $_.Value -eq $SmtpPermission -and $_.AllowedMemberTypes -contains 'Application' }
            if (-not $smtpRole) { throw "Role '$SmtpPermission' not found on EXO Service Principal." }

            $existingAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All | Where-Object { $_.ResourceId -eq $exoSp.Id -and $_.AppRoleId -eq $smtpRole.Id }
            if (-not $existingAssignment) {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ResourceId $exoSp.Id -AppRoleId $smtpRole.Id | Out-Null
                Write-Log "Assigned '$SmtpPermission' (Admin Consent Applied)." 'OK'
            }
            else {
                Write-Log "Role '$SmtpPermission' already assigned." 'WARN'
            }
        }

        # 7. Connect Exchange & Register
        Write-Log "Connecting to Exchange Online..." 'STEP'
        Connect-ExchangeOnline | Out-Null
        
        $registered = $false
        try {
            Get-ServicePrincipal -Identity $ServiceId -ErrorAction Stop | Out-Null
            $registered = $true
        }
        catch {
            New-ServicePrincipal -AppId $ClientId -ServiceId $ServiceId -DisplayName $DisplayName | Out-Null
            Write-Log "Registered Service Principal in EXO." 'OK'
        }

        if (-not $registered) {
            $attempt = 0
            while ($attempt -lt $RetryMax -and -not $registered) {
                Start-Sleep -Seconds 15
                $attempt++
                try {
                    Get-ServicePrincipal -Identity $ServiceId -ErrorAction Stop | Out-Null
                    $registered = $true
                    Write-Log "EXO SP visible (Attempt $attempt)." 'OK'
                }
                catch {
                    Write-Log "Waiting for propagation... ($attempt/$RetryMax)" 'WARN'
                }
            }
            if (-not $registered) { throw "EXO Service Principal failed to propagate." }
        }

        # 8. Posture Checks
        if ($EnableOrgSmtp) {
            $tc = Get-TransportConfig
            if ($tc.SmtpClientAuthenticationDisabled) {
                Write-Log "Enabling Org-wide SMTP Client Auth..." 'WARN'
                Set-TransportConfig -SmtpClientAuthenticationDisabled:$false
                Write-Log "Enabled." 'OK'
            }
        }

        # 9. Mailbox Permissions
        Write-Log "Assigning Mailbox Permissions..." 'STEP'
        foreach ($mbx in $Mailboxes) {
            try {
                Add-MailboxPermission -Identity $mbx -User $ServiceId -AccessRights FullAccess -AutoMapping:$false -ErrorAction Stop | Out-Null
                Write-Log "[$mbx] FullAccess granted." 'OK'
            }
            catch {
                Write-Log "[$mbx] FullAccess failed or exists: $_" 'WARN'
            }

            if ($AddSendAs) {
                try {
                    Add-RecipientPermission -Identity $mbx -Trustee $ServiceId -AccessRights SendAs -Confirm:$false -ErrorAction Stop | Out-Null
                    Write-Log "[$mbx] SendAs granted." 'OK'
                }
                catch {
                    Write-Log "[$mbx] SendAs failed or exists: $_" 'WARN'
                }
            }

            if ($FixMailboxSmtp) {
                try {
                    $cas = Get-CASMailbox -Identity $mbx
                    if ($cas.SmtpClientAuthenticationDisabled) {
                        Set-CASMailbox -Identity $mbx -SmtpClientAuthenticationDisabled:$false
                        Write-Log "[$mbx] SMTP Client Auth Enabled." 'OK'
                    }
                }
                catch {
                    Write-Log "[$mbx] Failed to check CAS settings." 'WARN'
                }
            }
        }

        # Return Object
        $result = [PSCustomObject]@{
            TenantName      = $TenantName
            TenantId        = $TenantIdGuid
            DefaultUPN      = ($org.VerifiedDomains | Where-Object IsDefault).Name
            AppName         = $DisplayName
            ClientId        = $ClientId
            ServiceId       = $ServiceId
            ClientSecret    = $ClientSecret
            SmtpServer      = "smtp.office365.com"
            SmtpPort        = 587
            AuthMethod      = "OAuth 2.0"
            Mailboxes       = $Mailboxes
            Permissions     = if ($AddSendAs) { "FullAccess, SendAs" } else { "FullAccess" }
            
            # Helper Commands (Ready-to-Paste)
            CleanupCommand  = "Remove-ExoSmtpAppPrincipal -ClientId `"$ClientId`" -Mailboxes `"$($Mailboxes -join '','' )`""
            TestCommand     = "Test-ExoOauthSmtpAppIdentity -ClientId `"$ClientId`" -Mailboxes `"$($Mailboxes -join '','' )`""
            MailTestCommand = "Invoke-ApiMailNotification -ClientId `"$ClientId`" -TenantID `"$TenantIdGuid`" -SecretValue `"$ClientSecret`" -From `"$($Mailboxes[0])`" -To `"receiver@example.com`" -Subject `"Test Email`" -Content `"Content`""
        }
        
        Write-Log "Setup Complete." 'OK'
        return $result

    }
    catch {
        Write-Log "Critical Error: $_" 'ERROR'
        throw $_
    }
}

# -----------------------------------------------------------------------
# Remote Invocation Guard
# -----------------------------------------------------------------------
# This block detects if parameters are staged in the parent scope (remote execution pattern)
# and automatically invokes the function.
if ($null -ne $params -and $params -is [hashtable]) {
    Write-Verbose "Auto-executing 'New-ExoOauthSmtpAppIdentity' with supplied params..."
    New-ExoOauthSmtpAppIdentity @params
}
