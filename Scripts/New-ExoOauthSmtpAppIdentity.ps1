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
        [string]$SmtpPermission = "SMTP.SendAsApp",

        [Parameter(Mandatory = $false)]
        [switch]$EnableOrgSmtp,

        [Parameter(Mandatory = $false)]
        [switch]$FixMailboxSmtp,

        [Parameter(Mandatory = $false)]
        [int]$RetryMax = 8,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [switch]$NoExportPrompt
    )

    # Nested Helpers (Private)
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

    # Execution Logic
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
            $app = New-MgApplication -DisplayName $DisplayName -SignInAudience $audience -Description "Created by ExoOauthSmtpTools script"
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
            Write-Log "Waiting for SP propagation..." 'INFO'
            Start-Sleep -Seconds 15
        }
        else {
            Write-Log "Found Service Principal: $($sp.Id)" 'WARN'
        }
        $ServiceId = $sp.Id

        # 6. Permissions (SMTP)
        if ($GrantSmtpPermission) {
            Write-Log "Granting SMTP Permission ($SmtpPermission)..." 'STEP'
            # Use the well-known AppId for Exchange Online (globally consistent across all tenants)
            $exoSp = Get-MgServicePrincipal -Filter "AppId eq '00000002-0000-0ff1-ce00-000000000000'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $exoSp) { throw "Could not find Exchange Online Service Principal (AppId: 00000002-0000-0ff1-ce00-000000000000)." }

            $smtpRole = $exoSp.AppRoles | Where-Object { $_.Value -eq $SmtpPermission -and $_.AllowedMemberTypes -contains 'Application' }
            
            # Fallback Logic: If the requested permission isn't found, check for the alternative
            if (-not $smtpRole) {
                Write-Log "Requested role '$SmtpPermission' not found. Checking alternatives..." 'WARN'
                if ($SmtpPermission -eq 'SMTP.Send') {
                    $targetRole = 'SMTP.SendAsApp'
                }
                else {
                    $targetRole = 'SMTP.Send'
                }
                
                $smtpRole = $exoSp.AppRoles | Where-Object { $_.Value -eq $targetRole -and $_.AllowedMemberTypes -contains 'Application' }
                
                if ($smtpRole) {
                    Write-Log "Found alternative role: '$targetRole'. Proceeding..." 'INFO'
                    $SmtpPermission = $targetRole
                }
            }

            if (-not $smtpRole) { throw "Neither 'SMTP.Send' nor 'SMTP.SendAsApp' found on EXO Service Principal." }

            # Update App Manifest with User.Read + SMTP permissions (Visual Fix for Azure Portal)
            Write-Log "Updating App Manifest with permissions..." 'INFO'
            $GraphSP = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction SilentlyContinue
            $UserReadId = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"  # User.Read delegated scope
            
            $ResourceAccess = @(
                @{
                    ResourceAppId  = $exoSp.AppId
                    ResourceAccess = @(@{ Id = $smtpRole.Id; Type = "Role" })
                },
                @{
                    ResourceAppId  = $GraphSP.AppId
                    ResourceAccess = @(@{ Id = $UserReadId; Type = "Scope" })
                }
            )
            Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $ResourceAccess
            Write-Log "App Manifest updated (User.Read + $SmtpPermission)." 'OK'

            $existingAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All | Where-Object { $_.ResourceId -eq $exoSp.Id -and $_.AppRoleId -eq $smtpRole.Id }
            if (-not $existingAssignment) {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $exoSp.Id -AppRoleId $smtpRole.Id | Out-Null
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
            New-ServicePrincipal -AppId $ClientId -ObjectId $ServiceId -DisplayName $DisplayName | Out-Null
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
            
            # Verify permissions were actually applied
            Start-Sleep -Seconds 2
            $fullAccessVerify = Get-MailboxPermission -Identity $mbx -User $ServiceId -ErrorAction SilentlyContinue
            if (-not $fullAccessVerify) {
                Write-Log "[$mbx] FullAccess verification failed - retrying..." 'WARN'
                Start-Sleep -Seconds 3
                Add-MailboxPermission -Identity $mbx -User $ServiceId -AccessRights FullAccess -AutoMapping:$false -ErrorAction SilentlyContinue | Out-Null
                Write-Log "[$mbx] FullAccess retry complete." 'INFO'
            }
            
            if ($AddSendAs) {
                $sendAsVerify = Get-RecipientPermission -Identity $mbx -Trustee $ServiceId -ErrorAction SilentlyContinue
                if (-not $sendAsVerify) {
                    Write-Log "[$mbx] SendAs verification failed - retrying..." 'WARN'
                    Start-Sleep -Seconds 3
                    Add-RecipientPermission -Identity $mbx -Trustee $ServiceId -AccessRights SendAs -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                    Write-Log "[$mbx] SendAs retry complete." 'INFO'
                }
            }
        }

        # Helper Commands (Ready-to-Paste)
        $joinedMailboxes = $Mailboxes -join "','"
        
        # Return Object
        $result = [PSCustomObject]@{
            TenantName            = $TenantName
            TenantId              = $TenantIdGuid
            DefaultUPN            = ($org.VerifiedDomains | Where-Object IsDefault).Name
            AppName               = $DisplayName
            ClientId              = $ClientId
            ServiceId             = $ServiceId
            ClientSecret          = $ClientSecret
            SmtpServer            = "smtp.office365.com"
            SmtpPort              = 587
            AuthMethod            = "OAuth 2.0"
            Mailboxes             = $Mailboxes
            Permissions           = if ($AddSendAs) { "FullAccess, SendAs" } else { "FullAccess" }
            
            # Local commands (using dot-sourcing)
            CleanupCommand        = ". .\Remove-ExoSmtpAppPrincipal.ps1; Remove-ExoSmtpAppPrincipal -ClientId `"$ClientId`" -Mailboxes `"$joinedMailboxes`""
            TestCommand           = ". .\Test-ExoOauthSmtpAppIdentity.ps1; Test-ExoOauthSmtpAppIdentity -ClientId `"$ClientId`" -Mailboxes `"$joinedMailboxes`""
            MailTestCommand       = ". .\Test-MailNotification.ps1; Send-SmtpOAuthTestMail -ClientId `"$ClientId`" -ClientSecret `"$ClientSecret`" -TenantId `"$TenantIdGuid`" -From `"$($Mailboxes[0])`" -To `"admin@example.com`""
            
            # Remote commands (using irm | iex)
            CleanupCommandRemote  = "irm `"https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/main/Scripts/Remove-ExoSmtpAppPrincipal.ps1`" | iex; Remove-ExoSmtpAppPrincipal -ClientId `"$ClientId`" -Mailboxes `"$joinedMailboxes`""
            TestCommandRemote     = "irm `"https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/main/Scripts/Test-ExoOauthSmtpAppIdentity.ps1`" | iex; Test-ExoOauthSmtpAppIdentity -ClientId `"$ClientId`" -Mailboxes `"$joinedMailboxes`""
            MailTestCommandRemote = "irm `"https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/main/Scripts/Test-MailNotification.ps1`" | iex; Send-SmtpOAuthTestMail -ClientId `"$ClientId`" -ClientSecret `"$ClientSecret`" -TenantId `"$TenantIdGuid`" -From `"$($Mailboxes[0])`" -To `"admin@example.com`""
        }
        
        Write-Log "Setup Complete." 'OK'

        # Display result first so user sees credentials
        Write-Output $result
        
        # THEN ask about export (after they've seen the credentials)
        $shouldExport = $false
        $exportFilePath = $ExportPath

        if ($ExportPath) {
            $shouldExport = $true
        }
        elseif (-not $NoExportPrompt) {
            $saveChoice = Read-Host "`nDo you want to save these credentials to a file? (Y/N)"
            if ($saveChoice -match '^[Yy]') {
                $shouldExport = $true
                $defaultFileName = "smtp-oauth-$($DisplayName -replace '[^a-zA-Z0-9]', '-')-$(Get-Date -Format 'yyyyMMdd').json"
                $exportFilePath = Read-Host "Enter file path (or press Enter for '$defaultFileName')"
                if ([string]::IsNullOrWhiteSpace($exportFilePath)) {
                    $exportFilePath = Join-Path (Get-Location) $defaultFileName
                }
            }
        }

        if ($shouldExport -and $exportFilePath) {
            try {
                $exportData = @{
                    TenantId     = $TenantIdGuid
                    ClientId     = $ClientId
                    ClientSecret = $ClientSecret
                    AppName      = $DisplayName
                    SmtpServer   = "smtp.office365.com"
                    SmtpPort     = 587
                    Mailboxes    = $Mailboxes
                    CreatedAt    = (Get-Date).ToString('o')
                }
                $exportData | ConvertTo-Json -Depth 3 | Out-File -FilePath $exportFilePath -Encoding UTF8
                Write-Log "Credentials saved to: $exportFilePath" 'OK'
                Write-Log "WARNING: This file contains secrets. Store securely!" 'WARN'
            }
            catch {
                Write-Log "Failed to save file: $_" 'ERROR'
            }
        }

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
