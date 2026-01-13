<#
.SYNOPSIS
  Removes the Entra App, Service Principal, and all associated mailbox permissions.

.DESCRIPTION
  A robust cleanup utility for decommissioning Business Central SMTP OAuth setups.
  This function performs a "scorched earth" removal of the identity:
  1. Revokes 'FullAccess' permission from all specified mailboxes.
  2. Revokes 'SendAs' permission from all specified mailboxes.
  3. Deletes the Service Principal from Exchange Online.
  4. Deletes the Service Principal (Enterprise App) from Entra ID.
  5. Deletes the App Registration from Entra ID.

.PARAMETER DisplayName
  The display name of the App Registration to remove.
  Used as the primary lookup method if ClientId is not provided.
  WARNING: If multiple apps exist with the same name, this will fail for safety. Use -ClientId instead.

.PARAMETER ClientId
  (Optional) The exact Application (Client) ID (GUID) to remove.
  Recommended for precision to avoid accidental deletion of similarly named apps.

.PARAMETER Mailboxes
  An array of SMTP addresses to cleanup.
  Crucial for removing residual permissions. If omitted, permissions might be left on mailboxes.

.EXAMPLE
  # 1. Standard Cleanup by Name
  Remove-ExoSmtpAppPrincipal -DisplayName "Organization SMTP Service" -Mailboxes "info@contoso.com"

.EXAMPLE
  # 2. Precise Cleanup by Client ID (Recommended)
  Remove-ExoSmtpAppPrincipal -ClientId "11111111-2222-3333-4444-555555555555" -Mailboxes "sales@contoso.com"

.EXAMPLE
  # 3. Remote Execution (One-Liner)
  irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/refs/heads/main/Scripts/Remove-ExoSmtpAppPrincipal.ps1 | iex; Remove-ExoSmtpAppPrincipal -DisplayName "Old App"
#>

function Remove-ExoSmtpAppPrincipal {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DisplayName = "Organization SMTP Service",

        [Parameter(Mandatory = $false)]
        [string]$ClientId,

        [Parameter(Mandatory = $false)]
        [string[]]$Mailboxes
    )

    # -------------------------------------------------------------------
    # Helpers
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

        # 2. Connect
        Write-Log "Connecting to Graph & Exchange..." 'STEP'
        try {
            if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
                Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'Directory.Read.All' -ErrorAction Stop | Out-Null
            }
            # Exchange might already be connected
            if (-not (Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' })) {
                Connect-ExchangeOnline -ErrorAction Stop | Out-Null
            }
        }
        catch {
            throw "Failed to connect: $_"
        }
        Write-Log "Connected." 'OK'

        # 3. Identify Objects
        Write-Log "Identifying objects to remove..." 'STEP'
        $sp = $null
        $app = $null

        # Try by ClientId first (Precision)
        if ($ClientId) {
            Write-Log "Lookup by ClientId: $ClientId" 'INFO'
            $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue
            $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue
        } 
        
        # Fallback to DisplayName
        if (-not $sp -and -not $app) {
            Write-Log "Lookup by DisplayName: $DisplayName" 'INFO'
            # Check for ambiguity
            $apps = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
            if ($apps.Count -gt 1) {
                throw "Multiple apps found with name '$DisplayName'. Please specify -ClientId."
            }
            $app = $apps | Select-Object -First 1
            if ($app) {
                $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
            }
            else {
                # Try finding SP directly if App is gone
                $sps = Get-MgServicePrincipal -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
                if ($sps.Count -gt 1) { throw "Multiple Service Principals found with name '$DisplayName'. Please specify -ClientId." }
                $sp = $sps | Select-Object -First 1
            }
        }

        if (-not $sp -and -not $app) {
            Write-Log "No App or Service Principal found. Nothing to delete." 'WARN'
            if (-not $Mailboxes) { return }
            Write-Log "Proceeding to check mailbox permissions manually (via Unknown User SID logic implied)..." 'WARN'
            # Note: Without SP ID, we can't reliably remove permissions unless we scan ACLs. 
            # This script assumes we have the ID. If not found, we warn.
            Write-Log "Cannot ensure mailbox permission cleanup without Service Principal ID." 'ERROR'
            return
        }

        $ServiceId = $sp.Id
        $AppId = $app.AppId
        Write-Log "Targeting: AppId=$AppId, SP_ObjectId=$ServiceId" 'OK'

        # 3b. Extra Safety Check: Description Verification
        $expectedTag = "Created by ExoOauthSmtpTools script"
        if ($app -and $app.Description -ne $expectedTag) {
            Write-Log "SAFETY WARNING: The App '$($app.DisplayName)' does NOT have the safety tag: '$expectedTag'." 'WARN'
            Write-Log "Current Description: $($app.Description)" 'INFO'
            
            $confirmation = Read-Host "Are you SURE you want to delete this app? It may not have been created by this script. (Type 'YES' to proceed)"
            if ($confirmation -ne 'YES') {
                throw "Cleanup aborted by user due to safety tag mismatch."
            }
        }

        # 4. Remove Mailbox Permissions
        if ($Mailboxes) {
            Write-Log "Cleaning Mailbox Permissions..." 'STEP'
            foreach ($mbx in $Mailboxes) {
                # Full Access
                try {
                    $perm = Get-MailboxPermission -Identity $mbx -User $ServiceId -ErrorAction SilentlyContinue
                    if ($perm) {
                        if ($PSCmdlet.ShouldProcess($mbx, "Remove FullAccess for $ServiceId")) {
                            Remove-MailboxPermission -Identity $mbx -User $ServiceId -AccessRights FullAccess -Confirm:$false -ErrorAction Stop | Out-Null
                            Write-Log "[$mbx] FullAccess removed." 'OK'
                        }
                    }
                }
                catch {
                    Write-Log "[$mbx] Error removing FullAccess: $_" 'WARN'
                }

                # Send As (New Logic)
                try {
                    $sendAs = Get-RecipientPermission -Identity $mbx -Trustee $ServiceId -ErrorAction SilentlyContinue
                    if ($sendAs) {
                        if ($PSCmdlet.ShouldProcess($mbx, "Remove SendAs for $ServiceId")) {
                            Remove-RecipientPermission -Identity $mbx -Trustee $ServiceId -AccessRights SendAs -Confirm:$false -ErrorAction Stop | Out-Null
                            Write-Log "[$mbx] SendAs removed." 'OK'
                        }
                    }
                }
                catch {
                    Write-Log "[$mbx] Error removing SendAs: $_" 'WARN'
                }
            }
        }

        # 5. Remove Exchange SP
        if ($ServiceId) {
            Write-Log "Removing Exchange Service Principal..." 'STEP'
            try {
                if ($PSCmdlet.ShouldProcess($ServiceId, "Remove Exchange Service Principal")) {
                    Remove-ServicePrincipal -Identity $ServiceId -Confirm:$false -ErrorAction Stop
                    Write-Log "Exchange SP deleted." 'OK'
                }
            }
            catch {
                Write-Log "Exchange SP already gone or failed: $_" 'WARN'
            }
        }

        # 6. Remove Entra SP
        if ($ServiceId) {
            Write-Log "Removing Entra Service Principal..." 'STEP'
            try {
                if ($PSCmdlet.ShouldProcess($ServiceId, "Remove Entra Service Principal (Enterprise App)")) {
                    Remove-MgServicePrincipal -ServicePrincipalId $ServiceId -ErrorAction Stop
                    Write-Log "Entra SP deleted." 'OK'
                }
            }
            catch {
                Write-Log "Entra SP already gone: $_" 'WARN'
            }
        }

        # 7. Remove App
        if ($app) {
            Write-Log "Removing App Registration..." 'STEP'
            try {
                if ($PSCmdlet.ShouldProcess($app.DisplayName, "Remove Entra App Registration ($($app.AppId))")) {
                    Remove-MgApplication -ApplicationId $app.Id -ErrorAction Stop
                    Write-Log "App Registration deleted." 'OK'
                }
            }
            catch {
                Write-Log "App Registration already gone: $_" 'WARN'
            }
        }

        Write-Log "Cleanup Complete." 'OK'

    }
    catch {
        Write-Log "Critical Error: $_" 'ERROR'
        throw $_
    }
}

# -----------------------------------------------------------------------
# Remote Invocation Guard
# -----------------------------------------------------------------------
if ($null -ne $params -and $params -is [hashtable]) {
    Write-Verbose "Auto-executing 'Remove-ExoSmtpAppIdentity' with supplied params..."
    Remove-ExoSmtpAppPrincipal @params
}