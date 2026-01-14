
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
        
        # Display detailed summary before deletion
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  APP DELETION SUMMARY" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Display Name    : " -NoNewline -ForegroundColor Gray
        Write-Host $app.DisplayName -ForegroundColor White
        Write-Host "Application ID  : " -NoNewline -ForegroundColor Gray
        Write-Host $AppId -ForegroundColor White
        Write-Host "Object ID (SP)  : " -NoNewline -ForegroundColor Gray
        Write-Host $ServiceId -ForegroundColor White
        Write-Host "Created         : " -NoNewline -ForegroundColor Gray
        Write-Host $app.CreatedDateTime -ForegroundColor White
        Write-Host "Description     : " -NoNewline -ForegroundColor Gray
        Write-Host $app.Description -ForegroundColor White
        
        Write-Host "`nWill Delete:" -ForegroundColor Yellow
        Write-Host "  - Exchange Online Service Principal" -ForegroundColor Yellow
        Write-Host "  - Entra ID Service Principal (Enterprise App)" -ForegroundColor Yellow
        Write-Host "  - Entra ID App Registration" -ForegroundColor Yellow
        if ($Mailboxes) {
            Write-Host "  - FullAccess & SendAs permissions on: $($Mailboxes -join ', ')" -ForegroundColor Yellow
        }
        Write-Host "========================================`n" -ForegroundColor Cyan

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
        else {
            # Standard confirmation for tagged apps
            $confirmation = Read-Host "Proceed with deletion? (Y/N)"
            if ($confirmation -notmatch '^[Yy]') {
                Write-Log "Cleanup aborted by user." 'WARN'
                return
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

if ($null -ne $params -and $params -is [hashtable]) {
    Write-Verbose "Auto-executing 'Remove-ExoSmtpAppIdentity' with supplied params..."
    Remove-ExoSmtpAppPrincipal @params
}