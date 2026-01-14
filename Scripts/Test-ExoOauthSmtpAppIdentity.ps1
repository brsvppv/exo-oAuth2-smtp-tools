function Test-ExoOauthSmtpAppIdentity {
    [CmdletBinding()]
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
        Write-Log "Starting Validation..." 'STEP'

        # 1. Module Checks
        Initialize-RequiredModule -Name Microsoft.Graph.Applications
        Initialize-RequiredModule -Name ExchangeOnlineManagement

        # 2. Connect
        try {
            if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
                Connect-MgGraph -Scopes 'Application.Read.All', 'Directory.Read.All' -ErrorAction Stop | Out-Null
            }
            if (-not (Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' })) {
                Connect-ExchangeOnline -ErrorAction Stop | Out-Null
            }
        }
        catch {
            throw "Failed to connect: $_"
        }
        Write-Log "Connected to Graph and Exchange." 'OK'

        # 3. Find Identity
        $sp = $null
        $app = $null

        if ($ClientId) {
            $sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue
            $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue
        }

        if (-not $sp -and -not $app) {
            # Fallback to DisplayName
            $apps = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
            if ($apps.Count -eq 1) {
                $app = $apps[0]
                $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
            }
        }

        if (-not $sp) {
            Write-Log "Service Principal not found." 'ERROR'
            return
        }
        Write-Log "Found Service Principal: $($sp.DisplayName) ($($sp.Id))" 'OK'

        # 4. Check Exchange Object
        $exoSp = Get-ServicePrincipal -Identity $sp.Id -ErrorAction SilentlyContinue
        if ($exoSp) {
            Write-Log "Exchange Service Principal Object exists." 'OK'
        }
        else {
            Write-Log "Exchange Service Principal Object NOT found (wait for propagation)." 'WARN'
        }

        # 5. Check Permissions
        if ($Mailboxes) {
            foreach ($mbx in $Mailboxes) {
                Write-Log "Checking $mbx..." 'STEP'
                
                # Full Access
                $fa = Get-MailboxPermission -Identity $mbx -User $sp.Id -ErrorAction SilentlyContinue
                if ($fa) { Write-Log "  [+] FullAccess: YES" 'OK' } else { Write-Log "  [-] FullAccess: NO" 'ERROR' }

                # Send As
                $sa = Get-RecipientPermission -Identity $mbx -Trustee $sp.Id -ErrorAction SilentlyContinue
                if ($sa) { Write-Log "  [+] SendAs: YES" 'OK' } else { Write-Log "  [-] SendAs: NO" 'WARN' }

                # SMTP Auth
                try {
                    $cas = Get-CASMailbox -Identity $mbx -ErrorAction Stop
                    if ($cas.SmtpClientAuthenticationDisabled -eq $false) {
                        Write-Log "  [+] SMTP Auth Enabled: YES (Explicit)" 'OK' 
                    }
                    elseif ($cas.SmtpClientAuthenticationDisabled -eq $true) {
                        Write-Log "  [-] SMTP Auth Enabled: NO (Disabled explicitly)" 'ERROR'
                    }
                    else {
                        # Mailbox inherits from org - check org setting
                        try {
                            $orgConfig = Get-TransportConfig -ErrorAction Stop
                            if ($orgConfig.SmtpClientAuthenticationDisabled -eq $true) {
                                Write-Log "  [-] SMTP Auth Enabled: NO (Inherited from Org)" 'ERROR'
                            }
                            else {
                                Write-Log "  [+] SMTP Auth Enabled: YES (Inherited from Org)" 'OK'
                            }
                        }
                        catch {
                            Write-Log "  [?] SMTP Auth: Inherited (could not check org setting)" 'WARN'
                        }
                    }
                }
                catch {
                    Write-Log "  [-] Could not check CAS settings." 'WARN'
                }
            }
        }

    }
    catch {
        Write-Log "Validation Error: $_" 'ERROR'
    }
}

if ($null -ne $params -and $params -is [hashtable]) {
    Write-Verbose "Auto-executing 'Test-ExoOauthSmtpAppIdentity' with supplied params..."
    Test-ExoOauthSmtpAppIdentity @params
}