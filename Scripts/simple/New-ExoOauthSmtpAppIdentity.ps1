<#
A simple, single-file provisioning helper function designed for quick remote runs via `iex (irm ...)`.
Provides a Plan/DryRun mode that accepts JSON (string or file path) and prints the exact planned steps to the console.
Optionally, it can perform provisioning (`-Perform`) if the required modules are available or with `-AutoInstall` consent.
#>

function Invoke-ExoSimpleProvision {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='Path to a JSON file or inline JSON text')]
        [string]$Config,
        [Parameter(Mandatory=$false, HelpMessage='If set, the function will only display the planned actions (default)')]
        [switch]$DryRun = $true,
        [Parameter(Mandatory=$false, HelpMessage='When set, attempt to perform the provisioning actions')]
        [switch]$Perform,
        [Parameter(Mandatory=$false, HelpMessage='Auto-install missing modules when performing')]
        [switch]$AutoInstall
    )

    function Write-Log([string]$Message, [ValidateSet('INFO','WARN','ERROR','VERBOSE')][string]$Level = 'INFO') {
        switch ($Level) {
            'INFO'  { Write-Information -MessageData $Message -InformationAction Continue }
            'WARN'  { Write-Warning $Message }
            'ERROR' { Write-Error $Message }
            'VERBOSE' { Write-Verbose $Message }
        }
    }

    if (-not $Config) {
        throw 'Please provide configuration via -Config (file path or JSON string).'
    }

    # Load config: if file exists treat as path, else treat as raw JSON
    if (Test-Path $Config) {
        $raw = Get-Content -Path $Config -Raw
    } elseif ($Config.TrimStart() -match '^[\[{]') {
        $raw = $Config
    } else {
        throw "Config not found as file and does not appear to be JSON: $Config"
    }

    try {
        $c = $raw | ConvertFrom-Json
    } catch {
        throw "Config is not valid JSON: $($_.Exception.Message)"
    }

    # Minimal validation
    if (-not $c.DisplayName) { throw 'Config missing DisplayName' }
    if (-not $c.TenantId) { Write-Log 'Warning: Config missing TenantId; certain checks may be skipped in DryRun.' 'WARN' }

    $displayName = $c.DisplayName
    $tenantId = $c.TenantId
    $mailboxes = if ($c.Mailboxes) { $c.Mailboxes } else { @() }
    $yearsValid = if ($c.YearsValid) { $c.YearsValid } else { 2 }
    $secretName = if ($c.SecretName) { $c.SecretName } else { "$displayName Secret" }

    # Display Plan
    Write-Log "Provisioning Plan:" 'INFO'
    Write-Log "  DisplayName: $displayName" 'INFO'
    if ($tenantId) { Write-Log "  TenantId:    $tenantId" 'INFO' }
    Write-Log "  Mailboxes:   $($mailboxes -join ', ')" 'INFO'
    Write-Log "  SecretName:  $secretName" 'INFO'
    Write-Log "  Secret valid years: $yearsValid" 'INFO'
    Write-Log "  Actions (in order):" 'INFO'
    Write-Log "    1) Ensure App Registration '$displayName' exists (create if missing)" 'INFO'
    Write-Log "    2) Generate client secret (one-time) named '$secretName' (valid for $yearsValid years)" 'INFO'
    Write-Log "    3) Ensure Service Principal (Enterprise App) exists" 'INFO'
    Write-Log "    4) Register Service Principal in Exchange and grant mailbox permissions" 'INFO'

    if ($DryRun) {
        Write-Log 'DryRun mode: no changes will be made. Use -Perform to execute provisioning actions.' 'WARN'
        return @{ DisplayName = $displayName; TenantId = $tenantId; Mailboxes = $mailboxes; SecretName = $secretName }
    }

    if ($Perform) {
        Write-Log 'Perform mode: attempting to perform provisioning. Validating modules...' 'INFO'
        # Check modules
        $missing = @()
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph -ErrorAction SilentlyContinue)) { $missing += 'Microsoft.Graph' }
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue)) { $missing += 'ExchangeOnlineManagement' }

        if ($missing.Count -gt 0) {
            Write-Log "Missing modules: $($missing -join ', ')" 'WARN'
            if ($AutoInstall) {
                foreach ($m in $missing) {
                    Write-Log "Installing module $m..." 'INFO'
                    Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber
                }
            } else {
                throw "Required modules missing: $($missing -join ', '). Rerun with -AutoInstall or install them manually."
            }
        }

        # Connect to Graph
        Write-Log 'Connecting to Microsoft Graph...' 'INFO'
        Connect-MgGraph -Scopes 'Application.ReadWrite.All','Directory.Read.All'

        # Create or find App
        $app = Get-MgApplication -Filter "displayName eq '$displayName'" -ErrorAction SilentlyContinue
        if (-not $app) {
            Write-Log "Creating application '$displayName'..." 'INFO'
            $app = New-MgApplication -DisplayName $displayName
            Write-Log "Application created: $($app.Id)" 'INFO'
        } else { Write-Log "Application already exists: $($app.Id)" 'INFO' }

        # Create secret
        Write-Log 'Creating client secret...' 'INFO'
        $end = (Get-Date).AddYears($yearsValid)
        $secret = New-MgApplicationPassword -ApplicationId $app.Id -DisplayName $secretName -EndDateTime $end
        $clientSecret = $secret.SecretText
        Write-Log 'Client secret created (copy it now; it will not be shown again).' 'WARN'
        Write-Log "ONE-TIME CLIENT SECRET: $clientSecret" 'WARN'

        # Ensure Service Principal
        $sp = Get-MgServicePrincipal -Filter "AppId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
        if (-not $sp) {
            Write-Log 'Creating Service Principal...' 'INFO'
            $sp = New-MgServicePrincipal -AppId $app.AppId
            Start-Sleep -Seconds 10
        } else { Write-Log "Service Principal exists: $($sp.Id)" 'INFO' }

        # Register in Exchange & assign permissions
        Write-Log 'Connecting to Exchange Online...' 'INFO'
        Connect-ExchangeOnline
        try {
            $ex = Get-ServicePrincipal -Identity $sp.Id -ErrorAction Stop
            Write-Log 'Service Principal already registered in Exchange.' 'INFO'
        } catch {
            Write-Log 'Registering Service Principal in Exchange...' 'INFO'
            New-ServicePrincipal -AppId $app.AppId -ServiceId $sp.Id -DisplayName $displayName
        }

        foreach ($m in $mailboxes) {
            Write-Log "Assigning permissions for $m..." 'INFO'
            Add-MailboxPermission -Identity $m -User $sp.Id -AccessRights FullAccess -ErrorAction SilentlyContinue
        }

        Write-Log 'Provisioning complete.' 'INFO'
        return @{ Application = $app; ServicePrincipal = $sp; ClientSecret = $clientSecret }
    }
}

# If the script is invoked directly, show usage
if ($MyInvocation.InvocationName -ne '.') {
    Write-Information "Usage examples:`n`n`nInvoke-ExoSimpleProvision -Config './config/smtp-app.example.json' -DryRun`nInvoke-ExoSimpleProvision -Config '{`"DisplayName`":`"My App`",`"TenantId`":`"<tenant-id>`",`"Mailboxes`":[`"no-reply@contoso.com`"]}' -Perform -AutoInstall`n" -InformationAction Continue
}


