# --------------------------------------------------------------------------------
# CONFIGURATION
# --------------------------------------------------------------------------------
$DisplayName = "Organization SMTP Service"
$SecretName  = "Organization SMTP Secret"
$YearsValid  = 2
# List all mailboxes that need to send mail (No-Reply + Shared Mailboxes)
$Mailboxes = @(
    "no-reply@example.com", #email user mailbox
    "info@example.com",  #email shared mailbox
    "notify@example.com"#email shared mailbox
)

# --------------------------------------------------------------------------------
# MODULE CHECK & CONNECTION
# --------------------------------------------------------------------------------
function Write-Log([string]$Message, [ValidateSet('INFO','WARN','ERROR','VERBOSE')][string]$Level = 'INFO') {
    switch ($Level) {
        'INFO'  { Write-Information -MessageData $Message -InformationAction Continue }
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message }
        'VERBOSE' { Write-Verbose $Message }
    }
}

Write-Log "Checking modules..." 'INFO'
if (-not (Get-Module -ListAvailable Microsoft.Graph.Applications)) { Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force }
if (-not (Get-Module -ListAvailable ExchangeOnlineManagement)) { Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force }

Write-Log "Connecting to Microsoft Graph (Login as Global Admin)..." 'INFO'
# We need permissions to Create Apps, Secrets, and read Service Principals
Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'Directory.Read.All'

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

# --------------------------------------------------------------------------------
# STEP 4: EXCHANGE ONLINE CONFIGURATION
# --------------------------------------------------------------------------------
Write-Log "Connecting to Exchange Online..." 'INFO'
Connect-ExchangeOnline

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
# STEP 5: ASSIGN MAILBOX PERMISSIONS
# --------------------------------------------------------------------------------
Write-Log "Assigning Permissions to Mailboxes..." 'INFO'

foreach ($Email in $Mailboxes) {
    Write-Log "   Processing $Email..." 'INFO'
    # Add permission (silently continue if already exists)
    Add-MailboxPermission -Identity $Email -User $ServiceId -AccessRights FullAccess -ErrorAction SilentlyContinue
    Write-Log "   - Access Granted." 'INFO'
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
Write-Information -MessageData "Tenant ID:      $($App.PublisherDomain)" -InformationAction Continue
Write-Information -MessageData "" -InformationAction Continue
Write-Warning "IMPORTANT: Copy the Client Secret NOW. You cannot see it again."
Write-Information -MessageData "================================================================" -InformationAction Continue
Write-Log "Final Step Check: Go to Azure Portal > App Registrations > '$DisplayName'" 'WARN'
Write-Log "Ensure 'API Permissions' > 'SMTP.SendAsApp' is added and Admin Consent is clicked." 'WARN'


