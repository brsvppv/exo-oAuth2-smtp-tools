function Invoke-ApiMailNotification {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $ClientID,
        [Parameter(Mandatory)]
        [string] $ClientSecret,
        [Parameter(Mandatory)]
        [string] $TenantID,
        [Parameter(Mandatory)]
        [ValidatePattern("^.+@.+\..+$")]
        [string] $MailSender,
        [Parameter(Mandatory)]
        [ValidatePattern("^.+@.+\..+$")]
        [string] $Recipient,
        [Parameter(Mandatory)]
        [string] $Subject,
        [Parameter(Mandatory)]
        [string] $BodyContent,
        [Parameter()]
        [switch] $Html
    )

    $ContentType = if ($Html) { "HTML" } else { "Text" }

    $tokenBody = @{
        grant_type    = "client_credentials"
        scope         = "https://graph.microsoft.com/.default"
        client_id     = $ClientID
        client_secret = $ClientSecret
    }

    try {
        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
    } catch {
        Write-Error "Failed to acquire token: $($_.Exception.Message)"
        return $null
    }

    $headers = @{
        "Authorization" = "Bearer $($tokenResponse.access_token)"
        "Content-type"  = "application/json"
    }

    $URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"

    $BodyJsonsend = @"
{
    "message": {
        "subject": "$Subject",
        "body": {
            "contentType": "$ContentType",
            "content": "$BodyContent"
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "address": "$Recipient"
                }
            }
        ]
    },
    "saveToSentItems": false
}
"@

    Write-Information -MessageData "Sending payload to Graph API" -InformationAction Continue
    try {
        $response = Invoke-RestMethod -Method POST -Uri $URLsend -Headers $headers -Body $BodyJsonsend
        Write-Output "Mail sent successfully."
        return $response
    } catch {
        Write-Error "Failed to send mail: $($_.Exception.Message)"
        Write-Warning "Payload: $BodyJsonsend"
        return $null
    }
}

# Import config outside the function
$configPath = Join-Path -Path $PSScriptRoot "Config\oAuth_config_v2.json"
if (!(Test-Path $configPath)) {
    Write-Error "Config file not found: $configPath"
    return $null
}
$Config = Get-Content -Path $configPath | ConvertFrom-Json

# Example mail content and recipient
$Recipient = "b.popov@team-vision.bg"
$Subject = "Test Subject"
$BodyContent = "Test message body."

$secret = $Config.SecretValue
if (-not $secret) { $secret = $env:EXO_SMTP_CLIENT_SECRET }
if (-not $secret) { Write-Error "Client secret not provided. Set EXO_SMTP_CLIENT_SECRET or update config."; return }

Invoke-ApiMailNotification `
    -ClientID $Config.ClientID `
    -ClientSecret $secret `
    -TenantID $Config.TenantID `
    -MailSender $Config.MailSender `
    -Recipient $Recipient `
    -Subject $Subject `
    -BodyContent $BodyContent