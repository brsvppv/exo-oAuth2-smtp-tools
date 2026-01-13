<#
.SYNOPSIS
  Sends a test email via Graph API for validation.

.DESCRIPTION
  Ultimate "proof of concept" tool. Authenticates as the app and sends a mail.

.EXAMPLE
  Invoke-ApiMailNotification -ClientID "x" -SecretValue "y" -TenantID "z" -Subject "Hi" -MailSender "a@b.com" -Recipent "c@d.com" -Massage "Hello"

.EXAMPLE
  # Remote Execution (One-Liner)
  irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/refs/heads/main/Scripts/Test-MailNotification.ps1 | iex; Invoke-ApiMailNotification -ClientID "x" -SecretValue "y" -TenantID "z" -Subject "Hi" -MailSender "a@b.com" -Recipent "c@d.com" -Massage "Hello"
#>

Function Invoke-ApiMailNotification { 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string] $ClientID,
        [Parameter(Mandatory)][string] $SecretValue,
        [Parameter(Mandatory)][string] $TenantID,
        [Parameter(Mandatory)][string] $Subject,
        [Parameter(Mandatory)][Alias('From')][string] $MailSender,
        [Parameter(Mandatory)][Alias('To')][string] $Recipent,
        [Parameter(Mandatory)][Alias('Content')][string] $Massage
    )

    # 1. Connect to GRAPH API
    $tokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        Client_Id     = $ClientID
        Client_Secret = $SecretValue
    }

    try {
        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to acquire token: $($_.Exception.Message)"
        return
    }

    $headers = @{
        "Authorization" = "Bearer $($tokenResponse.access_token)"
        "Content-type"  = "application/json"
    }

    # 2. Build JSON Safely
    $BodyObject = @{
        message         = @{
            subject      = $Subject
            body         = @{
                contentType = "HTML"
                content     = $Massage
            }
            toRecipients = @(
                @{
                    emailAddress = @{
                        address = $Recipent
                    }
                }
            )
        }
        saveToSentItems = "false"
    }
    
    # Convert to JSON automatically handles quotes/escaping
    $BodyJsonSend = $BodyObject | ConvertTo-Json -Depth 4

    # 3. Send Mail
    $URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"

    Try {
        Invoke-RestMethod -Method POST -Uri $URLsend -Headers $headers -Body $BodyJsonSend -ErrorAction Stop
        Write-Information -MessageData "Email sent successfully via Graph API." -InformationAction Continue
    }
    Catch {
        Write-Error "Failed To Send Mail: $($_.Exception.Message)"
        # Check for specific Graph errors
        if ($_.Exception.Response) {
            $Reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Warning "Graph API Details: $($Reader.ReadToEnd())"
        }
    }
}

# -----------------------------------------------------------------------
# Remote Invocation Guard
# -----------------------------------------------------------------------
if ($null -ne $params -and $params -is [hashtable]) {
    Write-Verbose "Auto-executing 'Invoke-ApiMailNotification' with supplied params..."
    Invoke-ApiMailNotification @params
}