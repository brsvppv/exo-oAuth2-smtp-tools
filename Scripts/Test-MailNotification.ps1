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
    } catch {
        Write-Error "Failed to acquire token: $($_.Exception.Message)"
        return
    }

    $headers = @{
        "Authorization" = "Bearer $($tokenResponse.access_token)"
        "Content-type"  = "application/json"
    }

    # 2. Build JSON Safely
    $BodyObject = @{
        message = @{
            subject = $Subject
            body = @{
                contentType = "HTML"
                content = $Massage
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
} # <--- Correct closing brace location

# USAGE EXAMPLE:
# Invoke-ApiMailNotification -ClientID "x" -SecretValue "y" ...