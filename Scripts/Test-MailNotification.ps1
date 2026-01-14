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
        Write-Host "[OK] Email sent successfully via Graph API." -ForegroundColor Green
    }
    Catch {
        Write-Error "Failed To Send Mail: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $Reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Warning "Graph API Details: $($Reader.ReadToEnd())"
        }
    }
}

# -----------------------------------------------------------------------
# Function 2: SMTP OAuth Mail (Uses SMTP.SendAsApp - True BC Test)
# -----------------------------------------------------------------------
Function Send-SmtpOAuthTestMail {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string] $ClientId,
        [Parameter(Mandatory)][string] $ClientSecret,
        [Parameter(Mandatory)][string] $TenantId,
        [Parameter(Mandatory)][string] $From,
        [Parameter(Mandatory)][string] $To,
        [Parameter(Mandatory = $false)][string] $Subject = "SMTP OAuth Test",
        [Parameter(Mandatory = $false)][string] $Body = "This is a test email sent via SMTP OAuth2.",
        [Parameter(Mandatory = $false)][string] $SmtpServer = "smtp.office365.com",
        [Parameter(Mandatory = $false)][int] $Port = 587
    )

    Write-Host "[STEP] Acquiring OAuth2 token for SMTP..." -ForegroundColor Cyan

    # 1. Get OAuth2 Token with SMTP scope
    $tokenBody = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://outlook.office365.com/.default"
        grant_type    = "client_credentials"
    }

    try {
        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody -ErrorAction Stop
        $accessToken = $tokenResponse.access_token
        Write-Host "[OK] Token acquired successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to acquire SMTP OAuth token: $($_.Exception.Message)"
        return
    }

    # 2. Build XOAUTH2 SASL string
    # Format: base64("user=" + user + "^Aauth=Bearer " + token + "^A^A")
    $authString = "user=$From`u{01}auth=Bearer $accessToken`u{01}`u{01}"
    $xoauth2Token = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($authString))

    Write-Host "[STEP] Connecting to $SmtpServer`:$Port..." -ForegroundColor Cyan

    # 3. Send via .NET SmtpClient with manual AUTH XOAUTH2
    try {
        # Use System.Net.Sockets for raw SMTP with XOAUTH2
        $tcpClient = New-Object System.Net.Sockets.TcpClient($SmtpServer, $Port)
        $stream = $tcpClient.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        # Helper to send command and get response
        function Send-SmtpCommand($cmd) {
            if ($cmd) { $writer.WriteLine($cmd) }
            Start-Sleep -Milliseconds 100
            return $reader.ReadLine()
        }

        # Helper to read all available lines
        function Read-AllResponses {
            $responses = @()
            Start-Sleep -Milliseconds 200
            while ($stream.DataAvailable) { 
                $responses += $reader.ReadLine()
            }
            return $responses
        }

        # SMTP Handshake - Read banner
        $banner = $reader.ReadLine()
        Write-Host "  Banner: $banner" -ForegroundColor Gray

        # EHLO - read until we get "250 " (space = final line, dash = more coming)
        $writer.WriteLine("EHLO localhost")
        do {
            $line = $reader.ReadLine()
        } while ($line -match "^250-")  # Keep reading while continuation lines
        Write-Host "  EHLO complete." -ForegroundColor Gray

        # STARTTLS - send and wait for 220 Ready
        $writer.WriteLine("STARTTLS")
        $starttlsResponse = $reader.ReadLine()
        Write-Host "  STARTTLS: $starttlsResponse" -ForegroundColor Gray
        
        if ($starttlsResponse -notmatch "^220") {
            throw "STARTTLS failed: $starttlsResponse"
        }

        # Upgrade to TLS
        $sslStream = New-Object System.Net.Security.SslStream($stream, $false)
        $sslStream.AuthenticateAsClient($SmtpServer)
        Write-Host "[OK] TLS connection established." -ForegroundColor Green

        $reader = New-Object System.IO.StreamReader($sslStream)
        $writer = New-Object System.IO.StreamWriter($sslStream)
        $writer.AutoFlush = $true

        # EHLO after TLS
        $writer.WriteLine("EHLO localhost")
        Start-Sleep -Milliseconds 300
        while ($sslStream.CanRead) { 
            $line = $reader.ReadLine()
            if ($line -match "^250 ") { break }  # Last EHLO response
        }

        # AUTH XOAUTH2
        $writer.WriteLine("AUTH XOAUTH2 $xoauth2Token")
        Start-Sleep -Milliseconds 200
        $response = $reader.ReadLine()
        if ($response -notmatch "^235") {
            throw "SMTP AUTH failed: $response"
        }
        Write-Host "[OK] SMTP Authentication successful." -ForegroundColor Green

        # MAIL FROM
        $response = Send-SmtpCommand "MAIL FROM:<$From>"
        if ($response -notmatch "^250") { throw "MAIL FROM failed: $response" }

        # RCPT TO
        $response = Send-SmtpCommand "RCPT TO:<$To>"
        if ($response -notmatch "^250") { throw "RCPT TO failed: $response" }

        # DATA
        $response = Send-SmtpCommand "DATA"
        if ($response -notmatch "^354") { throw "DATA failed: $response" }

        # Message
        $writer.WriteLine("From: $From")
        $writer.WriteLine("To: $To")
        $writer.WriteLine("Subject: $Subject")
        $writer.WriteLine("Content-Type: text/plain; charset=UTF-8")
        $writer.WriteLine("")
        $writer.WriteLine($Body)
        $response = Send-SmtpCommand "."

        if ($response -notmatch "^250") { throw "Message send failed: $response" }

        Send-SmtpCommand "QUIT" | Out-Null

        $tcpClient.Close()

        Write-Host "[OK] Email sent successfully via SMTP OAuth2!" -ForegroundColor Green
        Write-Host "     From: $From -> To: $To" -ForegroundColor Gray
    }
    catch {
        Write-Error "SMTP OAuth Error: $($_.Exception.Message)"
    }
}

# -----------------------------------------------------------------------
# Remote Invocation Guard
# -----------------------------------------------------------------------
if ($null -ne $params -and $params -is [hashtable]) {
    Write-Verbose "Auto-executing with supplied params..."
    if ($params.ContainsKey('SmtpServer') -or $params.ContainsKey('ClientSecret')) {
        Send-SmtpOAuthTestMail @params
    }
    else {
        Invoke-ApiMailNotification @params
    }
}