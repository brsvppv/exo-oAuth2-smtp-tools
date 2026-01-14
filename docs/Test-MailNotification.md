# Test-MailNotification

## Synopsis
Sends real test emails using either Microsoft Graph API or the SMTP protocol with OAuth 2.0.

## Description
This script provides two distinct methods for validating your mail flow. This is the **"proof of pudding"** test to ensure your Client ID and Secret are functional.

### 1. SMTP OAuth (Recommended for Business Central)
Simulates exactly how Business Central connects. It uses the `Send-SmtpOAuthTestMail` function to perform a raw SMTP handshake with XOAUTH2 authentication.
*   **Port**: 587 (STARTTLS)
*   **Auth**: SASL XOAUTH2
*   **Scope**: `https://outlook.office365.com/.default`

### 2. Graph API
Uses the `Invoke-ApiMailNotification` function to send mail via the RESTful Microsoft Graph API.
*   **Method**: POST to `/sendMail`
*   **Auth**: Bearer Token (Client Credentials)
*   **Scope**: `https://graph.microsoft.com/.default`

## Usage

### Local Usage
```powershell
. .\Test-MailNotification.ps1
Send-SmtpOAuthTestMail -ClientId "x" -ClientSecret "y" -TenantId "z" -From "a@b.com" -To "c@d.com"
```

### Remote Execution (irm | iex)

#### SMTP OAuth Test (Best for BC)
```powershell
irm "https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/main/Scripts/Test-MailNotification.ps1" | iex; 
Send-SmtpOAuthTestMail `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -TenantId "your-tenant-id" `
    -From "no-reply@contoso.com" `
    -To "admin@contoso.com"
```

#### Graph API Test
```powershell
irm "https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/main/Scripts/Test-MailNotification.ps1" | iex; 
Invoke-ApiMailNotification `
    -ClientID "your-client-id" `
    -SecretValue "your-client-secret" `
    -TenantID "your-tenant-id" `
    -MailSender "no-reply@contoso.com" `
    -Recipent "admin@contoso.com" `
    -Subject "Test via Graph" `
    -Massage "Hello from Graph API"
```

## Parameters

| Parameter | Method | Description |
| :--- | :--- | :--- |
| **ClientId** | Both | The Application (Client) ID from Azure Portal. |
| **ClientSecret** / **SecretValue** | Both | The generated application secret. |
| **TenantId** | Both | The Directory (Tenant) ID. |
| **From** / **MailSender** | Both | The email address authorized for sending. |
| **To** / **Recipent** | Both | The test recipient address. |

## Troubleshooting
*   **"STARTTLS failed"**: Ensure your network allows outbound traffic on port 587.
*   **"SMTP AUTH failed (535 5.7.3)"**: Usually means `SmtpClientAuthentication` is disabled. Run verification with `Test-ExoOauthSmtpAppIdentity`.
*   **"Access Denied (403)"**: (Graph only) Ensure the app has the `Mail.Send` Application permission consented.
