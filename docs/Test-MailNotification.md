# Test-MailNotification

## Synopsis
Sends a real test email using the OAuth 2.0 Client Credentials flow.

## Description
This script provides two functions for testing your SMTP OAuth setup:

1. **Invoke-ApiMailNotification** - Uses Microsoft Graph API (requires `Mail.Send` permission)
2. **Send-SmtpOAuthTestMail** - Uses SMTP with OAuth2 XOAUTH2 (requires `SMTP.SendAsApp`) - **Recommended for Business Central testing**

## Functions

### Send-SmtpOAuthTestMail (Recommended)
Sends mail using actual SMTP protocol with OAuth2 authentication - exactly like Business Central does.

```powershell
Send-SmtpOAuthTestMail `
    -ClientId "your-client-id" `
    -ClientSecret "your-client-secret" `
    -TenantId "your-tenant-id" `
    -From "no-reply@contoso.com" `
    -To "admin@contoso.com" `
    -Subject "Test Email" `
    -Body "Hello from SMTP OAuth!"
```

**Parameters:**
| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| ClientId | String | Yes | | Application (Client) ID |
| ClientSecret | String | Yes | | The client secret |
| TenantId | String | Yes | | Directory (Tenant) ID |
| From | String | Yes | | Sender email (must be authorized mailbox) |
| To | String | Yes | | Recipient email address |
| Subject | String | No | "SMTP OAuth Test" | Email subject |
| Body | String | No | "This is a test..." | Email body text |
| SmtpServer | String | No | smtp.office365.com | SMTP server |
| Port | Int | No | 587 | SMTP port |

### Invoke-ApiMailNotification
Sends mail using Microsoft Graph API. Requires `Mail.Send` application permission.

```powershell
Invoke-ApiMailNotification `
    -ClientID "your-client-id" `
    -SecretValue "your-client-secret" `
    -TenantID "your-tenant-id" `
    -Subject "Test Email" `
    -MailSender "no-reply@contoso.com" `
    -Recipent "admin@contoso.com" `
    -Massage "Hello from Graph API!"
```

**Parameters:**
| Parameter | Type | Required | Alias | Description |
| :--- | :--- | :--- | :--- | :--- |
| ClientID | String | Yes | | Application (Client) ID |
| SecretValue | String | Yes | | The client secret |
| TenantID | String | Yes | | Directory (Tenant) ID |
| Subject | String | Yes | | Email subject |
| MailSender | String | Yes | From | Sender email address |
| Recipent | String | Yes | To | Recipient email address |
| Massage | String | Yes | Content | Email body (HTML supported) |

## Remote Execution

### SMTP OAuth Test (Recommended)
```powershell
irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/main/Scripts/Test-MailNotification.ps1 | iex; Send-SmtpOAuthTestMail -ClientId "x" -ClientSecret "y" -TenantId "z" -From "a@b.com" -To "c@d.com"
```

### Graph API Test
```powershell
irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/main/Scripts/Test-MailNotification.ps1 | iex; Invoke-ApiMailNotification -ClientID "x" -SecretValue "y" -TenantID "z" -Subject "Hi" -MailSender "a@b.com" -Recipent "c@d.com" -Massage "Hello"
```

## Troubleshooting

### Send-SmtpOAuthTestMail Errors
| Error | Cause | Solution |
| :--- | :--- | :--- |
| "SMTP AUTH failed" | SMTP authentication disabled or wrong credentials | Run `New-ExoOauthSmtpAppIdentity` with `-FixMailboxSmtp` |
| "Token acquisition failed" | Invalid Client ID/Secret/Tenant | Verify credentials match Azure portal |

### Invoke-ApiMailNotification Errors
| Error | Cause | Solution |
| :--- | :--- | :--- |
| "Access Denied" / 403 | Missing Mail.Send permission | Add Mail.Send permission in Azure portal |
| "Mailbox not found" | User mailbox doesn't exist | Verify sender email is valid |
