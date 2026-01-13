# New-ExoOauthSmtpAppIdentity

## Synopsis
Provisions an Azure AD Application and Exchange Online Service Principal for use with Business Central SMTP (OAuth 2.0).

## Description
This script automates the end-to-end setup required to send emails from Business Central using Exchange Online via OAuth 2.0. It performs the following actions:
1.  **Creates an App Registration** in Entra ID (Azure AD).
2.  **Generates a Client Secret** (valid for 2 years by default).
3.  **Creates a Service Principal** (Enterprise App) for the application.
4.  **Grants API Permissions:** Assigns `SMTP.Send` or `SMTP.SendAsApp` to the Service Principal and performs Admin Consent.
5.  **Assigns Mailbox Permissions:** Grants `FullAccess` and optionally `SendAs` to the specified mailboxes.
6.  **Fixes SMTP Posture:** Optionally enables SMTP Client Authentication for the tenant and specific mailboxes if they are disabled.

## Usage

### Basic Usage
```powershell
.\New-ExoOauthSmtpAppIdentity.ps1 -Mailboxes "info@contoso.com"
```

### Full Setup (Recommended for Business Central)
```powershell
.\New-ExoOauthSmtpAppIdentity.ps1 `
    -Mailboxes "no-reply@contoso.com", "sales@contoso.com" `
    -AddSendAs `
    -EnableOrgSmtp `
    -FixMailboxSmtp
```

### Remote Execution (One-Liner)
You can run this script directly from GitHub without downloading it manually:
```powershell
irm https://raw.githubusercontent.com/username/repo/main/Scripts/New-ExoOauthSmtpAppIdentity.ps1 | iex; New-ExoOauthSmtpAppIdentity -DisplayName "BC Mailer" -Mailboxes "admin@contoso.com" -AddSendAs
```

## Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| **DisplayName** | String | "Organization SMTP Service" | The name display name for the App Registration in Azure. |
| **SecretName** | String | "Organization SMTP Secret" | The friendly name for the client secret key. |
| **YearsValid** | Int | 2 | The validity period for the client secret in years. |
| **Mailboxes** | String[] | (Mandatory) | List of email addresses the app will send from. |
| **AddSendAs** | Switch | False | **Recommended.** Grants `SendAs` permission so emails appear to come directly from the sender. |
| **GrantSmtpPermission** | Bool | True | Automates granting the `SMTP.Send` API permission. |
| **EnableOrgSmtp** | Switch | False | Enables SMTP Client Auth for the entire organization if it is disabled. |
| **FixMailboxSmtp** | Switch | False | Enables SMTP Client Auth for the specific mailboxes if it is disabled. |

## Outputs
 The script outputs the following values to the console, which are required for Business Central setup:
*   **Tenant ID**
*   **Client ID**
*   **Client Secret** (Shown once, must be copied immediately)
