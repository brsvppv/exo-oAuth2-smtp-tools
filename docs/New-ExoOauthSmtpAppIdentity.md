# New-ExoOauthSmtpAppIdentity

## Synopsis
Provisions an Azure AD Application and Exchange Online Service Principal for use with Business Central SMTP (OAuth 2.0).

## Description
This script automates the end-to-end setup required to send emails from Business Central using Exchange Online via OAuth 2.0. It performs the following actions:
1.  **Creates an App Registration** in Entra ID (Azure AD).
2.  **Generates a Client Secret** (valid for 2 years by default).
3.  **App Manifest Sync**: Updates the app with `User.Read` (Delegated) and `SMTP.SendAsApp` (Application) for better visibility in the Azure Portal.
4.  **Creates a Service Principal** (Enterprise App) for the application.
5.  **Grants API Authorization**: Assigns the requested SMTP role and performs Admin Consent using the Service Principal ID for reliable permission propagation.
6.  **Registers in Exchange**: Uses `New-ServicePrincipal` to sync the Entra identity to Exchange Online.
7.  **Assigns Mailbox Permissions**: Grants `FullAccess` and optionally `SendAs` to the specified mailboxes.
8.  **Fixes SMTP Posture**: Optionally enables SMTP Client Authentication for the tenant and specific mailboxes.

## Usage

### Basic Usage
```powershell
.\New-ExoOauthSmtpAppIdentity.ps1 -Mailboxes "info@contoso.com"
```
**Technical Breakdown:**
1.  **Identity Creation**: Provisions an Entra App Registration named "Organization SMTP Service".
2.  **Secret Stamping**: Generates a secure client secret valid for **2 years**.
3.  **API Authorization**: Automatically grants the `SMTP.SendAsApp` permission and performs a global Admin Consent.
4.  **Mailbox Access**: Configures Exchange Online to allow this app `FullAccess` to `info@contoso.com`.

### Full Setup with Export (Recommended)
```powershell
.\New-ExoOauthSmtpAppIdentity.ps1 `
    -DisplayName "BC ERP Mailer" `
    -Mailboxes "no-reply@contoso.com" `
    -AddSendAs `
    -FixMailboxSmtp `
    -ExportPath "C:\Setup\bc-smtp-config.json"
```
**Technical Breakdown:**
1.  **Safety Tagging**: Creates the Entra app with the description `"Created by ExoOauthSmtpTools script"` for future safety verification.
2.  **App Manifest Sync**: Ensures the portal visually shows `User.Read` and `SMTP.SendAsApp` permissions.
3.  **Permissions**: Grants `FullAccess` + **`SendAs`** for the specified mailbox. In M365, `FullAccess` alone is often not enough to send mail *as* the mailbox address.
4.  **Infrastructure Remediation**: Ensures the mailbox has SMTP Client Auth enabled (bypassing any restrictive tenant-wide defaults).
5.  **Integration Ready**: Exports a JSON file with TenantID, ClientID, and Secret for Business Central.

### Remote Execution (One-Liner)
```powershell
irm "https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/main/Scripts/New-ExoOauthSmtpAppIdentity.ps1" | iex; 
New-ExoOauthSmtpAppIdentity -DisplayName "BC Mailer" -Mailboxes "admin@contoso.com" -AddSendAs
```
**Technical Breakdown:**
1.  **In-Memory Load**: Downloads the script directly from GitHub and injects the function into your current PowerShell session.
2.  **Deployment**: Creates the "BC Mailer" identity and grants required permissions in a single stateless workflow.

## Parameters & Switches

### Identity Settings
*   **`-DisplayName`** (String, Default: `"Organization SMTP Service"`): Sets the name of the App Registration in Entra ID.
*   **`-SecretName`** (String, Default: `"Organization SMTP Secret"`): Sets the description label for the generated client secret.
*   **`-YearsValid`** (Int, Default: `2`): Secret validity period (Max recommended is 5).
*   **`-MultiTenant`** (Switch): Configures the app as Multi-Tenant (AzureADMultipleOrgs). Default is Single-Tenant.

### Mailbox & Permissions
*   **`-Mailboxes`** (String[], **Mandatory**): List of email addresses the app is authorized to send from.
*   **`-AddSendAs`** (Switch): **Highly Recommended.** Adds `SendAs` permission alongside `FullAccess`.
*   **`-SmtpPermission`** (String, Default: `"SMTP.SendAsApp"`): Defines the API scope granted. Valid options: `SMTP.Send`, `SMTP.SendAsApp`.

### Infrastructure & Export
*   **`-EnableOrgSmtp`** (Switch): Globally enables SMTP Client Authentication for the tenant.
*   **`-FixMailboxSmtp`** (Switch): Enables SMTP Client Authentication for the individual target mailboxes.
*   **`-ExportPath`** (String): Path to save the resulting configuration as a JSON file.
*   **`-NoExportPrompt`** (Switch): Skips the interactive prompt to save the configuration file at the end.

## 💡 Advanced Examples

### Multiple Shared Mailboxes
Assign access to an entire team of shared mailboxes in one command:
```powershell
.\New-ExoOauthSmtpAppIdentity.ps1 `
    -DisplayName "Corporate SMTP Relay" `
    -Mailboxes "info@contoso.com", "support@contoso.com", "billing@contoso.com" `
    -AddSendAs
```

### Long-Term Identity (5 Years)
Generate a secret that won't expire for 5 years to minimize maintenance:
```powershell
.\New-ExoOauthSmtpAppIdentity.ps1 `
    -DisplayName "BC Legacy App" `
    -Mailboxes "no-reply@contoso.com" `
    -YearsValid 5
```

### Automated DevOps Pipeline (No Interaction)
Provision an app and export the credentials to a specific path without any user prompts:
```powershell
.\New-ExoOauthSmtpAppIdentity.ps1 `
    -DisplayName "CI-CD-Mailer" `
    -Mailboxes "dev@contoso.com" `
    -ExportPath ".\vault\credentials.json" `
    -NoExportPrompt
```

### ISV Multi-Tenant Setup
Create an application registration that can be used across multiple customer tenants:
```powershell
.\New-ExoOauthSmtpAppIdentity.ps1 `
    -DisplayName "AppSource Connector" `
    -Mailboxes "service@contoso.com" `
    -MultiTenant
```

### Urgent Infrastructure Fix
Enable SMTP Auth at the tenant level if it was previously blocked by "Security Defaults":
```powershell
.\New-ExoOauthSmtpAppIdentity.ps1 `
    -Mailboxes "urgent@contoso.com" `
    -EnableOrgSmtp `
    -FixMailboxSmtp
```

## Outputs
The script returns a `PSCustomObject` containing:
*   **TenantId**: The Directory ID.
*   **ClientId**: The Application ID.
*   **ClientSecret**: The generated secret (Cleartext).
*   **CleanupCommand**: Pre-formatted command to remove this exact setup.
*   **TestCommand**: Pre-formatted command to verify the setup.
*   **MailTestCommand**: Pre-formatted command to send a test email.

> [!WARNING]
> **Credential Safety**: The output object and the exported JSON file contain the **Client Secret in cleartext**. Store these securely and delete the JSON file once the configuration in Business Central is complete.
