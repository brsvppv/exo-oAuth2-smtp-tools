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
**Technical Breakdown:**
1.  **Identity Creation**: Provisions an Entra App Registration named "Organization SMTP Service".
2.  **Secret Stamping**: Generates a secure client secret valid for **2 years**.
3.  **API Authorization**: Automatically grants the `SMTP.Send` permission and performs a global Admin Consent.
4.  **Mailbox Access**: Configures Exchange Online to allow this app `FullAccess` to `info@contoso.com`.

### Full Setup (Recommended for Business Central)
```powershell
.\New-ExoOauthSmtpAppIdentity.ps1 `
    -Mailboxes "no-reply@contoso.com", "sales@contoso.com" `
    -AddSendAs `
    -EnableOrgSmtp `
    -FixMailboxSmtp
```
**Technical Breakdown:**
1.  **Safety Tagging**: Creates the Entra app with the description `"Created by ExoOauthSmtpTools script"` for future safety verification.
2.  **Doubled Permissions**: Since `-AddSendAs` is used, the script performs **4 permission assignments**:
    *   `no-reply@contoso.com`: Grants `FullAccess` + **`SendAs`**.
    *   `sales@contoso.com`: Grants `FullAccess` + **`SendAs`**.
3.  **Infrastructure Remediation**:
    *   **Org-Wide**: Ensures `SmtpClientAuthenticationDisabled` is set to `$false` for the tenant.
    *   **Mailbox-Specific**: Ensures both mailboxes have SMTP Client Auth enabled (bypassing any restrictive tenant-wide defaults).
4.  **Integration Ready**: Returns a clean object with TenantID, ClientID, and Secret for Business Central.

> [!TIP]
> **Why -AddSendAs is vital**: Business Central often tries to send mail "From" the specific mailbox address. Without `SendAs`, M365 might reject the mail even with `FullAccess`. This switch prevents "Status: 5.7.1 Client was not authenticated to send anonymous mail" errors.

### Remote Execution (One-Liner)
You can run this script directly from GitHub without downloading it manually:
```powershell
irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/refs/heads/main/Scripts/New-ExoOauthSmtpAppIdentity.ps1 | iex; New-ExoOauthSmtpAppIdentity -DisplayName "BC Mailer" -Mailboxes "admin@contoso.com" -AddSendAs
```
**Technical Breakdown:**
1.  **In-Memory Load**: Downloads the script directly from GitHub and injects the function into your current PowerShell session (no local file created).
2.  **Identity Provisioning**: Creates an app named "BC Mailer" with all required API scopes.
3.  **Permissions**: Finalizes by granting `FullAccess` and `SendAs` to the admin mailbox.


## Parameters & Switches

### Identity Settings
*   **`-DisplayName`** (String, Default: `"Organization SMTP Service"`): Sets the name of the App Registration in Entra ID. This is how the identity appears in the "App registrations" portal.
*   **`-SecretName`** (String, Default: `"Organization SMTP Secret"`): Sets the description label for the generated client secret. Useful for auditing (e.g., "BC Production Secret").
*   **`-YearsValid`** (Int, Default: `2`): Determines how many years the secret remains valid. Maximum recommended is 5. After this period, you must generate a new secret and update Business Central.

### Mailbox & Permissions
*   **`-Mailboxes`** (String[], **Mandatory**): A comma-separated list of email addresses. The identity will be authorized to send mail through these specific accounts.
*   **`-AddSendAs`** (Switch): **Highly Recommended.** By default, the script grants `FullAccess`. This switch adds the `SendAs` right. In M365, `FullAccess` alone is often not enough to send mail *as* the mailbox address; `SendAs` ensures the "From" address is correctly authenticated.
*   **`-SmtpPermission`** (String, Default: `"SMTP.Send"`): Defines the API scope granted in Entra ID. 
    *   `SMTP.Send`: Standard scope for sending mail as the signed-in user or authorized mailbox.
    *   `SMTP.SendAsApp`: A broader scope used for automated services.

### Infrastructure & Remediation
*   **`-EnableOrgSmtp`** (Switch): A "fix-it" switch for the whole tenant. If your organization has disabled SMTP Auth globally (Security Defaults), this switch attempts to enable the `SmtpClientAuthenticationDisabled` organization setting to allow apps to connect.
*   **`-FixMailboxSmtp`** (Switch): A "fix-it" switch for individual mailboxes. If a specific mailbox has SMTP Auth disabled via its own policy, this switch enables it.
*   **`-GrantSmtpPermission`** (Bool, Default: `$true`): When true, the script handles the Entra ID API permission grant and Admin Consent automatically. Set to $false only if you intend to perform consent manually in the Azure Portal.

## Outputs
 The script outputs the following values to the console, which are required for Business Central setup:
*   **Tenant ID**
*   **Client ID**
*   **Client Secret** (Shown once, must be copied immediately)
