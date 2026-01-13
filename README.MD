# Exchange Online SMTP OAuth Tools for Business Central

A collection of PowerShell scripts to automate the setup, verification, and testing of **OAuth 2.0 SMTP** authentication for Microsoft Dynamics 365 Business Central (and other SMTP applications).

## 🚀 Quick Start

### 1. Provision the App
Run the script to create the app and configure Exchange Online automatically.
```powershell
.\Scripts\New-ExoOauthSmtpAppIdentity.ps1 `
    -Mailboxes "no-reply@yourdomain.com" `
    -AddSendAs `
    -EnableOrgSmtp `
    -FixMailboxSmtp
```

**Or run remotely from GitHub (One-Liner):**
```powershell
irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/refs/heads/main/Scripts/New-ExoOauthSmtpAppIdentity.ps1 | iex; New-ExoOauthSmtpAppIdentity -Mailboxes "info@contoso.com"
```

*   **[Documentation: New-ExoOauthSmtpAppIdentity](docs/New-ExoOauthSmtpAppIdentity.md)**

### 2. Verify the Setup (Optional)
Check if everything is green before configuring Business Central.
```powershell
.\Scripts\Test-ExoOauthSmtpAppIdentity.ps1 -DisplayName "Organization SMTP Service" -Mailboxes "no-reply@yourdomain.com"
```
*   **[Documentation: Test-ExoOauthSmtpAppIdentity](docs/Test-ExoOauthSmtpAppIdentity.md)**

### 3. Test Mail Flow
Send a real email using the generated credentials to prove it works.
```powershell
.\Scripts\Test-MailNotification.ps1 -ClientId "..." -TenantId "..." -ClientSecret "..." -Sender "no-reply@yourdomain.com" -Recipient "you@yourdomain.com"
```
*   **[Documentation: Test-MailNotification](docs/Test-MailNotification.md)**

---

## 📂 Repository Structure

*   **/Scripts**
    *   `New-ExoOauthSmtpAppIdentity.ps1`: **(Main Tool)** Creates App, Secret, and assigns permissions.
    *   `Test-ExoOauthSmtpAppIdentity.ps1`: Diagnostics tool to verify permissions.
    *   `Test-MailNotification.ps1`: Sends a test email via SMTP OAuth.
    *   `Remove-ExoSmtpAppPrincipal.ps1`: Cleanup script to remove the app.
*   **/docs**: Detailed documentation for each script.
*   **/Tests**: Unit tests to ensure script stability.

## ⚠️ Requirements
*   **PowerShell 7+** (Recommended) or Windows PowerShell 5.1
*   **Modules:** The scripts will attempt to install/load:
    *   `Microsoft.Graph`
    *   `ExchangeOnlineManagement`
*   **Permissions:** You must be a **Global Administrator** or have sufficient privileges (Application Administrator + Exchange Administrator) to run these scripts.

## 🤝 Contributing
Please verify any changes using the included Pester tests in the `/Tests` directory.
