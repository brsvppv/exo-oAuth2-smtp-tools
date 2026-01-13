# 📧 Exchange Online SMTP OAuth Tools

**Simplify and Secure Microsoft 365 SMTP Auth for Business Central.**

This repository provides a production-grade PowerShell suite designed to automate the complex setup of **OAuth 2.0 SMTP** authentication. While optimized for **Microsoft Dynamics 365 Business Central**, these tools work for any modern application requiring secure Exchange Online mail flow.

---

## 🌟 Key Features

*   ** Safety-First Approach**: Every App Registration is tagged with a unique description. The cleanup script verifies this tag before deletion to prevent accidental removal of mission-critical apps.
*   ** Infrastructure Auto-Fix**: Detects and remediates disabled `SmtpClientAuthentication` settings at both the Tenant and Mailbox levels.
*   ** Long-Term Stability**: Support for custom secret validity (up to 5 years) to minimize Business Central maintenance overhead.
*   ** Remote-Ready**: Full support for in-memory execution via GitHub Raw URLs (no local script files required).
*   ** Precision Diagnostics**: Verification scripts that audit everything from Entra ID service principals to mailbox-level ACLs.

---

##  Quick Start (REMOTE EXECUTION)

You don't even need to clone this repo. Run these commands directly in your PowerShell terminal:

### 1. Provision the Identity
Creates the App, Secret, and Mailbox permissions in one go.
```powershell
irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/refs/heads/main/Scripts/New-ExoOauthSmtpAppIdentity.ps1 | iex; 
New-ExoOauthSmtpAppIdentity -DisplayName "BC Mailer" -Mailboxes "info@contoso.com" -AddSendAs
```

### 2. Verify the Configuration
Ensures Entra ID and Exchange Online are perfectly synced.
```powershell
irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/refs/heads/main/Scripts/Test-ExoOauthSmtpAppIdentity.ps1 | iex; 
Test-ExoOauthSmtpAppIdentity -DisplayName "BC Mailer" -Mailboxes "info@contoso.com"
```

### 3. Send a Test Email
Validates the actual mail flow using your new Client ID and Secret.
```powershell
irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/refs/heads/main/Scripts/Test-MailNotification.ps1 | iex; 
Invoke-ApiMailNotification -ClientId "YOUR_ID" -ClientSecret "YOUR_SECRET" -Sender "info@contoso.com" -Recipient "admin@contoso.com"
```

---

## 📂 Deep-Dive Documentation

For detailed technical breakdowns, parameter lists, and advanced usage, see:

*   [**Provisioning Guide**](docs/New-ExoOauthSmtpAppIdentity.md): Creating long-term, safe identities.
*   [**Verification Guide**](docs/Test-ExoOauthSmtpAppIdentity.md): Diagnosing permission sync issues.
*   [**Cleanup Guide**](docs/Remove-ExoSmtpAppPrincipal.md): Precision decommissioning of apps and permissions.
*   [**SMTP Testing**](docs/Test-MailNotification.md): Validating end-to-end mail flow.

---

## ⚠️ Requirements

*   **Entra ID Permissions**: Global Administrator or (Application Administrator + Exchange Administrator).
*   **PowerShell Modules**: The scripts will auto-load `Microsoft.Graph` and `ExchangeOnlineManagement`.
*   **Environment**: PowerShell 7+ (Recommended) or Windows PowerShell 5.1.

---

## 🤝 Contributing & Safety
All changes are verified against [Pester](https://pester.dev/) unit tests. If you encounter issues or have improvements, feel free to open a PR or Issue.
