# Test-ExoOauthSmtpAppIdentity

## Synopsis
Verifies the configuration of an existing SMTP OAuth Application and its mailbox permissions.

## Description
This script is a diagnostic tool to validate that your Azure App, Service Principal, and Exchange Config are correctly set up **before** you try to connect Business Central. It checks:
1.  **App Existence:** Verifies the App Registration exists in Entra ID.
2.  **Service Principal:** Verifies the Enterprise App exists and has the correct Object ID.
3.  **API Permissions:** Checks if `SMTP.Send` or `SMTP.SendAsApp` is granted and consented.
4.  **Exchange Sync**: Confirms the Service Principal is correctly registered in Exchange Online.
5.  **Mailbox Permissions**: Verifies `FullAccess` and `SendAs` ACLs on target mailboxes.
6.  **SMTP Status:** Reports if `SmtpClientAuthenticationDisabled` is True or False. It identifies the **effective** setting by checking both mailbox-level and organization-wide (`Get-TransportConfig`) settings (handling "Inherited" cases).

## Usage

### Local Usage (Dot-Sourcing)

#### Check an App by Display Name
```powershell
. .\Test-ExoOauthSmtpAppIdentity.ps1; Test-ExoOauthSmtpAppIdentity -DisplayName "Organization SMTP Service" -Mailboxes "info@contoso.com"
```

#### Check using Client ID (Recommended)
```powershell
. .\Test-ExoOauthSmtpAppIdentity.ps1; Test-ExoOauthSmtpAppIdentity -ClientId "11111111-2222-3333-4444-555555555555" -Mailboxes "info@contoso.com"
```

### Remote Execution (One-Liner)
```powershell
irm "https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/main/Scripts/Test-ExoOauthSmtpAppIdentity.ps1" | iex; 
Test-ExoOauthSmtpAppIdentity -DisplayName "My App" -Mailboxes "info@contoso.com"
```

## Parameters & Switches

*   **`-DisplayName`** (String): Friendly name of the App Registration to audit.
*   **`-ClientId`** (String): The unique Application (Client) ID. Using this ensures zero ambiguity.
*   **`-Mailboxes`** (String[], **Mandatory**): List of mailboxes to verify permissions for.

## Diagnostic Logic: SMTP Authentication
Exchange Online allows disabling SMTP Authentication at two levels:
1.  **Mailbox Level**: `Set-CASMailbox -SmtpClientAuthenticationDisabled`
2.  **Organization Level**: `Set-TransportConfig -SmtpClientAuthenticationDisabled`

If the mailbox setting is `null` (default), it **inherits** from the Organization level. This script correctly identifies this "Inherited" state and queries the organization-wide configuration to provide the **Effective Status** (Enabled/Disabled).

## Outputs
*   **Console Output**: Color-coded status messages (STEP, INFO, OK, WARN, ERROR).
*   **Termination**: Throws a terminating error if a critical infrastructure component (App or SP) is missing.
