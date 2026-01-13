# Test-ExoOauthSmtpAppIdentity

## Synopsis
Verifies the configuration of an existing SMTP OAuth Application and its mailbox permissions.

## Description
This script is a diagnostic tool to validate that your Azure App, Service Principal, and Exchange Config are correctly set up **before** you try to connect Business Central. It checks:
1.  **App Existence:** Verifies the App Registration exists.
2.  **Service Principal:** Verifies the Enterprise App exists and has the correct Object ID.
3.  **API Permissions:** Checks if `SMTP.Send` or `SMTP.SendAsApp` is granted.
4.  **Mailbox Permissions:** Checks if the Service Principal has `FullAccess` (and optionally `SendAs`) on the target mailboxes.
5.  **SMTP Status:** Reports if `SmtpClientAuthenticationDisabled` is True or False for the tenant and mailbox.

## Usage

### Check an App by Display Name
```powershell
.\Test-ExoOauthSmtpAppIdentity.ps1 -DisplayName "Organization SMTP Service" -Mailboxes "info@contoso.com"
```

### Check using Client ID
```powershell
.\Test-ExoOauthSmtpAppIdentity.ps1 -ClientId "11111111-2222-3333-4444-555555555555" -Mailboxes "info@contoso.com"
```

### Remote Execution (One-Liner)
```powershell
irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/refs/heads/main/Scripts/Test-ExoOauthSmtpAppIdentity.ps1 | iex; Test-ExoOauthSmtpAppIdentity -DisplayName "My App" -Mailboxes "info@contoso.com"
```

## Parameters

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| **DisplayName** | String | No | The display name of the app to test. |
| **ClientId** | String | No | The Application (Client) ID of the app to test. (Provide either DisplayName or ClientId). |
| **Mailboxes** | String[] | Yes | The email addresses to check permissions against. |

## Outputs
*   **Console Output:** innovative status messages (color-coded) indicating Pass/Fail for each check.
*   **Error:** Throws a terminating error if a critical check fails.
