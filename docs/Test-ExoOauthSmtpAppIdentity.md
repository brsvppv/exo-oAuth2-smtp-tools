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
**Technical Breakdown:**
1.  **Identity Search**: Matches the name "Organization SMTP Service" against your Entra ID tenant.
2.  **SP Validation**: Confirms that a Service Principal exists for the app (essential for mailbox permissions).
3.  **Permissions Audit**: Scans the ACLs of `info@contoso.com` to confirm that the specific App's Object ID has been granted `FullAccess`.

### Check using Client ID
```powershell
.\Test-ExoOauthSmtpAppIdentity.ps1 -ClientId "11111111-2222-3333-4444-555555555555" -Mailboxes "info@contoso.com"
```
**Technical Breakdown:**
1.  **Exact Matching**: Bypasses name-based search to diagnostic the specific app ID you've entered in Business Central.
2.  **Consistency Check**: Compares the Client ID with the Service Principal to ensure they are properly "linked" in the directory.
3.  **Advanced Mailbox Audit**: Checks for both `FullAccess` and `SendAs` permissions on the target mailbox.

### Remote Execution (One-Liner)
```powershell
irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/refs/heads/main/Scripts/Test-ExoOauthSmtpAppIdentity.ps1 | iex; Test-ExoOauthSmtpAppIdentity -DisplayName "My App" -Mailboxes "info@contoso.com"
```
**Technical Breakdown:**
1.  **Ad-hoc Health Check**: Validates your setup immediately from the cloud without needing local dependencies.
2.  **Comprehensive Scan**: Performs all 5 critical checks (App, SP, Permissions, SMTP Auth, Tenant Scopes) in a single pass.

## Parameters & Switches

*   **`-DisplayName`** (String): The friendly name of the App Registration to audit. The script will try to find the App ID based on this name.
*   **`-ClientId`** (String): The unique Application (Client) ID. Using this ensures the diagnostic script is checking the exact same identity that is configured in your Business Central SMTP Setup.
*   **`-Mailboxes`** (String[], **Mandatory**): The list of mailboxes to verify permissions for. The script checks if the app's Service Principal has been granted the necessary ACLs (`FullAccess` / `SendAs`) on each of these targets.

## Outputs
*   **Console Output:** innovative status messages (color-coded) indicating Pass/Fail for each check.
*   **Error:** Throws a terminating error if a critical check fails.
