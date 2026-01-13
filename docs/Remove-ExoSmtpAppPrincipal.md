# Remove-ExoSmtpAppPrincipal

## Synopsis
Cleanly removes the Azure App, Service Principal, and associated permissions.

## Description
Use this script to decommission an SMTP App Identity. It performs a clean sweep:
1.  **Removes Mailbox Permissions:** Revokes `FullAccess` and `SendAs` from all mailboxes the app had access to.
2.  **Removes Service Principal:** Deletes the Enterprise App from the tenant.
3.  **Removes App Registration:** Deletes the App Registration from Entra ID.

## Usage

### Remove by Display Name
```powershell
.\Remove-ExoSmtpAppPrincipal.ps1 -DisplayName "Organization SMTP Service"
```

### Remove by Client ID (Recommended)
```powershell
.\Remove-ExoSmtpAppPrincipal.ps1 -ClientId "11111111-2222-3333-4444-555555555555" -Mailboxes "info@contoso.com"
```

### Remote Execution (One-Liner)
```powershell
irm https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/refs/heads/main/Scripts/Remove-ExoSmtpAppPrincipal.ps1 | iex; Remove-ExoSmtpAppPrincipal -DisplayName "Org SMTP" -Mailboxes "info@contoso.com"
```

## Parameters

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| **DisplayName** | String | No | The display name of the app to remove. (Use caution). |
| **ClientId** | String | No | The Application (Client) ID of the app to remove. (Preferred). |
| **Mailboxes** | String[] | **Yes** | The list of mailboxes to clean permissions from. |

## Safety
*   **Confirmation:** The script protects against accidental deletion by requiring explicit targets.
*   **Idempotent:** It checks if the object exists before trying to delete it.
