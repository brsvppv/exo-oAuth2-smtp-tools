# Remove-ExoSmtpAppPrincipal

## Synopsis
Cleanly removes the Azure App, Service Principal, and associated permissions.

## Description
Use this script to decommission an SMTP App Identity. It performs a clean sweep:
1.  **Removes Mailbox Permissions:** Revokes `FullAccess` and `SendAs` from all mailboxes the app had access to.
2.  **Removes Service Principal:** Deletes the Enterprise App from the tenant.
3.  **Removes App Registration:** Deletes the App Registration from Entra ID.

## Usage

### Local Usage (Dot-Sourcing)

####Remove by Display Name
```powershell
. .\Remove-ExoSmtpAppPrincipal.ps1; Remove-ExoSmtpAppPrincipal -DisplayName "Organization SMTP Service"
```
**Technical Breakdown:**
1.  **Identity Discovery**: Searches for the App Registration and Service Principal by the friendly name.
2.  **Ambiguity Protection**: If more than one app shares this name, the script **halts immediately** to prevent accidental deletion.
3.  **Core Deletion**:
    *   Removes the **Service Principal** from Exchange Online.
    *   Removes the **Enterprise Application** from Entra ID.
    *   Removes the **App Registration** from Entra ID.
4.  **Limitation**: Since no mailboxes were provided, the **FullAccess/SendAs permissions remain** on the mailboxes. This is useful for "re-creation" but not for full decommissioning.

#### Remove by Client ID (Recommended)
```powershell
. .\Remove-ExoSmtpAppPrincipal.ps1; Remove-ExoSmtpAppPrincipal -ClientId "11111111-2222-3333-4444-555555555555" -Mailboxes "info@contoso.com"
```
**Technical Breakdown:**
1.  **Guaranteed Precision**: Targets the specific App using its unique GUID.
2.  **Safety Tag Check**: Verifies if the app has the `"Created by..."` description. If missing, it prompts for a manual `YES` confirmation.
3.  **Permission Revocation**: Scans the `info@contoso.com` mailbox and explicitly removes the specific `FullAccess` and `SendAs` ACLs associated with this app.
4.  **Scorched Earth**: Once permissions are clear, it permanently deletes the App Registration and all associated service identities from the tenant.

### Remote Execution (One-Liner)
```powershell
irm "https://raw.githubusercontent.com/brsvppv/exo-oAuth2-smtp-tools/main/Scripts/Remove-ExoSmtpAppPrincipal.ps1" | iex; 
Remove-ExoSmtpAppPrincipal -DisplayName "Org SMTP" -Mailboxes "info@contoso.com"
```
**Technical Breakdown:**
1.  **Stateless Deletion**: Decommissions the setup using a single command without requiring you to have any local script files.
2.  **Full Cleanup**: Correctly handles both the mailbox permissions and the Entra identity lifecycle in a single workflow.


## Parameters & Switches

*   **`-DisplayName`** (String): Searches for the identity using its friendly name in Entra ID. Use this when you don't have the Client ID handy. *Warning: The script will abort if multiple apps share the same name.*
*   **`-ClientId`** (String, **Preferred**): Targets the identity using the unique Application ID. This is the safest way to ensure you are deleting the correct app.
*   **`-Mailboxes`** (String[]): A list of mailboxes to scan for cleanup. If provided, the script will explicitly revoke `FullAccess` and `SendAs` permissions for the target identity on these mailboxes.
*   **`-WhatIf`** (Switch): Standard PowerShell switch. Run the script with this to see a simulation of what would be deleted without actually making any changes.
*   **`-Confirm`** (Switch): Standard PowerShell switch. Prompts you for confirmation before each destructive step (Permission removal, App deletion, etc.).

## Safety
*   **Confirmation:** The script protects against accidental deletion by requiring explicit targets.
*   **Idempotent:** It checks if the object exists before trying to delete it.
