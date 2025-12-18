## Purpose
This repository contains automation scripts (primarily PowerShell) to provision, validate, and remove OAuth2 Client Credentials flow for sending mail through Exchange Online SMTP. These instructions give AI coding agents the minimal, actionable context to make safe, focused changes.

## Big picture
- Primary goal: manage EXO OAuth2 SMTP App identities (create app, grant `SMTP.SendAsApp`, test SMTP via XOAUTH2, remove artifacts).
- Languages: PowerShell (Scripts/). Small Python utilities may exist but PowerShell is canonical for provisioning and testing.
- External integrations: Azure AD (App Registration, client secret, app permissions) and Exchange Online SMTP (smtp.office365.com:587 STARTTLS).

## Key files to read first
- `Scripts/Test-ExoOauthSmtpAppIdentity.ps1` — end-to-end example: obtains token, builds XOAUTH2 base64 string, performs STARTTLS and AUTH XOAUTH2 handshake. Note: scope uses `https://outlook.office365.com/.default` (not Microsoft Graph).
- `Scripts/New-ExoOauthSmtpAppIdentity.ps1` — provisioning (create App Registration / secret / service principal and grant permissions).
- `Scripts/Remove-ExoSmtpAppPrincipal.ps1` — cleanup steps to remove permissions/service principal.
- `config/` — any environment-specific settings; secrets are passed as runtime params and must not be committed.

## Important, discoverable behaviors & conventions
- All scripts accept secrets/IDs as parameters; do not hardcode credentials. Example usage pattern is shown in `Test-ExoOauthSmtpAppIdentity.ps1`'s header comment.
- TLS is explicitly enforced in scripts: they set `Tls12` via `[Net.ServicePointManager]::SecurityProtocol` before network calls — keep this intact when editing network code.
- Token scope: scripts use the EXO SMTP scope (`https://outlook.office365.com/.default`). Never replace this with Graph unless the code and Azure permissions were explicitly changed and tested.
- SMTP flow: scripts implement plain TCP EHLO → STARTTLS → SslStream.AuthenticateAsClient → EHLO → AUTH XOAUTH2 → MAIL DATA → QUIT. Preserve this sequence in tests.

## Typical developer workflows (how to run & debug)
- Run tests and tooling from the `Scripts/` folder in PowerShell (PowerShell 7+ recommended). Typical command (example):
```
.
\Scripts\Test-ExoOauthSmtpAppIdentity.ps1 -ClientId <id> -TenantId <id> -ClientSecret <secret> -SenderEmail no-reply@domain.com -RecipientEmail admin@domain.com -Verbose
```
- Use `-Verbose` to surface detailed Invoke-RestMethod errors — the scripts print Azure error responses when available.
- Common debugging checks: ensure TLS1.2 enforced, confirm token scope is `https://outlook.office365.com/.default`, verify `SMTP.SendAsApp` permission and mailbox grants, and watch for SMTP replies `235` (success) vs `535` (auth fail).

## Code change guidance for agents
- Small edits to PowerShell scripts should preserve parameterized secrets and existing input signatures. When adding features, add parameters rather than inlined secrets.
- When touching network/auth code, keep exact send/expect SMTP codes and ordering (EHLO/STARTTLS/EHLO/AUTH). Tests depend on these sequences.
- If adding Azure permission changes, update README.MD and scripts' usage comments to reflect new scopes or consent requirements.

## Security & release notes
- Never commit ClientSecret, TenantId, or production addresses. The repo expects runtime params for secrets.
- If a sample secret appears in a script (left for developer convenience), flag it for immediate rotation and update the repository to remove it.

## Examples (copyable patterns)
- Build XOAUTH2 token (from `Test-ExoOauthSmtpAppIdentity.ps1`):
```
$XOAUTH2String = "user=$SenderEmail`x01auth=Bearer $AccessToken`x01`x01"
$XOAUTH2Base64 = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($XOAUTH2String))
```
- Token request body uses client_credentials grant and scope `https://outlook.office365.com/.default`.

## Where to look for follow-ups
- For provisioning logic: `Scripts/New-ExoOauthSmtpAppIdentity.ps1`
- For removal logic: `Scripts/Remove-ExoSmtpAppPrincipal.ps1`
- For sending/email-format examples: `Scripts/Test-MailNotification.ps1`

---
If anything looks incomplete or you want the agent to follow a stricter editing policy (tests, commit hooks, formatting), tell me which parts to tighten and I will update this file.
