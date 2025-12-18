# Needs Review — Improvements & Hardening

This file lists concrete, reviewable improvements to make the scripts in this repository safer, more robust, and ready to be run directly from the repository (for example using `irm` / `Invoke-RestMethod` patterns). The goal is actionable items maintainers can pick up and implement.

## High priority

- Remove any embedded or example secrets from files. Example: `Test-ExoOauthSmtpAppIdentity.ps1` and `New-ExoOauthSmtpAppIdentity.ps1` contain sample secret/comment lines — rotate and remove immediately.
- Add `Set-StrictMode -Version Latest` and `ErrorActionPreference = 'Stop'` at the top of each script to fail fast and avoid surprising partial runs.
- Stop printing secrets to console. `New-ExoOauthSmtpAppIdentity.ps1` prints the `ClientSecret` (one-time-only). Instead: print a short note telling the user to copy it from the script output and store it in a secure store; redact the value in logs.

## Behavior & correctness

- Make scripts idempotent and explicitly handle partial states:
  - `New-ExoOauthSmtpAppIdentity.ps1`: if an app exists, don't create duplicate secrets by default — add `-RotateSecret` option and guard repeated secret creation.
  - `Remove-ExoSmtpAppPrincipal.ps1`: support force / best-effort removal when AppReg or ServicePrincipal is already gone; return non-zero exit code when cleanup fails.
- Validate inputs with `Param(... [ValidateNotNullOrEmpty()] )` and fail with helpful messages.
- Add explicit mailboxes existence checks before calling `Add-MailboxPermission` / `Remove-MailboxPermission` and report per-mailbox status.

## Safety for remote execution (irm / iex)

- Make scripts safe to run via piping from raw GitHub content (`irm https://raw.githubusercontent.com/... | iex`) by:
  - Avoiding interactive prompts by default; add `-NonInteractive` / `-Force` switches.
  - Adding a `-WhatIf` / `-Confirm`/`SupportsShouldProcess` pattern where destructive actions are taken.
  - Provide small example usage block in comment-based help showing the recommended safe invocation (download-then-inspect pattern):
    ```powershell
    Invoke-WebRequest -Uri <raw-url> -OutFile ./temp.ps1; Get-Content ./temp.ps1; pwsh ./temp.ps1 -ClientId ...
    ```

## Observability & debugging

- Add structured logging and an optional log file (`-LogPath`), and avoid dumping tokens/secrets in verbose output. Prefer `Write-Verbose` / `Write-Error` and honor `-Verbose` switches.
- Add consistent exit codes and meaningful messages for CI/automation to act upon.

## Testing & CI

- Add PSScriptAnalyzer to CI and a GitHub Action that runs it on push / PR. Rules to enable: `PSUseApprovedVerbs`, `PSAvoidUsingWriteHost`, `PSUseShouldProcess`.
- Add unit and integration tests using `Pester`:
  - Unit tests to validate helper functions (XOAUTH2 builder, token parsing).
  - A gated integration test job that runs `Test-ExoOauthSmtpAppIdentity.ps1` against a test tenant using GH Actions and secrets (only on protected branches).

## Documentation

- Update `README.MD` to match actual filenames and usage examples (`New-ExoOauthSmtpAppIdentity.ps1`, `Test-ExoOauthSmtpAppIdentity.ps1`, `Remove-ExoSmtpAppPrincipal.ps1`). The current README references different filenames like `Setup-SMTP-Service.ps1` and `Test-SMTP-Connection.ps1` which are outdated.
- Add example `irm` usage and a clear warning about vetting scripts before running remotely.

## Security & permissions

- Make explicit in READMEs which Azure permissions are required (e.g., `Application.ReadWrite.All`, `Directory.Read.All`, and admin consent for `SMTP.SendAsApp`) and what admin role is needed.
- Consider adding optional certificate-based authentication or MSAL client assertion flow as an alternative to client secrets in long-lived automation.

## Small developer quality fixes

- Use `Try/Catch` blocks that rethrow or set meaningful exit codes and include remote API response bodies if available (already done in some places; make consistent across scripts).
- Normalize parameter names and aliases across scripts (`ClientId`/`ClientID`, `ClientSecret`/`SecretValue`, `SenderEmail`/`MailSender`).
- Add a small `CONTRIBUTING.md` to document how to add scripts or tests and how to run them locally.

---
If you want, I can implement the highest-priority items (top: remove sample secrets, add strict mode + ErrorActionPreference, add param validation, and add a PSScriptAnalyzer GitHub Action). Which items should I start with? If you meant a different command than `irm` when you wrote "irc/irm", tell me and I'll show the recommended command usage and safety patterns.
