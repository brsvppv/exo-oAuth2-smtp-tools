# Remote Provisioning Flow — Run via iex/irm 🔐

Purpose: provide a safe, repeatable flow for running the provisioning script remotely (no module publish required). Use this to create the OAuth App, Service Principal, and validate mailbox permissions for EXO SMTP XOAUTH2.

---

## Summary (short)
1. Inspect the remote script (do not run blindly).  
2. Run local pre-checks (`Scripts/Check-PreRun.ps1`).  
3. Run a **DryRun** remotely (`-DryRun`) to validate config and mailboxes.  
4. If DryRun looks good, run the production command (use DPAPI or SecretManagement to persist secrets).  
5. Verify by running the included test script.

---

## Preconditions
- PowerShell 7+ recommended.
- You have an account that can register Azure Apps and grant Service Principal permissions (or will coordinate with an admin to grant consent).  
- The repository has no leaked secrets (run gitleaks locally or check CI artifacts).

---

## Step 1 — Inspect the script
- **Never** run a remote script without inspecting it first.
- Open the raw file in your browser or download and inspect locally:
```powershell
# Download and inspect
irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Invoke-InteractiveSetup.ps1' -OutFile ./Invoke-InteractiveSetup.ps1
Get-Content ./Invoke-InteractiveSetup.ps1 -Head 80 | Out-Host
```
- Prefer using a **tagged release** for production to avoid code drift:
  - https://raw.githubusercontent.com/<owner>/<repo>/v1.0.0/Scripts/Invoke-InteractiveSetup.ps1

---

## Step 2 — Run pre-checks locally
- Use the helper that mirrors CI checks:
```powershell
pwsh -File .\Scripts\Check-PreRun.ps1
```
- The helper runs PSScriptAnalyzer, gitleaks, and Pester unit tests. Fix any issues before proceeding.

---

## Step 3 — Remote DryRun (validate only)
- Dry-run checks config and mailbox availability without creating resources.
- Example (remote DryRun):
```powershell
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Invoke-InteractiveSetup.ps1'); \
  Invoke-InteractiveSetup -ConfigUrl 'https://raw.githubusercontent.com/<owner>/<repo>/main/config/smtp-app.example.json' -NonInteractive -DryRun
```
- Or use inline JSON:
```powershell
$cfg = '{"DisplayName":"My SMTP App","TenantId":"00000000-0000-0000-0000-000000000000","Mailboxes":["no-reply@contoso.com"]}'
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Invoke-InteractiveSetup.ps1'); \
  Invoke-InteractiveSetup -ConfigPath $cfg -NonInteractive -DryRun
```

---

## Step 4 — Production run (create resources)
- After a successful DryRun, run the production invocation. Examples:

DPAPI protected export (local protected file):
```powershell
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Invoke-InteractiveSetup.ps1'); \
  Invoke-InteractiveSetup -ConfigUrl 'https://raw.githubusercontent.com/<owner>/<repo>/main/config/smtp-app.example.json' -NonInteractive -SecretStorage DPAPI -ExportProtectedPath 'C:\secrets\smtp_secret.prot' -RotateSecret -Force -LogPath 'C:\logs\exo-setup.log'
```

SecretManagement vault (recommended for automation):
```powershell
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Invoke-InteractiveSetup.ps1'); \
  Invoke-InteractiveSetup -ConfigUrl 'https://raw.githubusercontent.com/<owner>/<repo>/main/config/smtp-app.example.json' -NonInteractive -UseSecretManagement -RotateSecret -Force
```

Notes:
- `-Force` auto-installs `SecretManagement`/`SecretStore` in non-interactive mode if required.
- `-LogPath` is optional (console output is always shown); secrets are redacted in logs.
- `-TraceCommands` is opt-in for verbose tracing if you need command-level detail.

---

## Step 5 — Verification (test sending mail)
- Use the test helper to perform an XOAUTH2 SMTP send:
```powershell
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Test-ExoOauthSmtpAppIdentity.ps1'); \
  Test-ExoOauthSmtpAppIdentity -ClientId <client-id> -TenantId <tenant> -ClientSecret <secret> -SenderEmail no-reply@contoso.com -RecipientEmail admin@contoso.com -Verbose
```
- Check SMTP response codes: `235` = success; `535` = auth fail. Ensure the app has `SMTP.SendAsApp` and admin consent if required.

---

## Secrets handling guidelines (imperative)
- Do not commit secrets to source control. If a secret is ever committed, rotate it immediately and follow the git-history purge playbook in `docs/GIT_HISTORY_PURGE_PLAYBOOK.md`.
- Storage options:
  - **ShowOnce** — secrets displayed on console only (default for interactive flows). Not stored.
  - **DPAPI** (`-ExportProtectedPath`) — encrypted file bound to the current Windows user/machine.
  - **SecretManagement** (`-UseSecretManagement`) — preferred for automation and vault storage.

---

## Troubleshooting tips 🔧
- If DryRun shows missing TenantId or missing mailboxes, fix the config and re-run DryRun.
- If provisioning fails with permissions errors, confirm the operator account has app registration and Exchange admin privileges.
- If gitleaks or analyzer finds issues, fix them and re-run `Scripts/Check-PreRun.ps1`.

---

## Release and reproducibility ✨
- For production readiness, tag releases and use the raw URL from a tag (e.g., `v1.0.0`) in your `iex` commands to ensure immutability.
- If you want, create an `install.ps1` wrapper that defaults to DryRun and points to a tagged release.

---

## Quick checklist before making repository public
- Run gitleaks across history and review artifacts.  
- Remove or scrub any secrets from history, rotate secrets.  
- Re-run PSScriptAnalyzer and fix disallowed rules.  
- Ensure README, LICENSE, and CHANGELOG are present and correct.

---

If you'd like, I can add an `install.ps1` wrapper and create a **draft tag/release** (e.g., `v1.0.0`) so your team can run a stable `iex` command for production. Let me know and I'll proceed.