# exo-oauth2-smtp-tools

A collection of automation scripts (PowerShell & Python) to configure, validate, and decommission **OAuth 2.0 Client Credentials Flow** for sending emails via Microsoft Exchange Online (EXO).

These tools replace Basic Authentication (Legacy Auth) for applications and services like **Dynamics 365 Business Central**.

## ⚠️ Security Warning
**NEVER commit `Client Secret` values or `Tenant IDs` to this repository.**
All scripts are designed to accept secrets as runtime parameters. If you commit a secret, rotate it immediately using the Cleanup and Setup tools.

---

## 📂 PowerShell Tools (`/Scripts`)

### Prerequisites
* **PowerShell 7+** (recommended)
* **Modules:** `Microsoft.Graph.Applications`, `ExchangeOnlineManagement` (scripts try to install them if missing)
* **Protocol:** TLS 1.2 is required.

### Scripts
* **`New-ExoOauthSmtpAppIdentity.ps1`**: Provisioning script (legacy).
* **`New-ExoOauthSmtpAppIdentity_v2.ps1`**: Production-ready provisioning with options for secure secret storage and config-driven runs.
  - Secrets are NOT printed by default. Options to retrieve or store the secret:
    - `-ShowSecret` (explicitly show the one-time secret on-screen)
    - `-ExportSecretPath <path>` (plain file; attempts to set restrictive ACLs)
    - `-ExportProtectedPath <path>` (Windows DPAPI, CurrentUser — recommended for local protected files)
    - `-UseSecretManagement` (store in configured SecretManagement vault such as `SecretStore`)
* **`Test-ExoOauthSmtpAppIdentity.ps1`**: Validates SMTP XOAUTH2 flow (STARTTLS -> AUTH XOAUTH2 -> send email).
* **`Remove-ExoSmtpAppPrincipal.ps1`**: Cleanup script to remove permissions and registration.

### Protected export (DPAPI)
Protected files written by `-ExportProtectedPath` are encrypted to the current Windows account using DPAPI and are only retrievable by the same user on the same machine. To read a protected secret file:
```powershell
$b64 = Get-Content C:\secrets\smtp_secret.prot -Raw
$bytes = [Convert]::FromBase64String($b64)
$plain = [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
Write-Output $plain
```

---

## 📂 Config
* Example config: `config/smtp-app.example.json` — copy and update for your environment.

---

If you'd like, I can add a `Get-ProtectedSecretFromFile.ps1` helper script or extend tests to validate the protected export flow.

---

## 🚀 Quick Start — Fresh Windows

1) Clone the repository and open PowerShell 7+ (recommended).

2) Bootstrap your machine (installs required modules and creates `config/smtp-app.json`):

```powershell
pwsh -File .\Scripts\Bootstrap-Environment.ps1
``` 

3) Edit `config/smtp-app.json` and set the following fields (example):

```json
{
  "DisplayName": "Organization SMTP Service",
  "TenantId": "<your-tenant-id>",
  "Mailboxes": ["no-reply@contoso.com","notify@contoso.com"],
  "SecretValidityYears": 2
}
```

4) Provide the client secret securely (one of):
- export environment variable (recommended for one-off runs):

```powershell
setx EXO_SMTP_CLIENT_SECRET "<your-client-secret>"
```

- or set `ExportProtectedPath` in the config to write a DPAPI-protected file during provisioning, or use `-UseSecretManagement` to store in a secret vault.
  - The `-ConfigPath` parameter accepts either a local file path or a URL to a raw JSON/YAML config (the script will download it). For example:

```powershell
# Provide a remote config URL directly:
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/New-ExoOauthSmtpAppIdentity_v3.ps1')
New-ExoOauthSmtpAppIdentity -ConfigPath 'https://raw.githubusercontent.com/<owner>/<repo>/main/config/smtp-app.example.json' -NonInteractive
```

Or download the config first locally and pass the path:

```powershell
irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/config/smtp-app.example.json' -OutFile ./config/smtp-app.json
New-ExoOauthSmtpAppIdentity -ConfigPath ./config/smtp-app.json -NonInteractive
```

---

### One-line IRM examples (interactive and non-interactive)

Interactive (prompts; recommended for first run):
```powershell
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Run-Interactive-Setup.ps1')
```

Non-interactive (automation; requires config URL or path and explicit choices):
```powershell
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Run-Interactive-Setup.ps1') ; \
  Run-Interactive-Setup -ConfigUrl 'https://raw.githubusercontent.com/<owner>/<repo>/main/config/smtp-app.example.json' -NonInteractive -SecretStorage DPAPI -ExportProtectedPath 'C:\secrets\smtp_secret.prot' -RotateSecret -Force
```

Dry run example (validate config and mailboxes only):
```powershell
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Run-Interactive-Setup.ps1') ; \
  Run-Interactive-Setup -ConfigPath ./config/smtp-app.json -NonInteractive -DryRun
```

---

### One-line remote examples (safe patterns)

- Dry-run (remote script inspected by operator):
```powershell
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Run-Interactive-Setup.ps1'); \
  Run-Interactive-Setup -ConfigUrl 'https://raw.githubusercontent.com/<owner>/<repo>/main/config/smtp-app.example.json' -NonInteractive -DryRun
```

- Production run (only after DryRun validated; secrets handled via DPAPI or SecretManagement):
```powershell
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/Run-Interactive-Setup.ps1'); \
  Run-Interactive-Setup -ConfigUrl 'https://raw.githubusercontent.com/<owner>/<repo>/main/config/smtp-app.example.json' -NonInteractive -SecretStorage DPAPI -ExportProtectedPath 'C:\secrets\smtp_secret.prot' -RotateSecret -Force -LogPath 'C:\logs\exo-setup.log'
```

**Security note:** Always inspect the remote script before running `iex`. Prefer download-then-inspect or run the pre-run helper (`Scripts/Check-PreRun.ps1`) to run lint/tests locally before invoking remote code.

---

### Logging & Diagnostics

- **Console output is always shown** to the operator so you can see progress and warnings.
- **Optional file logging**: pass `-LogPath <path>` to `Run-Interactive-Setup` (or the top-level wrapper) to also append timestamped logs to the specified file.
  - Example: `Run-Interactive-Setup -ConfigPath ./config/smtp-app.json -NonInteractive -LogPath 'C:\logs\exo-setup.log'`
- **Command tracing**: opt-in trace via `-TraceCommands` (off by default); when enabled the script logs higher-fidelity command traces to console & file (if `-LogPath` set).
  - Use with caution: tracing may increase verbosity; secrets are redacted in logs automatically (the script will not write raw client secrets to the log file).
- **Sensitive data handling:**
  - ONE-TIME CLIENT SECRET is shown on-screen when `-ShowSecret` or the interactive choice is used; it is explicitly **not** written to log files.
  - If you want to persist a secret, use `-ExportProtectedPath` (DPAPI) or `-UseSecretManagement` to store in a vault.

---

## Contributing & CI checks

- **Secret scanning (gitleaks)** runs on PRs and weekly scheduled jobs. If secrets are found the job fails and a `gitleaks-report.json` artifact is produced.
- **PSScriptAnalyzer** runs during CI; this repository blocks PRs that introduce disallowed rules such as `PSAvoidUsingWriteHost` or `PSUseApprovedVerbs`.

See `CONTRIBUTING.md` for instructions to run these checks locally and for guidance on correcting common violations.

### Running the pre-run helper locally

We provide a small helper that runs the same checks used in CI (PSScriptAnalyzer, gitleaks, and unit tests). Run it locally before invoking `iex` on the remote script:

```powershell
pwsh -File .\Scripts\Check-PreRun.ps1
```

If you need to skip gitleaks or the analyzer while testing locally, pass the switches `-SkipGitleaks` or `-SkipAnalyzer` respectively.

Notes:
- `-Force` allows the script to auto-install SecretManagement modules in non-interactive mode when required.
- `-SecretStorage` accepts: `ShowOnce` (default), `DPAPI`, `SecretStore`, or `None`.
- Always inspect remote scripts before running them with `iex (irm ...)`.

5) Run the provisioning script (non-interactive recommended after bootstrapping):

```powershell
iex (irm 'https://raw.githubusercontent.com/<owner>/<repo>/main/Scripts/New-ExoOauthSmtpAppIdentity_v3.ps1')
New-ExoOauthSmtpAppIdentity -ConfigPath ./config/smtp-app.json -NonInteractive
```

Notes:
- `Mailboxes` is an array of mailbox addresses to check and optionally assign rights for; the script verifies existence and warns if missing.
- App-only SMTP requires the `SMTP.SendAsApp` application permission and admin consent; the script will create the App Registration and Service Principal but admin consent may need to be granted via portal or pre-approved in your tenant.

