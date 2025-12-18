# Configuration Modernization & Comprehensive Audit

Date: 2025-12-16

Author: Senior DevOps Architect (audit performed on repository state)

Purpose: Deliver a holistic audit of configuration management, security, code quality, and recommended modernization roadmap including prioritized action items, migration strategies, proof-of-concept snippets, and success metrics.

---

## 1) Executive Summary ✅

The repository provides PowerShell tooling to create and test Exchange Online SMTP OAuth2 Client-Credentials flows. It is operationally useful but has gaps that prevent safe automation at scale: committed secrets in repo history (critical), inconsistent config loading and validation, limited CI/test coverage, and ad-hoc secret handling oriented to local usage (DPAPI / SecretStore). The project is one step away from being automation-ready — the primary work is to centralize configuration, enforce secret-safe workflows (vault-first), add strict validation, and lock CI and pre-commit checks.

Major immediate risk: at least one secret is present in the repo (`config/oAuth_config_v2.json` contains a `SecretValue`). This must be rotated and removed from history immediately.

High-level recommendation: apply a phased modernization plan that (1) eliminates committed secrets and adds scanning, (2) centralizes configuration and validation, (3) migrates to vault-backed secret storage, (4) enforces CI and tests, and (5) gradually migrates provisioning to IaC (Terraform/Bicep) with managed-identity automation for production flows.

---

## 2) Current State Findings (detailed) 🔎

- Configuration formats found:
  - JSON examples in `config/` (e.g., `oAuth_config_v2.json`, `smtp-app.example.json`).
  - Parameters across scripts (PowerShell Param blocks) used in lieu of a centralized config loader.

- Secrets & Sensitive Data:
  - **Critical**: `config/oAuth_config_v2.json` contains `"SecretValue": "1Ag8Q~..."` (committed secret). Also `Scripts/simple/Test-ExoOauthSmtpAppIdentity.ps1` contains hard-coded `$ClientSecret` sample. (See `Needs_Review.md`.)
  - The v2 and v3 scripts provide options for DPAPI-protected exports and optional SecretManagement storage, but there is no enforced vault-first flow.

- Validation & Robustness:
  - Some scripts use `Set-StrictMode` and parameter validation; others print secrets, and parameter naming is inconsistent.
  - No JSON Schema or strict validation for `config/*.json` files.

- Observability & CI:
  - No PSScriptAnalyzer, Pester tests, or pre-commit secret detection currently enforced.

- Idempotence & Automation:
  - v2/v3 scripts implement idempotent patterns but some legacy scripts still create secrets and print them (not safe for automation).

- Cross-platform considerations:
  - DPAPI-protected export is Windows CurrentUser scoped — good for single-machine usage, not for CI or multi-machine automation.

---

## 3) Risks & Immediate Remediations (0–24 hours) 🚨

1. Rotate the secret(s) immediately that were committed and remove them from the repository: RISK = critical.
   - Steps (immediate):
     - Rotate secrets in the tenant (Azure portal/PowerShell).
     - Remove secrets from repo files and replace with placeholders.
     - Purge history using `git filter-repo` or BFG and force-push to protected branches; follow org policy.
     - Add `gitleaks` / `truffleHog` to scanning Actions and pre-commit hook to prevent recurrence.
   - Success metric: no discovered leaked secrets in the repository or the last N commits; scans return 0 critical findings.

2. Make scripts safe-by-default (if not already): disable automatic printing of secrets and add `-ShowSecret` as an explicit opt-in. (v3 already follows this.)

3. Add a temporary readme note and PR blocking policy that disallows committed secrets and requires rotating any rotated secrets to be reported.

---

## 4) Architecture & Configuration Strategy Recommendations (Design) 🏗️

Goal: Centralize configuration, enable safe secret injection, and support automation (CI/CD) and local development with the same patterns.

Principles to adopt:
- 12-Factor App (config via environment for automated runs).
- Principle of Least Privilege (short-lived credentials, managed identities). 
- Validate early: fail-fast with schema validation.
- Vault-first secret storage; local DPAPI/SecretStore as a fallback for single-machine workflows.

Concrete design:
- Canonical config file(s): keep examples in `config/` but canonical runtime config should be environment variables (for CI & automation) or a single validated config file that can be `--config` loaded for local runs.
- Implement a `Scripts/Load-Config.ps1` helper (proof-of-concept snippet below) that supports:
  - JSON and YAML (`ConvertFrom-Json`, `YamlDotNet` via PowerShell module or `powershell-yaml`),
  - Schema validation via JSON Schema or a lightweight custom validator, and
  - Environment variable overrides.
- Secret handling:
  - For automation (GH Actions / Azure Pipelines): store secrets in GitHub Secrets / Azure Key Vault and inject at runtime.
  - For local developer workflows: use `Microsoft.PowerShell.SecretManagement` with a LocalSecretStore or Azure Key Vault backing.
  - Keep DPAPI-only as a documented, local fallback.

---

## 5) Tooling & Comparative Matrix (Secrets & Config) 🧾

Secrets Management comparison (short):

| Tool | Use case | Pros | Cons | Recommendation |
|---|---|---|---|---|
| Azure Key Vault | Azure automation & production | Managed identities, RBAC, native with Azure, fully supported in pipelines | Requires Azure infra ops, some permissions complexity | **Primary** for Azure-hosted automation (High)
| HashiCorp Vault | Multi-cloud & advanced secrets (dynamic) | Dynamic secrets, leasing, broad platform support | More operational complexity to run | Good for multi-cloud, high-security requirements (Medium)
| GitHub Secrets | CI secrets for GH Actions | Easy, masked in logs, integrated | Not ideal for runtime secrets in long-lived infra | Use for GH Actions only (Medium)
| Microsoft.PowerShell.SecretManagement + SecretStore | Local dev convenience | Simple local dev workflow, vault adapters | Local store is machine-bound (SecretStore) | Use for developer UX + vault adapters (High for dev)

Config storage comparison (JSON vs YAML vs Hybrid):

| Format | Pros | Cons | Recommendation |
|---|---|---|---|
| JSON | Native for scripts, strict typing | Verbose, lacks comments | Keep for examples and machine-driven configs (OK)
| YAML | Readable, supports comments | Parsing differences, indentation-sensitive | Good for human-edited configs and advanced environments (Recommended for ops)
| Hybrid (JSON + env overrides) | Best of both: machine defaults + env overrides for automation | Slightly more complex | **Recommended**: store canonical example in JSON/YAML, use env for overrides (High)

---

## 6) IaC & Provisioning Recommendations 🌐

Current scripts are procedural (PowerShell/Graph) — which is fine for small scopes and operators. For production and repeatability, provide an IaC layer to declare application/service principal and permission assignment.

Suggested IaC options:
- Terraform (recommended): `azuread` or `azuread` + `azureRM` providers can create `azuread_application`, `azuread_service_principal`, and `azuread_application_password` resources. Works cross-platform and supports state.
- Bicep/ARM: if you prefer Azure-native IaC and want to run under Azure pipelines, consider Bicep for infra-as-code of related resources.

PoC Terraform snippet (create app + secret):
```hcl
resource "azuread_application" "smtp_app" {
  display_name = "smtp-app"
}

resource "azuread_service_principal" "smtp_sp" {
  application_id = azuread_application.smtp_app.application_id
}

resource "azuread_application_password" "smtp_secret" {
  application_object_id = azuread_application.smtp_app.object_id
  end_date_relative     = "720h" # 30d
}
```

Note: Terraform's lifecycle differs from Graph-based PowerShell. Use IaC for declaration and use scripts for one-off consent flows where needed.

---

## 7) CI, Quality, and Tests 📈

Minimum CI to add:
- PSScriptAnalyzer GitHub Action (fail on critical rules).
- gitleaks Action to block secrets in PRs.
- Pester unit tests for helper functions (e.g., XOAUTH2 builder, DPAPI protect/unprotect round-trip), run in PRs.
- Optional gated integration job for `Test-ExoOauthSmtpAppIdentity.ps1` running on protected branches using test tenant credentials stored as GH Secrets.

Example GH Action skeleton for PSScriptAnalyzer + gitleaks (PoC):
```yaml
name: Lint & Security
on: [pull_request]
jobs:
  lint:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run gitleaks
        uses: zricethezav/gitleaks-action@v2
      - name: Run PSScriptAnalyzer
        uses: PowerShell/PSScriptAnalyzer@v1
        with:
          script: '**/*.ps1'
```

Success metrics: 0 gitleaks secrets in master, 100% critical PSScriptAnalyzer rules passing on PRs, Pester coverage targets (e.g., 70%+ for helpers), and no failing integration jobs on protected branches.

---

## 8) Migration Roadmap & Prioritized Action Plan (Sprint-style) 🗂️

Sprint 0 (Immediate / 0–1 day) — Emergency
- Rotate and revoke exposed secrets; remove secrets from files and history; add `REVERTED_SECRET_ROTATION.md` to track actions.
- Add gitleaks to pre-commit and GH Actions.

Sprint 1 (1–3 days) — Stabilize
- Add `Set-StrictMode` and `$ErrorActionPreference='Stop'` to all scripts that change state (if missing).
- Add param validation ([ValidateNotNullOrEmpty()]) across entry scripts.
- Update README & `Needs_Review.md` with emergency remediation steps taken.

Sprint 2 (1–2 weeks) — Centralize config & validation
- Implement `Scripts/Load-Config.ps1` + `config/schema/smtp-config.schema.json` and integrate into `New-ExoOauthSmtpAppIdentity_v2.ps1` and v3.
- Add JSON Schema validation and explicit errors for missing keys.
- Add `Get-ProtectedSecretFromFile.ps1` helper for DPAPI retrieval (safe dev UX).

Sprint 3 (2–4 weeks) — Vault-first & CI
- Integrate `SecretManagement` calls to read from Azure Key Vault in automation flows and configure GH Actions to pull secrets from Key Vault for deployment jobs.
- Add PSScriptAnalyzer + Pester jobs to CI and require passing status on PRs.

Sprint 4 (4–8 weeks) — IaC & hardened automation
- Create Terraform modules for creating App Registration + SP + app password and optionally Exchange Service Principal registration steps (where Terraform supports it) or scripted approvers.
- Add gated integration tests that run `Test-ExoOauthSmtpAppIdentity.ps1` against a test tenant using GH Secrets and Managed Identity flows.

Long term (Quarterly)
- Evaluate dynamic secret rotation (Vault dynamic secrets), certificate-based auth (client assertion) instead of client secrets, and replace long-lived secrets with short-lived credentials.

---

## 9) Proof-of-Concept Snippets ✍️

PowerShell: central config loader (POC)
```powershell
function Load-Config {
  param([string]$Path)
  $raw = Get-Content -Path $Path -Raw
  if ($Path -like '*.yml' -or $Path -like '*.yaml') { Import-Module powershell-yaml; $cfg = ConvertFrom-Yaml $raw }
  else { $cfg = $raw | ConvertFrom-Json }
  # basic schema check
  if (-not $cfg.DisplayName) { throw 'DisplayName missing from config' }
  return $cfg
}
```

JSON Schema snippet (POC for `config/smtp-app.schema.json`)
```json
{
  "$schema":"http://json-schema.org/draft-07/schema#",
  "type":"object",
  "required":["DisplayName","TenantId"],
  "properties":{
    "DisplayName":{"type":"string"},
    "TenantId":{"type":"string"},
    "Mailboxes":{"type":"array","items":{"type":"string"}}
  }
}
```

Pydantic / Python PoC (if repo grows Python components)
```python
from pydantic import BaseSettings

class Settings(BaseSettings):
    display_name: str
    tenant_id: str
    mailboxes: list[str] = []

    class Config:
        env_prefix = 'SMTP_'

settings = Settings()
```

---

## 10) Success Metrics & Acceptance Criteria 📊

- Security: 0 secrets detected by `gitleaks` on main+PRs; all previously leaked secrets rotated and removed from history.
- Configuration & Validation: JSON Schema validation in place for config files; all scripts return well-formed errors on bad config.
- CI: PSScriptAnalyzer configured; PRs blocked if critical rules fail. Pester unit tests run on PRs with >= 70% coverage target for helper code.
- Automation: v2/v3 scripts can be invoked non-interactively with secrets read from Key Vault or SecretManagement.
- Developer UX: local dev secrets flow via `SecretManagement` with documented setup; DPAPI retrieval helper is available.

---

## 11) Recommended First Implementation Tasks (concrete PRs) 🛠️

1. Emergency secret rotation & history purge PR (include rotation logs). (Immediate)
2. Add `gitleaks` Action + pre-commit hook. (Immediate)
3. Add `PSScriptAnalyzer` Action and a `pester` GitHub Action job (basic tests). (Sprint 1)
4. Implement `Scripts/Load-Config.ps1` and `config/smtp-app.schema.json`. (Sprint 2)
5. Add `Get-ProtectedSecretFromFile.ps1` helper and docs. (Sprint 2)
6. Implement Terraform IaC module for app/SP creation and add a migration guide. (Sprint 3)

---

## 12) Closing Notes & Offer to Implement ✅

I can begin immediately with the emergency tasks: (A) rotate and purge committed secrets (I will prepare the PR and remediation steps text for maintainers to execute and coordinate rotation), and (B) add `gitleaks` and `PSScriptAnalyzer` Actions with a `pre-commit` configuration. Please confirm I should start with the emergency remediation (rotate/purge + secret scanning) or prefer I scaffold `Load-Config.ps1` first.

---

Appendix: references to key files and sample commands were used to assemble this report. If you'd like, I can also create the PoC files (schema, config loader, GH Action workflows, Pester tests) as follow-up PRs and implement the first sprint items.
