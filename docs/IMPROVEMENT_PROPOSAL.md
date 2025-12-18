# Configuration & Architecture Improvement Proposal

Date: 2025-12-16

This document audits the project's current configuration management posture and recommends concrete, prioritized improvements focused on security, validation, scalability, and maintainability. It is non-destructive — no code changes are proposed here, only procedures, patterns and libraries to adopt.

**Files referenced:** [config/smtp-app.example.json](config/smtp-app.example.json), [README.MD](readme.md), [Scripts/New-ExoOauthSmtpAppIdentity_v2.ps1](Scripts/New-ExoOauthSmtpAppIdentity_v2.ps1), [Scripts/Test-ExoOauthSmtpAppIdentity.ps1](Scripts/Test-ExoOauthSmtpAppIdentity.ps1), [Needs_Review.md](Needs_Review.md)

## 1. Executive Summary

The repository contains useful PowerShell tooling for provisioning and validating Exchange Online SMTP OAuth2 client-credentials flows. Configuration today is ad-hoc: JSON example files, per-script parameters, and a small set of documented options (DPAPI protected export, SecretManagement optional use). Strengths: scripts are parameterized, README documents protected export, and a v2 provisioning script exists with safer patterns.

Primary gaps and risks:
- Secrets have appeared in examples and comments (see `Needs_Review.md`) — risk of accidental commits.
- No single, validated configuration model: scripts accept parameters directly and consume loose JSON examples without a shared schema or strong validation.
- Inconsistent parameter naming across scripts, inconsistent input validation, and limited automated CI checks for PowerShell linting and behavioral tests.
- Secret-handling is partly ad hoc (DPAPI is useful locally but is user/machine bound; SecretManagement is optional and not enforced).

Conclusion: overall workable for manual/operational usage, but not yet ready for scaled automation (CI/CD, multi-machine runs) without centralizing config handling, stricter validation, and enforced secrets strategy.

## 2. Findings & Recommendations Matrix

| Category | Current Approach | Proposed Improvement | Impact | Priority |
|---|---|---|---:|---|
| Security (committed secrets) | Example secrets and commented sample secrets were found in scripts and examples (noted in `Needs_Review.md`). | Remove any secret-like text from repo. Enforce pre-commit scanning (secret detection) with a GitHub Action (e.g., `truffleHog`, `gitleaks`). | Prevents credential leak, immediate risk reduction. | High |
| Secret Storage | Optional DPAPI protected export and optional SecretManagement usage; no canonical cloud-backed secret store integration. | Standardize on a vault-first model: prefer cloud key-vault (Azure Key Vault) or HashiCorp Vault for CI/automation; keep DPAPI as local, one-off fallback. Integrate `SecretManagement` plugin to write/read secrets to vaults in automation. | Reduces risk of secrets leaking; supports cross-machine automation. | High |
| Input Validation | Scripts rely on parameter checks sprinkled manually (some ValidateNotNull not present), inconsistent parameter names. | Centralize validation: add `Param()` validation attributes for each script and enforce `Set-StrictMode -Version Latest` and `ErrorActionPreference = 'Stop'`. Add a lightweight config schema (JSON Schema) for `config/*.json`. | Prevents runtime failures, improves DX and reliable automation. | High |
| Configuration Loading | Loose JSON sample + many per-script parameters; no shared loader or typed settings object. | Introduce a central config loader pattern. For PowerShell: load JSON then validate against JSON Schema and expose typed PSCustomObject. For multi-language components (if any), centralize with environment variable overrides following 12-Factor. | Single source of truth reduces drift and makes automation predictable. | High |
| Documentation Drift | README mentions some outdated filenames and the repo contains multiple similarly-named scripts. | Update README to reflect canonical filenames and add a short `CONTRIBUTING.md` describing safe operational patterns (download-then-inspect), secrets handling, and recommended invocation. | Reduces operational mistakes and accidental remote execution. | Medium |
| Observability & Secrets in Logs | Scripts may print sensitive data when operators pass `-ShowSecret`. | Make `-ShowSecret` explicit and ephemeral; redact secrets in all logs by default. Provide a secure retrieval helper script `Get-ProtectedSecretFromFile.ps1` for DPAPI exports. | Reduces accidental leakage in logs and CI output. | High |
| Idempotence & Partial Failures | Some scripts create resources without guarded idempotence or partial-state handling. | Adopt idempotent operations (check-create pattern), implement `-RotateSecret` flag to avoid creating duplicate secrets, and use `SupportsShouldProcess`/`-WhatIf` for destructive actions. | Safer automation; easier to retry failed runs. | High |
| CI / Linting / Tests | No CI configured for PowerShell linting and Pester tests. | Add GitHub Actions: PSScriptAnalyzer on PRs, Pester unit tests for helper code, and an optional gated integration job (protected branches) for `Test-ExoOauthSmtpAppIdentity.ps1` using a test tenant and secrets stored in GH Secrets. | Improves code quality and prevents regressions. | Medium |
| Cross-platform / Portability | DPAPI-based protected export is Windows CurrentUser only (documented), but scripts may be run in other contexts. | Document limitations; provide Vault-based alternative. For cross-platform protect, use `SecretManagement` with cross-platform stores or cloud KVs. | Enables automation across runners (Linux, macOS, Windows). | Medium |

## 3. Modernization Suggestions (libraries, patterns, and concrete steps)

- Follow 12-Factor App principles for configuration: store config in the environment (env vars) for automation, keep defaults only for local development.

- For PowerShell projects (this repo is primarily PowerShell):
  - Central config loader pattern:
    - Add a `Scripts/Load-Config.ps1` helper that: reads `config/*.json`, validates with a JSON Schema, and produces a typed PSCustomObject. Use `ConvertFrom-Json` then validate keys with `Test-Json` or a small validation function.
  - Input validation and safety:
    - Use `Param(... [ValidateNotNullOrEmpty()] ...)` consistently.
    - Add `Set-StrictMode -Version Latest` and `$ErrorActionPreference='Stop'` at script start.
    - Add `[CmdletBinding(SupportsShouldProcess=$true)]` to scripts that change remote state and implement `-WhatIf` / `-Confirm` flows.
  - Secrets:
    - Standardize on PowerShell `SecretManagement` (Microsoft.PowerShell.SecretManagement + SecretStore) for local dev plus Azure Key Vault connector for automation. Provide documented fallback to ProtectedData DPAPI export for single-machine operators but mark it as local-only and ephemeral.

- For any Python or multi-language utilities (if added):
  - Use `pydantic.BaseSettings` for typed settings with environment variable overrides. `dynaconf` is an alternative for multi-source layered config (files, env, vault) but `pydantic` is simpler and widely supported.

- Vault / Cloud Secret Recommendations:
  - For automated runs in Azure: use Managed Identities + Azure Key Vault; store client secret only in Key Vault and grant minimal access to the automation run-identity.
  - For GitHub Actions: store sensitive values in GitHub Secrets and avoid printing them; use Actions with `secrets` masked.

- Testing & CI:
  - Add GitHub Actions: PSScriptAnalyzer (on PR), Pester tests (unit), and a gated integration job for `Test-ExoOauthSmtpAppIdentity.ps1` that runs only on protected branches using secrets.
  - Add a pre-commit hook (or GH Action) to run `gitleaks` or `gitleaks-action` on PRs to prevent committing secrets.

## 4. Concrete, Minimal Action Plan (recommended first sprint)

1. Immediate (Days 0–2):
   - Remove any sample secrets from the repo and rotate if any were exposed.
   - Add `Set-StrictMode -Version Latest` and `$ErrorActionPreference='Stop'` to top of scripts.
   - Add Param validation (`[ValidateNotNullOrEmpty()]`) to key scripts.
   - Add `Needs_Review.md` items as checklist tasks (already present) and track completion.

2. Short term (Week 1–2):
   - Implement central `Load-Config.ps1` and a small JSON Schema for `config/smtp-app.example.json` and run validation at start of v2 script.
   - Add GitHub Action with PSScriptAnalyzer; fail PRs on high-severity rules.
   - Add `gitleaks` or `trufflehog` Action to scan for secrets on PRs.

3. Medium term (Weeks 2–5):
   - Add Pester unit tests for helper logic (XOAUTH2 builder, DPAPI protect/unprotect roundtrip) and a gated integration job for `Test-ExoOauthSmtpAppIdentity.ps1` (protected branch, test tenant secrets stored in GH Secrets).
   - Standardize secret handling: wire scripts to use `SecretManagement` + `AzureKeyVault` or `SecretStore` in dev; document DPAPI fallback clearly.

4. Long term (Quarter plan):
   - Consider migrating to a library-based config approach for any multi-language components (e.g., `pydantic` for Python microservices reading the same config inputs). Consider adopting a single control plane for secrets (Vault or Azure Key Vault) and enabling Managed Identity flows (certificate or MSI) instead of long-lived client secrets where possible.

## 5. Justification (standards & best practices)

- Prevent committing secrets: industry standard (e.g., OWASP, SANS) — immediate mitigation reduces blast radius.
- 12-Factor App (config via env): improves portability and CI/CD compatibility.
- Principle of Least Privilege: use dedicated app roles and Key Vault access policies rather than broadly-scoped secrets in code.
- Typed settings / validation: prevents runtime failures and reduces incident recovery time (fail-fast on invalid config).
- PSScriptAnalyzer & Pester: common best practice for PowerShell repositories to maintain code quality and safety in automation contexts.

---

If you want, I can implement the first sprint items: remove sample secrets, add strict mode and error preference, add param validation, and scaffold a GitHub Action for PSScriptAnalyzer. Which items should I start with? If you prefer, I can instead add the small `Load-Config.ps1` and JSON Schema next.
