# ExoOauthSmtp PowerShell Module - Design Document

## Goals
- Provide a single reusable PowerShell module for provisioning and managing Exchange Online SMTP OAuth2 app identities.
- Separation of public vs private functions for testability and maintainability.
- Centralized config loader that supports JSON/YAML and environment overrides.
- Pluggable secret backends: SecretManagement adapters, Azure Key Vault, local DPAPI fallback.
- CI pipelines (lint + tests + secret scanning) and optional gated integration tests.

## Structure
- src/ExoOauthSmtp/ExoOauthSmtp.psd1 - module manifest
- src/ExoOauthSmtp/ExoOauthSmtp.psm1 - module implementation and public functions
- Scripts/ - contains v2/v3 scripts (kept for operational compatibility; module dot-sources v3)
- config/schema/smtp-config.schema.json - JSON schema for config validation
- Tests/Unit - Pester unit tests
- .github/workflows - CI (lint/test/secret-scan)

## Public API
- New-ExoOauthSmtpAppIdentity - main entrypoint for provisioning; supports non-interactive mode and secret export options
- Load-ExoConfig - load and validate config files (YAML/JSON)
- Get-ProtectedSecretFromFile - DPAPI unprotect helper for local dev

## Security & Secret Flow
- Primary: Vault-first (Azure Key Vault, HashiCorp Vault)
- Secondary: `SecretManagement` + `SecretStore` adapter for local dev
- Tertiary: DPAPI protected files for single-machine operator recoverability

## Testing & CI
- PSScriptAnalyzer in PRs
- gitleaks scheduled scans and PR scans
- Pester tests run on PRs

## Migration Notes
- Provide backward compatibility script wrappers to call new module functions.
- Gradually refactor v3 internals into discrete, testable private functions.
