# Contributing Guide

Thanks for contributing! This short guide explains the CI gates and how to run checks locally before opening a PR.

## CI Gates
- **Secret scanning (gitleaks)** runs on Pull Requests and weekly via scheduled job. If gitleaks finds secrets, the job fails and a JSON report artifact (`gitleaks-report.json`) is attached for review.
- **PSScriptAnalyzer** runs in CI. The workflow fails the PR if certain disallowed rules are found (e.g., `PSAvoidUsingWriteHost`, `PSUseApprovedVerbs`).

## Run checks locally
### PSScriptAnalyzer
1. Install the module (PowerShell 7+):
```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
```
2. Run the analyzer over the repo:
```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning,Error
```
3. To check the rules enforced in CI specifically:
```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning,Error | Where-Object { $_.RuleName -in @('PSAvoidUsingWriteHost','PSUseApprovedVerbs') }
```

> CI uploads the full PSScriptAnalyzer JSON report as an artifact (`psscriptanalyzer-report`) on PRs so you can download and inspect findings from the Actions UI.

### gitleaks (secret scan)
Install gitleaks (see https://github.com/zricethezav/gitleaks) and run with the same options as CI:
```powershell
gitleaks detect --redact --report-format json --report-path gitleaks-report.json
```
If the report contains results, remove secrets and rotate them if necessary before opening a PR.

> The PR pre-check job (`precheck`) will run `gitleaks` and upload `gitleaks-prerun-report` as an artifact when it runs on PRs.
## Logging & Diagnostics (note for contributors)
- `Invoke-InteractiveSetup.ps1` supports optional `-LogPath` and `-TraceCommands`. Console output is always shown.
- Secrets are redacted and never written to log files by default.

If you'd like to add more checks to CI or stricter rules, open an issue or submit a PR describing the rationale and proposed rules.
