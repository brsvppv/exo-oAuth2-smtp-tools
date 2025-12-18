# Publish Readiness Checklist

Before publishing this repository publicly, complete the following checklist to reduce security risk and ensure a smooth experience for users:

## Security & Secrets
- [ ] Rotate and revoke any secrets that have been committed historically (see `config/oAuth_config_v2.json` and `temp/` files). Use `git filter-repo` or BFG to remove secrets from history if required.
- [ ] Run `gitleaks` locally and via CI; resolve any findings and enforce via Action.
- [ ] Ensure `.gitignore` excludes local config and secret files (we added `/Scripts/config/*.json`, `/config/*.json`, `*.prot`, `.env`, etc.).

## Code Quality & CI
- [ ] Ensure `PSScriptAnalyzer` runs on PRs and fixes all critical findings.
- [ ] Ensure `Pester` tests run and pass in CI; add more tests to cover critical flows.
- [ ] Add branch protection rules requiring PRs, passing CI, and at least one reviewer.

## Documentation
- [ ] Add `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` (optional but recommended).
- [ ] Confirm `README.MD` Quick Start is accurate and warns about running remote scripts (download-then-inspect pattern).
- [ ] Add LICENSE (e.g., MIT) or other applicable license file.

## Artifacts & Packaging
- [ ] Ensure module manifest (`src/ExoOauthSmtp/ExoOauthSmtp.psd1`) is complete and versioned.
- [ ] Consider publishing a release with compiled module or release notes.

## Final checks
- [ ] Run a final `gitleaks detect --source .` and confirm zero results.
- [ ] Run `pwsh -c 'Invoke-Pester -Output Detailed'` and confirm all tests pass.
- [ ] Verify no secrets in `git log --all --grep='1Ag8Q'` or other known tokens.

If you'd like, I can prepare a PR that includes the `.gitignore` update (done), `PUBLISH_CHECKLIST.md` (this file), and optionally create a `LICENSE` and `CONTRIBUTING.md` for you to review before publishing. Which additional items would you like me to add now? 
