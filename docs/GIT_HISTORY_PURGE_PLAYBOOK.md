# Git History Purge Playbook

Purpose: provide a safe, documented process to remove sensitive data from repository history if gitleaks or other scanners detect secrets in commits, along with a secret-rotation checklist and verification steps.

---

## 1) Preliminary steps (do not rewrite history yet)
- **Stop merging PRs** into the branch being rewritten (usually `main`) while the purge is planned and executed.
- **Notify stakeholders**: notify security, team leads, and any owners of the repositories that may be impacted.
- **Do not rotate secrets yet** — wait until the purge is ready so rotation can be coordinated and validated (see checklist below).
- **Create a backup**: clone the repo and create a compressed backup of the bare repo:
  ```powershell
  git clone --mirror https://github.com/ORG/REPO.git repo-mirror.git
  cd repo-mirror.git
  tar -czf ../repo-mirror-backup.tgz .
  ```

## 2) Detection & confirmation
- Run gitleaks locally (same options as CI):
  ```powershell
  gitleaks detect --redact --report-format json --report-path gitleaks-report.json
  cat gitleaks-report.json | jq
  ```
- If gitleaks finds hits, **inspect the report** and collect the following details: file path(s), commit SHAs, rule IDs, and example matches.

## 3) Decide purge scope & approach
- If leaks only exist in a small set of recent commits, consider `git rebase -i` on a branch and modify commits locally (simpler, less invasive).
- For leaks across many commits or across many branches, use `git filter-repo` (recommended) or the BFG Repo-Cleaner.
- Prefer `git filter-repo` when available (faster, safer, and actively maintained). BFG is an alternative with a simpler interface.

### Example: git-filter-repo (recommended)
- Install: https://github.com/newren/git-filter-repo
- Example to remove a specific file from history:
  ```bash
  git clone --mirror https://github.com/ORG/REPO.git
  cd REPO.git
  git filter-repo --invert-paths --paths path/to/secret-file.txt
  # or to remove a string pattern (use carefully):
  git filter-repo --replace-text replacements.txt
  ```
- `replacements.txt` format example to remove exact matches (secure these files):
  ````text
  # any line starting with 'literal:' is a literal string to replace
  literal:super-secret-abc123==
  ```

### Example: BFG Repo-Cleaner (alternative)
- Install: https://rtyley.github.io/bfg-repo-cleaner/
- Replace a password in history:
  ```bash
  git clone --mirror https://github.com/ORG/REPO.git
  java -jar bfg.jar --replace-text passwords.txt REPO.git
  cd REPO.git
  git reflog expire --expire=now --all && git gc --prune=now --aggressive
  git push --force
  ```

## 4) Secret rotation checklist (coordinate with owners)
1. Identify the impacted secrets (client IDs, client secrets, tokens, certificates, keys). Use the gitleaks report and repo inspection to build the list.
2. **Do not** rotate secrets until you have a plan (change schedule, who will update apps/configs).
3. Generate new secrets in the authoritative systems (Azure AD for client secrets, vaults for passwords, etc.).
4. Update CI/CD and deployed systems to use the new secrets before deleting the old ones when possible.
5. After systems are updated, rotate the secrets (revoke old secrets), and confirm systems operate normally.
6. Record rotated secrets in a secure vault (Azure Key Vault, HashiCorp Vault, or SecretManagement) and audit access.

## 5) Push & recovery plan
- After history is rewritten (filter-repo or BFG), push using `--force` to the remote. Coordinate the push and block merges until downstream consumers are updated.
- Any forks or clones will have the old history; ask contributors to re-clone or use the documented cleanup steps to rebase onto the rewritten main.

## 6) Post-purge verification
- Re-run gitleaks on the rewritten repo to ensure no findings remain.
- Confirm CI secret-scan job completes successfully and no `gitleaks-report.json` contains findings.
- Verify that all systems and CI pipelines are updated to use rotated secrets.

## 7) Communicate and document
- Create a short release note or security advisory to notify stakeholders about the purge and secret rotation.
- Document any follow-ups (e.g., rotate secondary credentials, review access logs).

---

## Appendix: Quick commands summary
```bash
# Backup mirror
git clone --mirror https://github.com/ORG/REPO.git
# Run gitleaks across all history
gitleaks detect --redact --report-format json --report-path gitleaks-report.json --log-opts "--all"
# Use git-filter-repo to remove sensitive path
git filter-repo --invert-paths --paths "path/to/secret"
# Use BFG to replace/clean secrets (alternative)
java -jar bfg.jar --replace-text passwords.txt REPO.git
# Cleanup and push
git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push --force
```

If you want, I can add a helper script (PowerShell) that runs gitleaks and summarizes the findings and optionally creates a draft issue with the findings to help coordinate remediation.