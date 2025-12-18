# Secret Remediation & Git History Cleanup Guide

This guide provides step-by-step instructions to rotate exposed secrets, remove them from repository history, and prevent future accidental commits.

1) Rotate secrets immediately
   - For any exposed secret (identified via `gitleaks` or manual inspection), rotate the secret in the service (Azure portal, Application -> Certificates & secrets -> New client secret).
   - Update any running services to use the new secret before removing the old one from the repository to prevent outages.

2) Remove secrets from files (commit)
   - Replace any cleartext secret values in the repo files with empty values or placeholders (e.g., `"SecretValue": ""`).
   - Commit the change on a feature branch and open a PR describing the rotation and replacement.

3) Purge secret from git history (if necessary)
   - Use `git filter-repo` (recommended) or BFG to remove secrets from history:
     - Example `git filter-repo` usage:
       ```bash
       git clone --mirror https://github.com/yourorg/yourrepo.git
       cd yourrepo.git
       git filter-repo --replace-text ../replacements.txt
       git push --force --mirror
       ```
     - `replacements.txt` format may contain lines like:
       `PASSWORD==>REDACTED`

4) Add repository-level protections
   - Add `gitleaks` Action and make it required for merging.
   - Add branch protection rules to enforce PR reviews and passing CI checks.

5) Local developer guidance
   - Document how to use `gitleaks` locally for scanning:
     ```bash
     # Install gitleaks
     brew install gitleaks    # macOS
     choco install gitleaks   # Windows (if available) or use binary
     gitleaks detect --source .
     ```

6) Post-remediation checklist
   - Confirm no remaining secret findings with `gitleaks` on the default branch.
   - Confirm automated scans show zero findings on schedule.
   - Update README and developer docs to point to secret management best practices.

If you'd like, I can prepare the PR that replaces the secrets with placeholders and assemble the `replacements.txt` to feed into `git filter-repo` for you to run (requires repository admin rights and coordination). 
