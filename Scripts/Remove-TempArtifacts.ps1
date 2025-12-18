# Cleanup script to remove temp/credential files and legacy provisioning scripts
# Run this locally from the repo root (PowerShell 7+ recommended)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$filesToRemove = @(
    'temp\oAuth_config.json',
    'temp\oAuth_config_v2.json',
    'gitleaks-local-report.json',
    'Scripts\config\oAuth_config.json',
    'Scripts\config\oAuth_config_v2.json',
    'Scripts\config\setup-auth-example.json',
    'Scripts\New-ExoOauthSmtpAppIdentity.ps1',
    'Scripts\New-ExoOauthSmtpAppIdentity_v2.ps1'
)

Write-Host "This script will attempt to delete the following files from the repository and run 'git rm' if a git repo is present:`n"
$filesToRemove | ForEach-Object { Write-Host " - $_" }

if (-not (Read-Host 'Type YES to proceed') -eq 'YES') { Write-Host 'Aborted by user.'; exit 1 }

$repoRoot = (Get-Location).Path
$gitPresent = Test-Path (Join-Path $repoRoot '.git')

foreach ($f in $filesToRemove) {
    $full = Join-Path $repoRoot $f
    if (Test-Path $full) {
        try {
            Remove-Item -Path $full -Force -ErrorAction Stop
            Write-Host "Deleted: $f"
            if ($gitPresent) {
                git rm --quiet -- "$f" 2>$null
                Write-Host "Git rm: $f"
            }
        } catch {
            Write-Warning "Failed to remove $($f): $($_.Exception.Message)"
        }
    } else {
        Write-Host "Not found: $f"
    }
}

if ($gitPresent) { Write-Host "All deletions staged. Commit them with: git commit -m 'chore: remove temp/secret and legacy scripts'" } else { Write-Host "No .git folder found. Files removed (if present) but not staged in git." }

Write-Host "IMPORTANT: If any of the deleted files contained real secrets, rotate those secrets immediately in Azure/clients."
