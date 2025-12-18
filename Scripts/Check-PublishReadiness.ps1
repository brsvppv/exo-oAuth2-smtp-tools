<#
.SYNOPSIS
  Simple readiness checks for publishing the repository.

.DESCRIPTION
  Runs quick validations: looks for obvious secret patterns in tracked files, checks that CI workflows are present, and ensures critical docs exist.
  This is not a substitute for a full secret scan (gitleaks) or human review but provides a fast local pre-flight.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log([string]$Message, [ValidateSet('INFO','WARN','ERROR','VERBOSE')][string]$Level = 'INFO') {
    switch ($Level) {
        'INFO'  { Write-Information -MessageData $Message -InformationAction Continue }
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message }
        'VERBOSE' { Write-Verbose $Message }
    }
}

Write-Log "Running publish readiness checks..." 'INFO'

$root = Split-Path -Parent $PSCommandPath

function Find-SecretPatterns {
    param([string]$Path)
    $patterns = @(
        '"SecretValue"\s*:\s*".+"',
        '(?i)client_secret\s*=\s*".+"',
        '(?i)clientsecret\s*[:=]\s*".+"',
        '[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' # jwt-ish
    )
    $results = @()
    foreach ($p in $patterns) {
        $matches = Select-String -Path $Path -Pattern $p -NotMatch 'temp\' -SimpleMatch -ErrorAction SilentlyContinue
        foreach ($m in $matches) { $results += $m }
    }
    return $results
}

# 1) Look for obvious secrets
$secretMatches = Find-SecretPatterns -Path "**/*"
if ($secretMatches.Count -gt 0) {
    Write-Log "Potential secret patterns found in the repository (not exhaustive):" 'WARN'
    $secretMatches | ForEach-Object { Write-Log " $($_.Path):$($_.LineNumber) -> $($_.Line.Trim())" 'WARN' }
} else { Write-Log "No obvious secret patterns found in tracked files (quick check)." 'INFO' }

# 2) Check for CI workflows
if (Test-Path ".github/workflows/lint-and-test.yml" -and Test-Path ".github/workflows/secret-scan.yml") {
    Write-Log "CI workflows detected." 'INFO'
} else { Write-Log "CI workflows missing or incomplete (check .github/workflows)." 'WARN' }

# 3) Check for README and LICENSE
if (Test-Path "README.MD") { Write-Log "README present." 'INFO' } else { Write-Log "README.MD not found." 'WARN' }
if (Test-Path "LICENSE" -or Test-Path "LICENSE.md") { Write-Log "LICENSE present." 'INFO' } else { Write-Log "No LICENSE found. Consider adding one (e.g., MIT)." 'WARN' }

Write-Log "Quick checks complete. For publication: rotate and purge any historical secrets, run gitleaks, ensure CI passes, and add LICENSE/CONTRIBUTING if desired." 'INFO'
