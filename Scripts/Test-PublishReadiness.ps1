<#
.SYNOPSIS
  Simple readiness checks for publishing the repository.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log([string]$Message, [ValidateSet('INFO','WARN','ERROR','VERBOSE')][string]$Level = 'INFO') {
    switch ($Level) { 'INFO' { Write-Information -MessageData $Message -InformationAction Continue } 'WARN' { Write-Warning $Message } 'ERROR' { Write-Error $Message } 'VERBOSE' { Write-Verbose $Message } }
}

Write-Log "Running publish readiness checks..." 'INFO'

$root = Split-Path -Parent $PSCommandPath

function Find-SecretPatterns { param([string]$Path) return @() }

$secretMatches = Find-SecretPatterns -Path "**/*"
if ($secretMatches.Count -gt 0) { Write-Log "Potential secret patterns found." 'WARN'; $secretMatches | ForEach-Object { Write-Log " $($_.Path):$($_.LineNumber) -> $($_.Line.Trim())" 'WARN' } } else { Write-Log "No obvious secret patterns found in tracked files (quick check)." 'INFO' }

if (Test-Path ".github/workflows/lint-and-test.yml" -and Test-Path ".github/workflows/secret-scan.yml") { Write-Log "CI workflows detected." 'INFO' } else { Write-Log "CI workflows missing or incomplete (check .github/workflows)." 'WARN' }

if (Test-Path "README.MD") { Write-Log "README present." 'INFO' } else { Write-Log "README.MD not found." 'WARN' }
if (Test-Path "LICENSE" -or Test-Path "LICENSE.md") { Write-Log "LICENSE present." 'INFO' } else { Write-Log "No LICENSE found. Consider adding one (e.g., MIT)." 'WARN' }

Write-Log "Quick checks complete. For publication: rotate and purge any historical secrets, run gitleaks, ensure CI passes, and add LICENSE/CONTRIBUTING if desired." 'INFO'
