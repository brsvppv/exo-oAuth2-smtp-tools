<#
.SYNOPSIS
  Helper to run local pre-run checks: PSScriptAnalyzer, gitleaks, and unit tests.

.DESCRIPTION
  Use this script before running remote `iex (irm ...)` invocations to ensure the repo
  passes configured checks locally. Intended for developer safety and CI parity.

USAGE
  pwsh -File .\Scripts\Check-PreRun.ps1
  pwsh -File .\Scripts\Check-PreRun.ps1 -SkipGitleaks -SkipAnalyzer
#>
[CmdletBinding()]
Param(
    [switch]$SkipGitleaks,
    [switch]$SkipAnalyzer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log([string]$Message, [ValidateSet('INFO','WARN','ERROR')] [string]$Level = 'INFO') {
    switch ($Level) {
        'INFO'  { Write-Information -MessageData $Message -InformationAction Continue }
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message }
    }
} 

# 1) Run PSScriptAnalyzer (if not skipped)
$analyzerRules = @('PSAvoidUsingWriteHost','PSUseApprovedVerbs','PSAvoidUsingConvertToSecureStringWithPlainText','PSAvoidUsingPlainTextForSecrets')
if (-not $SkipAnalyzer) {
    Write-Log 'Installing or ensuring PSScriptAnalyzer module is available...' 'INFO'
    try { Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser -ErrorAction SilentlyContinue } catch { }
    Write-Log 'Running Invoke-ScriptAnalyzer (this may take a few seconds)...' 'INFO'
    $findings = Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning,Error
    $bad = $findings | Where-Object { $_.RuleName -in $analyzerRules }
    if ($bad -and $bad.Count -gt 0) {
        Write-Log "PSScriptAnalyzer found disallowed rules:" 'ERROR'
        $bad | Select-Object FileName, Line, RuleName, Severity, Message | Format-Table -AutoSize
        exit 1
    } else { Write-Log 'No disallowed PSScriptAnalyzer rules found.' 'INFO' }
}

# 2) Run gitleaks (if not skipped)
if (-not $SkipGitleaks) {
    Write-Log 'Running gitleaks (repo history) — ensure gitleaks is installed and on PATH...' 'INFO'
    $report = 'gitleaks-prerun-report.json'
    try {
        & gitleaks detect --redact --report-format json --report-path $report --log-opts "--all"
        if (Test-Path $report) {
            $content = Get-Content -Path $report -Raw
            if ($content.Trim()) {
                $json = $content | ConvertFrom-Json
                if ($json -and $json.Count -gt 0) {
                    Write-Log "gitleaks found $($json.Count) findings. See $report" 'ERROR'
                    exit 2
                }
            }
        }
        Write-Log 'gitleaks found no issues.' 'INFO'
    } catch {
        Write-Log "gitleaks execution failed: $($_.Exception.Message)" 'WARN'
        Write-Log 'If gitleaks is not available, install it or pass -SkipGitleaks to skip this check.' 'WARN'
    }
}

# 3) Run unit tests
Write-Log 'Running unit tests (Pester)...' 'INFO'
try {
    $res = Invoke-Pester -Script .\Tests\Unit -PassThru -Verbose
    if ($res.FailedCount -gt 0) {
        Write-Log 'Unit tests failed. Fix tests before proceeding.' 'ERROR'
        exit 3
    }
    Write-Log 'Unit tests passed.' 'INFO'
} catch {
    Write-Log "Running tests failed: $($_.Exception.Message)" 'ERROR'
    exit 3
}

Write-Log 'Pre-run checks passed. You may proceed with a DryRun invocation or production run.' 'INFO'
exit 0
