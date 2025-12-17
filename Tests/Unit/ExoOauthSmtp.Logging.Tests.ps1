Describe 'Write-Log file logging and redaction' {
    It 'writes non-secret message to file' {
        $tmp = Join-Path -Path $env:TEMP -ChildPath ("exo-log-{0}.log" -f ([guid]::NewGuid().ToString()))
        if (Test-Path $tmp) { Remove-Item $tmp -Force }
        $runScript = (Resolve-Path (Join-Path $PSScriptRoot '..\..\Scripts\Run-Interactive-Setup.ps1')).Path
        # Dot-source script; our change prevents auto-run when dot-sourced
        . $runScript
        $Global:LogPath = $tmp

        Write-Log "Hello world test" 'INFO'

        Test-Path $tmp | Should -BeTrue
        (Get-Content $tmp -Raw) | Should -Match 'Hello world test'
        Remove-Item $tmp -Force
    }

    It 'does not write client secret to file (redacted)' {
        $tmp = Join-Path -Path $env:TEMP -ChildPath ("exo-log-{0}.log" -f ([guid]::NewGuid().ToString()))
        if (Test-Path $tmp) { Remove-Item $tmp -Force }
        $runScript = (Resolve-Path (Join-Path $PSScriptRoot '..\..\Scripts\Run-Interactive-Setup.ps1')).Path
        . $runScript
        $Global:LogPath = $tmp

        Write-Log "ONE-TIME CLIENT SECRET (copy now): abc123" 'WARN'

        (Get-Content $tmp -Raw) | Should -Not -Match 'abc123'
        (Get-Content $tmp -Raw) | Should -Match 'REDACTED'
        Remove-Item $tmp -Force
    }
}
