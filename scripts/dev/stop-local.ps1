$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$runtimeDir = Join-Path $RepoRoot ".runtime"

foreach ($name in @("backend-dev.pid", "frontend-dev.pid")) {
    $pidPath = Join-Path $runtimeDir $name
    if (-not (Test-Path $pidPath)) {
        continue
    }
    $pidValue = (Get-Content $pidPath -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    if ($pidValue) {
        try {
            Stop-Process -Id ([int]$pidValue) -Force -ErrorAction Stop
            Write-Host "Stopped PID $pidValue"
        } catch {
            Write-Host "PID $pidValue was not running"
        }
    }
    Remove-Item $pidPath -Force -ErrorAction SilentlyContinue
}
