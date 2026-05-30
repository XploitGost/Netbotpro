$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$runtimeDir = Join-Path $RepoRoot ".runtime"

function Stop-DevPid {
    param([int]$PidValue)
    try {
        Stop-Process -Id $PidValue -Force -ErrorAction Stop
        Write-Host "Stopped PID $PidValue"
    } catch {
        Write-Host "PID $PidValue was not running"
    }
}

foreach ($name in @("backend-dev.pid", "frontend-dev.pid")) {
    $pidPath = Join-Path $runtimeDir $name
    if (-not (Test-Path $pidPath)) {
        continue
    }
    $pidValue = (Get-Content $pidPath -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    if ($pidValue) {
        Stop-DevPid -PidValue ([int]$pidValue)
    }
    Remove-Item $pidPath -Force -ErrorAction SilentlyContinue
}

foreach ($port in @(8765, 5173)) {
    $owners = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($owner in @($owners)) {
        if ($owner) {
            Stop-DevPid -PidValue ([int]$owner)
        }
    }
}
