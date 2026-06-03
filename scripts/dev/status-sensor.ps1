param()

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$RuntimeDir = Join-Path $RepoRoot ".runtime"
$PidFile = Join-Path $RuntimeDir "sensor-backend.pid"
$TokenFile = Join-Path $RuntimeDir "sensor-token.txt"
$LogDir = Join-Path $RuntimeDir "logs"
$StdoutLog = Join-Path $LogDir "sensor-backend.log"
$StderrLog = Join-Path $LogDir "sensor-backend.err.log"

$hostValue = if ($env:NETBOT_HOST) { $env:NETBOT_HOST } else { "0.0.0.0" }
$portValue = if ($env:NETBOT_PORT) { $env:NETBOT_PORT } else { "8765" }
$remoteAccess = if ($env:NETBOT_REMOTE_ACCESS) { $env:NETBOT_REMOTE_ACCESS } else { "<unknown>" }
$allowlist = if ($env:NETBOT_REMOTE_IP_ALLOWLIST) { $env:NETBOT_REMOTE_IP_ALLOWLIST } else { "<not set>" }

Write-Host "NetBotPro sensor status"
Write-Host "Endpoint: http://$hostValue`:$portValue"
Write-Host "Remote access: $remoteAccess"
Write-Host "Remote IP allowlist: $allowlist"
Write-Host "Token file: $TokenFile"
Write-Host "PID file: $PidFile"
Write-Host "Logs: $StdoutLog | $StderrLog"

if (-not (Test-Path $PidFile)) {
    Write-Host "Process: stopped (no PID file)"
    exit 0
}

$pidText = (Get-Content -Path $PidFile -Raw -ErrorAction SilentlyContinue).Trim()
if (-not $pidText -or -not ($pidText -match '^\d+$')) {
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    Write-Host "Process: stopped (invalid stale PID file removed)"
    exit 1
}

$process = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
if ($process) {
    Write-Host "Process: running PID $($process.Id)"
    exit 0
}

Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
Write-Host "Process: stopped (stale PID file removed)"
exit 1
