param()

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$RuntimeDir = Join-Path $RepoRoot ".runtime"
$PidFile = Join-Path $RuntimeDir "sensor-backend.pid"
$LogDir = Join-Path $RuntimeDir "logs"
$StdoutLog = Join-Path $LogDir "sensor-backend.log"
$StderrLog = Join-Path $LogDir "sensor-backend.err.log"

Write-Host "NetBotPro sensor stop"
Write-Host "PID file: $PidFile"
Write-Host "Logs: $StdoutLog | $StderrLog"

if (-not (Test-Path $PidFile)) {
    Write-Host "[INFO] No sensor PID file exists."
    exit 0
}

$pidText = (Get-Content -Path $PidFile -Raw -ErrorAction SilentlyContinue).Trim()
if (-not $pidText -or -not ($pidText -match '^\d+$')) {
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    Write-Host "[WARN] Stale or invalid PID file removed."
    exit 0
}

$process = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
if (-not $process) {
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    Write-Host "[WARN] Sensor process is not running; stale PID file removed."
    exit 0
}

Stop-Process -Id $process.Id -Force
Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
Write-Host "[OK] Stopped sensor PID $($process.Id)."
