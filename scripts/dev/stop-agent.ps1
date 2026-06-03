$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$RuntimeDir = Join-Path $RepoRoot ".runtime"
$LogDir = Join-Path $RuntimeDir "logs"
$PidFile = Join-Path $RuntimeDir "agent-runner.pid"
$StdoutLog = Join-Path $LogDir "agent-runner.log"
$StderrLog = Join-Path $LogDir "agent-runner.err.log"

Write-Host "Stopping NetBotPro Agent"
Write-Host "PID file: $PidFile"
Write-Host "Log: $StdoutLog"
Write-Host "Error log: $StderrLog"

if (-not (Test-Path $PidFile)) {
    Write-Host "Status: stopped"
    exit 0
}

$PidText = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
if ($PidText -notmatch "^\d+$") {
    Remove-Item -Force $PidFile
    Write-Host "Status: invalid stale PID file removed"
    exit 0
}

$Process = Get-Process -Id ([int]$PidText) -ErrorAction SilentlyContinue
if ($Process) {
    Stop-Process -Id ([int]$PidText) -Force
    Write-Host "Stopped PID $PidText"
} else {
    Write-Host "Status: stale PID file removed"
}

Remove-Item -Force $PidFile
