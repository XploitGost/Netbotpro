$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$RuntimeDir = Join-Path $RepoRoot ".runtime"
$LogDir = Join-Path $RuntimeDir "logs"
$PidFile = Join-Path $RuntimeDir "agent-runner.pid"
$StdoutLog = Join-Path $LogDir "agent-runner.log"
$StderrLog = Join-Path $LogDir "agent-runner.err.log"

Write-Host "NetBotPro Agent status"
Write-Host "PID file: $PidFile"
Write-Host "Log: $StdoutLog"
Write-Host "Error log: $StderrLog"
Write-Host "Agent token is never printed by this status command."

if (-not (Test-Path $PidFile)) {
    Write-Host "Status: stopped"
    exit 1
}

$PidText = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
if ($PidText -notmatch "^\d+$") {
    Remove-Item -Force $PidFile
    Write-Host "Status: invalid stale PID file removed"
    exit 1
}

$Process = Get-Process -Id ([int]$PidText) -ErrorAction SilentlyContinue
if (-not $Process) {
    Remove-Item -Force $PidFile
    Write-Host "Status: stale PID file removed"
    exit 1
}

Write-Host "Status: running"
Write-Host "PID: $PidText"
Write-Host "Process: $($Process.ProcessName)"
