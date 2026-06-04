$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$RuntimeDir = Join-Path $RepoRoot ".runtime"
$FleetDir = Join-Path $RuntimeDir "agent-demo-fleet"
$LogDir = Join-Path $FleetDir "logs"

Write-Host "NetBotPro local Agent demo fleet status"
Write-Host "Fleet runtime: $FleetDir"
Write-Host "Agent tokens are never printed by this status command."

if (-not (Test-Path $FleetDir)) {
    Write-Host "No fleet runtime directory found."
    exit 1
}

$PidFiles = Get-ChildItem -Path $FleetDir -Filter "agent-*.pid" -ErrorAction SilentlyContinue
if (-not $PidFiles) {
    Write-Host "No demo fleet PID files found."
    exit 1
}

$AnyRunning = $false
foreach ($PidFile in $PidFiles) {
    $Name = [System.IO.Path]::GetFileNameWithoutExtension($PidFile.Name)
    $PidText = Get-Content $PidFile.FullName -ErrorAction SilentlyContinue | Select-Object -First 1
    $Index = $Name -replace "^agent-", ""
    $StdoutLog = Join-Path $LogDir ("agent-{0}.log" -f $Index)
    $StderrLog = Join-Path $LogDir ("agent-{0}.err.log" -f $Index)

    if ($PidText -notmatch "^\d+$") {
        Remove-Item -Force $PidFile.FullName
        Write-Host "$Name: invalid stale PID file removed"
        continue
    }

    $Process = Get-Process -Id ([int]$PidText) -ErrorAction SilentlyContinue
    if (-not $Process) {
        Remove-Item -Force $PidFile.FullName
        Write-Host "$Name: stopped; stale PID file removed"
        continue
    }

    $AnyRunning = $true
    $LogTime = if (Test-Path $StdoutLog) {
        (Get-Item $StdoutLog).LastWriteTime.ToString("s")
    } else {
        "missing"
    }
    Write-Host "$Name: running pid=$PidText log=$StdoutLog last_log_write=$LogTime"
    Write-Host "$Name error log: $StderrLog"
}

if ($AnyRunning) {
    exit 0
}

exit 1
