$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$RuntimeDir = Join-Path $RepoRoot ".runtime"
$FleetDir = Join-Path $RuntimeDir "agent-demo-fleet"
$LogDir = Join-Path $FleetDir "logs"

Write-Host "Stopping NetBotPro local Agent demo fleet"
Write-Host "Fleet runtime: $FleetDir"
Write-Host "Agent tokens are never printed by this command."

if (-not (Test-Path $FleetDir)) {
    Write-Host "No fleet runtime directory found."
    exit 0
}

$PidFiles = Get-ChildItem -Path $FleetDir -Filter "agent-*.pid" -ErrorAction SilentlyContinue
if (-not $PidFiles) {
    Write-Host "No demo fleet PID files found."
    exit 0
}

foreach ($PidFile in $PidFiles) {
    $Name = [System.IO.Path]::GetFileNameWithoutExtension($PidFile.Name)
    $PidText = Get-Content $PidFile.FullName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($PidText -notmatch "^\d+$") {
        Remove-Item -Force $PidFile.FullName
        Write-Host "$Name: invalid stale PID file removed"
        continue
    }

    $Process = Get-Process -Id ([int]$PidText) -ErrorAction SilentlyContinue
    if ($Process) {
        Stop-Process -Id ([int]$PidText) -Force
        Write-Host "$Name: stopped pid=$PidText"
    } else {
        Write-Host "$Name: already stopped"
    }
    Remove-Item -Force $PidFile.FullName
}

Write-Host "Fleet logs remain in $LogDir"
