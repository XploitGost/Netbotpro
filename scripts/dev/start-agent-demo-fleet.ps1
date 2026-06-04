param(
    [int]$Count = 3,
    [string]$CentralApi = "http://127.0.0.1:8765/api",
    [int]$Interval = 15,
    [string]$AgentToken = $env:NETBOT_AGENT_TOKEN
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$RuntimeDir = Join-Path $RepoRoot ".runtime"
$FleetDir = Join-Path $RuntimeDir "agent-demo-fleet"
$LogDir = Join-Path $FleetDir "logs"
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

if ([string]::IsNullOrWhiteSpace($AgentToken)) {
    throw "Agent token is required. Pass -AgentToken or set NETBOT_AGENT_TOKEN."
}

New-Item -ItemType Directory -Force -Path $RuntimeDir, $FleetDir, $LogDir | Out-Null

Write-Host "Starting NetBotPro local Agent demo fleet"
Write-Host "Central API: $CentralApi"
Write-Host "Fleet runtime: $FleetDir"
Write-Host "Agent tokens are configured and hidden."

$Roles = @("Web Server", "Database Server", "API Server", "File Server")

for ($Index = 1; $Index -le $Count; $Index++) {
    $PidFile = Join-Path $FleetDir ("agent-{0}.pid" -f $Index)
    $StdoutLog = Join-Path $LogDir ("agent-{0}.log" -f $Index)
    $StderrLog = Join-Path $LogDir ("agent-{0}.err.log" -f $Index)

    if (Test-Path $PidFile) {
        $ExistingPid = Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ExistingPid -match "^\d+$") {
            $ExistingProcess = Get-Process -Id ([int]$ExistingPid) -ErrorAction SilentlyContinue
            if ($ExistingProcess) {
                Write-Host "Agent $Index already running with PID $ExistingPid"
                continue
            }
        }
        Remove-Item -Force $PidFile
    }

    $AgentId = [guid]::NewGuid().ToString()
    $DisplayName = if ($Index -le $Roles.Count) { $Roles[$Index - 1] } else { "Demo Agent $Index" }

    $env:NETBOT_AGENT_MODE = "1"
    $env:NETBOT_CENTRAL_API = $CentralApi
    $env:NETBOT_AGENT_TOKEN = $AgentToken
    $env:NETBOT_AGENT_ID = $AgentId
    $env:NETBOT_AGENT_DISPLAY_NAME = $DisplayName
    $env:NETBOT_AGENT_HEARTBEAT_INTERVAL = [string]$Interval
    $env:NETBOT_AGENT_TELEMETRY_INTERVAL = [string]$Interval

    $Process = Start-Process `
        -FilePath $PythonExe `
        -ArgumentList @("-m", "agent.agent_runner") `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $StdoutLog `
        -RedirectStandardError $StderrLog `
        -WindowStyle Hidden `
        -PassThru

    Set-Content -Path $PidFile -Value $Process.Id -Encoding ascii
    Write-Host "Started $DisplayName as $AgentId with PID $($Process.Id)"
    Write-Host "Log: $StdoutLog"
}
