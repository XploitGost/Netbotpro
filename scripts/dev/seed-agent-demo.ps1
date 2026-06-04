param(
    [string]$DbPath = ".runtime/logs/agents.db",
    [int]$Count = 4,
    [switch]$Reset
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

$ResolvedDbPath = if ([System.IO.Path]::IsPathRooted($DbPath)) {
    $DbPath
} else {
    Join-Path $RepoRoot $DbPath
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ResolvedDbPath) | Out-Null

$ArgsList = @(
    "-m",
    "backend.app.services.agent_demo",
    "--db-path",
    $ResolvedDbPath,
    "--count",
    [string]$Count
)

if ($Reset) {
    $ArgsList += "--reset"
}

Write-Host "Seeding NetBotPro Agent demo data"
Write-Host "Database: $ResolvedDbPath"
Write-Host "Count: $Count"
Write-Host "Agent tokens are not printed by this command."

Push-Location $RepoRoot
try {
    & $PythonExe @ArgsList
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
