param(
    [string]$DbPath = ".runtime/logs/agents.db",
    [int]$RetentionDays = 30,
    [switch]$DryRun
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

Write-Host "Cleaning NetBotPro Agent history"
Write-Host "Database: $ResolvedDbPath"
Write-Host "Retention days: $RetentionDays"
Write-Host "Dry run: $([bool]$DryRun)"
Write-Host "Agent tokens are never printed by this command."

$DryRunLiteral = if ($DryRun) { "True" } else { "False" }
$Code = @"
import json
from backend.app.services.agent_registry import cleanup_agent_history
result = cleanup_agent_history($RetentionDays, storage_path=r'''$ResolvedDbPath''', dry_run=$DryRunLiteral)
print(json.dumps(result, indent=2))
"@

Push-Location $RepoRoot
try {
    $Code | & $PythonExe -
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
