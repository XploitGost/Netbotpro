$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
Set-Location $RepoRoot

$targets = @(
    ".runtime",
    "__pycache__",
    "backend\__pycache__",
    "backend\app\__pycache__",
    "backend\app\repositories\__pycache__",
    "backend\app\schemas\__pycache__",
    "backend\app\services\__pycache__",
    "config\__pycache__",
    "core\__pycache__",
    "core\capture\__pycache__",
    "core\netbotpro_logging\__pycache__",
    "core\netbotpro_sniffer_core\__pycache__",
    "scripts\qa\__pycache__",
    "scripts\release\__pycache__",
    "tests\__pycache__",
    "frontend\dist",
    "desktop\electron\dist"
)

foreach ($target in $targets) {
    $path = Join-Path $RepoRoot $target
    if (Test-Path $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
        Write-Host "Removed $target"
    }
}
