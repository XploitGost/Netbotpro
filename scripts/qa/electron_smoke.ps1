$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ElectronDir = Join-Path $RepoRoot "desktop\electron"
$ElectronBinary = Join-Path $ElectronDir "node_modules\electron\dist\electron.exe"
$ElectronPathFile = Join-Path $ElectronDir "node_modules\electron\path.txt"
$FrontendApp = Join-Path $RepoRoot "frontend\dist\app.html"
$MainFile = Join-Path $ElectronDir "main.cjs"

function Assert-Path {
    param(
        [string]$Path,
        [string]$Label
    )
    if (-not (Test-Path $Path)) {
        throw "$Label is missing: $Path"
    }
    Write-Host "[OK] $Label - $Path"
}

Assert-Path -Path $ElectronBinary -Label "Electron binary"
Assert-Path -Path $ElectronPathFile -Label "Electron path file"
Assert-Path -Path $MainFile -Label "Electron main"

$pathText = (Get-Content $ElectronPathFile -Raw).Trim()
if ($pathText -ne "electron.exe") {
    throw "Electron path.txt must contain electron.exe, got: $pathText"
}
Write-Host "[OK] Electron path.txt"

if (-not (Test-Path $FrontendApp)) {
    Write-Host "[INFO] Frontend dist is missing; building it now."
    npm --prefix (Join-Path $RepoRoot "frontend") run build
}
Assert-Path -Path $FrontendApp -Label "Frontend desktop asset"

Write-Host "[OK] Electron smoke passed"
