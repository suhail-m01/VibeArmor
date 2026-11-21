$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  VibeArmor v3.6 Full-Stack Studio & Multi-Editor Guard" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan

$py = $null
if ($env:VIRTUAL_ENV -and (Test-Path "$env:VIRTUAL_ENV\Scripts\python.exe")) {
    $py = "$env:VIRTUAL_ENV\Scripts\python.exe"
} elseif (Test-Path ".\.venv\Scripts\python.exe") {
    $py = ".\.venv\Scripts\python.exe"
} elseif (Get-Command "python" -ErrorAction SilentlyContinue) {
    $py = "python"
} elseif (Get-Command "py" -ErrorAction SilentlyContinue) {
    $py = "py"
}

if (-not $py) {
    Write-Host "ERROR: Python 3.10+ not found on PATH. Install Python from https://python.org (check 'Add Python to PATH')." -ForegroundColor Red
    exit 1
}

Write-Host "==> Checking Python dependencies ($py)..." -ForegroundColor Yellow
& $py -m pip install -q -r requirements.txt
& $py -m pip install -q -e . --no-deps

$vsix = Join-Path $PSScriptRoot "ide-extension\vibearmor-guard-3.6.0.vsix"
if ((Test-Path $vsix) -and (Get-Command "code" -ErrorAction SilentlyContinue)) {
    Remove-Item -Recurse -Force "$env:USERPROFILE\.vscode\extensions\nexgen-coders.vibearmor-ide-guard-3.0*" -ErrorAction SilentlyContinue
    code --install-extension $vsix --force | Out-Null
    Write-Host "==> Ensured VibeArmor VS Code Extension v3.6.0 is installed ✓" -ForegroundColor Green
}

Write-Host "==> Launching VibeArmor Full-Stack Studio at http://127.0.0.1:8000 ..." -ForegroundColor Green
Start-Job -ScriptBlock { Start-Sleep -Seconds 2; Start-Process "http://127.0.0.1:8000" } | Out-Null
$env:PYTHONPATH = $PSScriptRoot
& $py -m uvicorn core.interfaces.api:app --host 127.0.0.1 --port 8000
