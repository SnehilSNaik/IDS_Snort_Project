<#
Starts the Windows-hosted IDS demonstration. Run from an elevated PowerShell
when you need Scapy capture or Windows Firewall rules.

Docker mode is intentionally separate: use `docker compose up --build` for
the portable dashboard/correlation demo, and this script for real host capture.
#>

param(
    [switch]$NoFrontend
)

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonLauncher = Get-Command py -ErrorAction SilentlyContinue
if (-not $pythonLauncher) {
    throw "Python Launcher (py.exe) was not found. Install Python 3.10+ and the project requirements first."
}

# TensorFlow supports Python through 3.13. The legacy Windows py launcher may
# not discover a user-scoped 3.13 install, so check its standard path first.
$python313 = Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"
if (Test-Path $python313) {
    $pythonSelector = "& '$python313'"
} else {
    & py -3.13 -c "import sys" 2>$null
    $pythonSelector = if ($LASTEXITCODE -eq 0) { "py -3.13" } else { "py -3" }
}
if ($pythonSelector -eq "py -3") {
    Write-Warning "Python 3.13 is not installed. The dashboard and RF detector can run, but the TensorFlow/LSTM detector requires Python 3.13."
}

Write-Host "Starting IDS backend on http://localhost:5000" -ForegroundColor Cyan
Start-Process powershell -ArgumentList @(
    "-NoExit", "-Command",
    "Set-Location -LiteralPath '$projectRoot'; $pythonSelector backend\start_ids.py"
)

if (-not $NoFrontend) {
    Write-Host "Starting React dashboard on http://localhost:5173" -ForegroundColor Cyan
    Start-Process powershell -ArgumentList @(
        "-NoExit", "-Command",
        "Set-Location -LiteralPath '$projectRoot\frontend'; npm run dev"
    )
}

Write-Host "Use the dashboard's Engage IDS Engine button after logging in." -ForegroundColor Green
