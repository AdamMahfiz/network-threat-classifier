# Bootstrap and run the Network Threat Classifier (Windows PowerShell)
# This version uses your existing environment as-is:
# - Does NOT create a virtual environment
# - Does NOT install dependencies
# - Does NOT create or modify .env
# - Simply activates .venv if it already exists, then runs app.py

$ErrorActionPreference = 'Stop'

Write-Host "Starting Network Threat Classifier..." -ForegroundColor Cyan

if (!(Test-Path ".\.env")) {
    Write-Host ".env not found. The app will rely on existing OS env vars." -ForegroundColor Yellow
}

# Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed or not in PATH. Install Python 3.10+ and retry."
    exit 1
}

<#
Optionally activate .venv if it already exists. If not, use current env.
#>
$venvActivate = ".\.venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) {
    . $venvActivate
    Write-Host "Activated existing .venv." -ForegroundColor Green
} else {
    Write-Host "No .venv found; using current Python environment." -ForegroundColor Yellow
}

# Run the app
Write-Host "Launching app.py..." -ForegroundColor Cyan
python app.py