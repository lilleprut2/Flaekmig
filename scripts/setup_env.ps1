#!/usr/bin/env pwsh
# PowerShell script to create virtual environment and install requirements (Windows)
param(
    [string]$EnvDir = ".venv"
)

if (Test-Path $EnvDir) {
    Write-Host "Virtualenv already exists at $EnvDir"
} else {
    python -m venv $EnvDir
    Write-Host "Created virtualenv at $EnvDir"
}

Write-Host "To activate the environment run: .\$EnvDir\Scripts\Activate.ps1"
Write-Host "Upgrading pip and installing requirements..."
& "$EnvDir/Scripts/python.exe" -m pip install --upgrade pip
if (Test-Path "requirements.txt") {
    & "$EnvDir/Scripts/python.exe" -m pip install -r requirements.txt
}

Write-Host "Setup complete. Activate with: .\$EnvDir\Scripts\Activate.ps1"
