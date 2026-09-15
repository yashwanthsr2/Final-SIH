$ErrorActionPreference = 'Stop'

$pythonCmd = if (Test-Path '.\.venv312\Scripts\python.exe') { '.\.venv312\Scripts\python.exe' } else { 'python' }

Write-Host "Starting CyberSentinel Unified SOC Platform on http://127.0.0.1:8000..." -ForegroundColor Cyan
& $pythonCmd -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

