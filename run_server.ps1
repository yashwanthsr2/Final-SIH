$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.\.venv312\Scripts\python.exe')) {
    Write-Host 'ERROR: .venv312 was not found. Create/use a Python 3.12 environment first.' -ForegroundColor Red
    exit 1
}

& .\.venv312\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
