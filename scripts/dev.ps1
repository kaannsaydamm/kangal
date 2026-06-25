<#
Kangal Dashboard — dev launcher (Windows PowerShell)
Starts backend (port 8000) and Vite frontend (port 5173) with logs.
Ctrl+C kills both.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir '..')).Path

function Say($msg) { Write-Host "[+] $msg" -ForegroundColor Green }

# --- backend ---
$backendDir = Join-Path $ProjectRoot 'backend'
$venvActivate = Join-Path $backendDir '.venv/Scripts/Activate.ps1'
if (-not (Test-Path $venvActivate)) {
  Write-Host '[!] Backend venv missing — run .\scripts\setup.ps1 first' -ForegroundColor Yellow
  exit 1
}

Say 'Starting backend on http://127.0.0.1:8000 (logs → $env:TEMP\kangal-backend.log)'
$backendLog = Join-Path $env:TEMP 'kangal-backend.log'
$backendCmd = "Set-Location '$backendDir'; & '$venvActivate'; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --backlog 2048 --timeout-keep-alive 60"
Start-Process -FilePath powershell -ArgumentList '-NoProfile','-Command',$backendCmd -RedirectStandardOutput $backendLog -RedirectStandardError "$backendLog.err" -WindowStyle Hidden

# --- frontend ---
$frontendDir = Join-Path $ProjectRoot 'frontend'
$env:VITE_BACKEND_URL = 'http://127.0.0.1:8000'
$env:VITE_BACKEND_WS_URL = 'ws://127.0.0.1:8000'

Say 'Starting frontend on http://127.0.0.1:5173 (logs → $env:TEMP\kangal-frontend.log)'
$frontendLog = Join-Path $env:TEMP 'kangal-frontend.log'
$frontendCmd = "Set-Location '$frontendDir'; `$env:VITE_BACKEND_URL='http://127.0.0.1:8000'; `$env:VITE_BACKEND_WS_URL='ws://127.0.0.1:8000'; npm run dev -- --host 127.0.0.1 --port 5173"
Start-Process -FilePath powershell -ArgumentList '-NoProfile','-Command',$frontendCmd -RedirectStandardOutput $frontendLog -RedirectStandardError "$frontendLog.err" -WindowStyle Hidden

Write-Host ''
Write-Host 'Kangal is running:' -ForegroundColor Cyan
Write-Host '  Dashboard : http://127.0.0.1:5173'
Write-Host '  API       : http://127.0.0.1:8000/docs'
Write-Host '  OpenAPI   : http://127.0.0.1:8000/redoc'
Write-Host "  Logs      : Get-Content '$backendLog' -Wait; Get-Content '$frontendLog' -Wait"
Write-Host ''
Write-Host 'Stop processes with: Get-Process python,node | Where-Object { $_.MainWindowTitle -eq '''' } | Stop-Process' -ForegroundColor Yellow
Write-Host 'Or kill by port:    Get-NetTCPConnection -LocalPort 8000,5173 -State Listen | ForEach { Stop-Process -Id \$_.OwningProcess -Force }'
Write-Host ''
Write-Host 'Press Ctrl+C to detach (processes keep running).'