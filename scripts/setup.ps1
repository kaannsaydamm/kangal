<#
Kangal Dashboard — one-shot bootstrap (Windows PowerShell)
Creates venv, installs backend + frontend deps, optionally installs CLI.

Usage:
  .\scripts\setup.ps1           # full setup
  .\scripts\setup.ps1 -Cli      # also install kangal-cli
  .\scripts\setup.ps1 -NoFrontend   # backend only
#>
[CmdletBinding()]
param(
  [switch]$Cli,
  [switch]$NoFrontend,
  [switch]$SkipChoco
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir '..')).Path
Set-Location $ProjectRoot

function Say($msg)  { Write-Host "[+] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Die($msg)  { Write-Host "[x] $msg" -ForegroundColor Red; exit 1 }

# --- prerequisites ---
Say 'Checking prerequisites…'

$py = $null
foreach ($c in @('python', 'py')) {
  $cmd = Get-Command $c -ErrorAction SilentlyContinue
  if ($cmd) { $py = $c; break }
}
if (-not $py) { Die "Python 3.11+ not found. Install from https://www.python.org/downloads/windows/ (tick 'Add python.exe to PATH')" }
$pyVer = & $py -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"
Say "Using $py ($pyVer)"

if (-not $NoFrontend) {
  if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Die "Node 20+ not found. Install from https://nodejs.org/en/download"
  }
  Say "Using node $(node -v)"
}

# --- optional winget/choco install of recon tools ---
if (-not $SkipChoco -and -not $NoFrontend) {
  $hasChoco = [bool](Get-Command choco -ErrorAction SilentlyContinue)
  $hasWinget = [bool](Get-Command winget -ErrorAction SilentlyContinue)
  if ($hasChoco -or $hasWinget) {
    Warn "Optional: install nmap/git via $((Get-Command choco -ErrorAction SilentlyContinue) ? 'choco' : 'winget'). Re-run with -SkipChoco to skip."
  }
}

# --- backend ---
Say 'Setting up backend venv…'
$backendDir = Join-Path $ProjectRoot 'backend'
Set-Location $backendDir
if (-not (Test-Path .venv)) {
  & $py -m venv .venv
}
& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip wheel setuptools | Out-Null
Say 'Installing backend dependencies…'
pip install -r requirements.txt
if (Test-Path requirements-dev.txt) { pip install -r requirements-dev.txt }

# --- frontend ---
if (-not $NoFrontend) {
  Say 'Installing frontend dependencies…'
  Set-Location (Join-Path $ProjectRoot 'frontend')
  if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Die 'npm not found'
  }
  npm install --no-audit --no-fund
}

# --- kangal-cli ---
if ($Cli) {
  Say 'Installing kangal-cli…'
  Set-Location (Join-Path $ProjectRoot 'cli')
  pip install -e .
}

# --- .env defaults ---
Set-Location $ProjectRoot
$envLocal = Join-Path $ProjectRoot 'frontend/.env.local'
if (-not (Test-Path $envLocal)) {
  @'
VITE_BACKEND_URL=http://127.0.0.1:8000
VITE_BACKEND_WS_URL=ws://127.0.0.1:8000
'@ | Set-Content -Path $envLocal -Encoding UTF8
  Say 'Wrote frontend/.env.local'
}

Say 'Done.'
Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Cyan
Write-Host '  .\scripts\dev.ps1           # start backend (8000) + frontend (5173)'
Write-Host '  open http://127.0.0.1:5173'
Write-Host ''
Write-Host '  .\scripts\setup.ps1 -Cli    # install kangal-cli'
Write-Host '  kangal --help'