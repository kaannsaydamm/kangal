#!/usr/bin/env bash
# Kangal Dashboard — one-shot bootstrap (Linux / macOS / WSL)
# Creates venv, installs backend + frontend deps, optionally installs CLI.
#
# Usage:
#   ./scripts/setup.sh           # full setup
#   ./scripts/setup.sh --cli     # also install kangal-cli
#   ./scripts/setup.sh --no-frontend   # backend only
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

WITH_CLI=0
WITH_FRONTEND=1
for arg in "$@"; do
  case "$arg" in
    --cli) WITH_CLI=1 ;;
    --no-frontend) WITH_FRONTEND=0 ;;
    --help|-h)
      grep '^#' "$0" | sed -e 's/^# \?//'
      exit 0
      ;;
  esac
done

# --- color helpers ---
GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'; NC=$'\033[0m'
say()  { echo "${GREEN}[+]${NC} $*"; }
warn() { echo "${YELLOW}[!]${NC} $*"; }
die()  { echo "${RED}[x]${NC} $*" >&2; exit 1; }

# --- prerequisites ---
say "Checking prerequisites…"
PYTHON_BIN=""
for c in python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1; then
    PYTHON_BIN="$c"
    break
  fi
done
[ -n "$PYTHON_BIN" ] || die "Python 3.11+ not found. Install via: brew install python@3.11 | sudo apt install -y python3.11"
PY_VER="$($PYTHON_BIN -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
say "Using $PYTHON_BIN ($PY_VER)"

if [ "$WITH_FRONTEND" = "1" ]; then
  command -v node >/dev/null 2>&1 || die "Node 20+ not found. Install via: brew install node@20 | https://deb.nodesource.com/setup_20.x"
  NODE_VER="$(node -v | tr -d 'v')"
  say "Using node $NODE_VER"
fi

# --- system packages (Linux only, optional) ---
if [ "$WITH_FRONTEND" = "1" ] && command -v apt-get >/dev/null 2>&1 && [ -z "${SKIP_APT:-}" ]; then
  warn "Optional: install recon tools via apt (requires sudo). Re-run with SKIP_APT=1 to skip."
  if [ -t 0 ]; then
    read -r -p "Install apt recon packages now? [y/N] " ans || ans="N"
    case "$ans" in
      [Yy]*) sudo apt-get update && sudo apt-get install -y nmap nuclei git curl build-essential ;;
    esac
  fi
fi

# --- backend ---
say "Setting up backend venv…"
cd "$PROJECT_ROOT/backend"
[ -d .venv ] || "$PYTHON_BIN" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip wheel setuptools
say "Installing backend dependencies…"
pip install -r requirements.txt
[ -f requirements-dev.txt ] && pip install -r requirements-dev.txt || true

# --- frontend ---
if [ "$WITH_FRONTEND" = "1" ]; then
  say "Installing frontend dependencies…"
  cd "$PROJECT_ROOT/frontend"
  if command -v npm >/dev/null 2>&1; then
    npm install --no-audit --no-fund
  else
    die "npm not found"
  fi
fi

# --- kangal-cli (optional) ---
if [ "$WITH_CLI" = "1" ]; then
  say "Installing kangal-cli…"
  cd "$PROJECT_ROOT/cli"
  pip install -e .
fi

# --- .env defaults ---
cd "$PROJECT_ROOT"
if [ ! -f frontend/.env.local ]; then
  cat > frontend/.env.local <<'EOF'
VITE_BACKEND_URL=http://127.0.0.1:8000
VITE_BACKEND_WS_URL=ws://127.0.0.1:8000
EOF
  say "Wrote frontend/.env.local (127.0.0.1 backend)"
fi

say "Done."
echo
echo "Next steps:"
echo "  ./scripts/dev.sh           # start backend (8000) + frontend (5173)"
echo "  open http://127.0.0.1:5173"
echo
echo "  ./scripts/setup.sh --cli   # install kangal-cli for terminal use"
echo "  kangal --help"