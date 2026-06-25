#!/usr/bin/env bash
# Kangal Dashboard — dev launcher (Linux / macOS / WSL)
# Starts backend (port 8000) and Vite frontend (port 5173) with logs.
# Ctrl+C kills both.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN=$'\033[0;32m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
say() { echo "${GREEN}[+]${NC} $*"; }

# --- backend ---
if [ ! -d "$PROJECT_ROOT/backend/.venv" ]; then
  echo "${CYAN}[*]${NC} Backend venv missing — run ./scripts/setup.sh first"
  exit 1
fi

# shellcheck disable=SC1091
source "$PROJECT_ROOT/backend/.venv/bin/activate"

cd "$PROJECT_ROOT/backend"
unset DATABASE_URL_ASYNC || true

say "Starting backend on http://127.0.0.1:8000 (logs → /tmp/kangal-backend.log)"
nohup python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --backlog 2048 --timeout-keep-alive 60 \
  > /tmp/kangal-backend.log 2>&1 &
BACK_PID=$!
echo $BACK_PID > /tmp/kangal-backend.pid

# --- frontend ---
cd "$PROJECT_ROOT/frontend"
export VITE_BACKEND_URL="${VITE_BACKEND_URL:-http://127.0.0.1:8000}"
export VITE_BACKEND_WS_URL="${VITE_BACKEND_WS_URL:-ws://127.0.0.1:8000}"

say "Starting frontend on http://127.0.0.1:5173 (logs → /tmp/kangal-frontend.log)"
nohup npm run dev -- --host 127.0.0.1 --port 5173 \
  > /tmp/kangal-frontend.log 2>&1 &
FRONT_PID=$!
echo $FRONT_PID > /tmp/kangal-frontend.pid

trap 'echo; echo "Shutting down…"; kill "$BACK_PID" "$FRONT_PID" 2>/dev/null || true; exit 0' INT TERM EXIT

cat <<EOF

${CYAN}Kangal is running:${NC}
  Dashboard : http://127.0.0.1:5173
  API       : http://127.0.0.1:8000/docs
  OpenAPI   : http://127.0.0.1:8000/redoc
  Logs      : tail -f /tmp/kangal-backend.log /tmp/kangal-frontend.log

  PID files : /tmp/kangal-backend.pid /tmp/kangal-frontend.pid
  Ctrl+C to stop both.
EOF

# Wait for either to exit
wait "$BACK_PID" "$FRONT_PID"