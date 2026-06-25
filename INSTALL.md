# Installing Kangal — OS-Specific Guide

Kangal runs natively on Linux, macOS, and Windows. You need **Python 3.11+** and **Node 20+**. The interactive PTY shell requires a POSIX host (Linux / macOS / WSL).

---

## macOS

### 1. Toolchain (Xcode Command Line Tools)
```bash
xcode-select --install
```

### 2. Python 3.11+ (via Homebrew)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python@3.11 node@20
echo 'export PATH="/opt/homebrew/opt/python@3.11/bin:/opt/homebrew/opt/node@20/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### 3. Optional recon tools
```bash
brew install nmap
```

### 4. Backend
```bash
cd backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 5. Frontend (new terminal)
```bash
cd frontend
npm install
npm run dev   # http://localhost:5173
```

> **Note**: the interactive PTY shell (`SHELL` button) works on macOS out of the box.

---

## Linux (Debian / Ubuntu)

### 1. System packages
```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip curl ca-certificates gnupg
# Node 20 (NodeSource)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### 2. Optional recon tools
```bash
sudo apt install -y nmap
```

### 3. Backend
```bash
cd backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 4. Frontend (new terminal)
```bash
cd frontend
npm install
npm run dev   # http://localhost:5173
```

> **Note**: the interactive PTY shell works on Linux out of the box.

---

## Linux (Fedora / RHEL)

```bash
sudo dnf install -y python3.11 python3.11-devel python3-pip nodejs npm nmap
cd backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
# (new terminal)
cd ../frontend && npm install && npm run dev
```

---

## Windows (native, no WSL)

> **PTY shell caveat**: the interactive `SHELL` button returns `501` on native Windows because Windows has no `forkpty`. All other features (recon, scan history, asset graph, intel search, scope check, findings) work normally. To use the interactive shell, install WSL (see below) and run the backend there.

### 1. Python (official installer)
- Download **Python 3.11+** from https://www.python.org/downloads/windows/
- During install, **tick "Add python.exe to PATH"**
- Verify: `python --version`

### 2. Node 20 LTS
- Download the Windows installer from https://nodejs.org/en/download
- Run with default options (this also adds `node` + `npm` to PATH)
- Verify: `node --version && npm --version`

### 3. Optional recon tools
- **nmap**: https://nmap.org/download.html (Windows self-installer)
- Add `C:\Program Files (x86)\Nmap` to PATH

### 4. Backend (PowerShell)
```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

If you hit `ModuleNotFoundError: No module named 'aiosqlite'` on a fresh venv, install it explicitly:
```powershell
pip install aiosqlite
```

### 5. Frontend (new PowerShell window)
```powershell
cd frontend
npm install
npm run dev   # http://localhost:5173
```

---

## Windows (WSL — full features, including interactive shell)

This is the recommended setup on Windows if you want every feature (including the PTY bash).

### 1. Install WSL
```powershell
wsl --install
# restart when prompted
```

### 2. Inside WSL (Ubuntu) — follow the Linux / Debian section above
```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip curl
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### 3. Run backend & frontend inside WSL
```bash
cd /mnt/c/Users/<you>/Desktop/kangal/backend
source .venv/bin/activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
# (new WSL terminal)
cd /mnt/c/Users/<you>/Desktop/kangal/frontend
npm install && npm run dev
```

Open <http://localhost:5173> from your Windows browser.

---

## Common configuration

### Environment variables

The backend reads these (all optional, sensible defaults for dev):

| Variable               | Default                    | Purpose                                   |
|------------------------|----------------------------|-------------------------------------------|
| `DATABASE_URL`         | `sqlite:///./kangal.db`    | SQLAlchemy URL. Postgres example: `postgresql+asyncpg://user:pass@host/kangal` |
| `KANGAL_SHELL_CWD`     | `/data`                    | Where interactive bash starts             |
| `KANGAL_REDTEAM_TOKEN` | (random UUID)              | Required header on redteam event sinks    |

Frontend reads these (set in `frontend/.env.local`):

| Variable                | Default                        | Purpose                          |
|-------------------------|--------------------------------|----------------------------------|
| `VITE_BACKEND_URL`      | `http://127.0.0.1:8000`        | REST base                        |
| `VITE_BACKEND_WS_URL`   | `ws://127.0.0.1:8000`          | WebSocket base                   |

### First-run health check

Once both processes are up:

```bash
curl http://127.0.0.1:8000/api/intel/patterns   # →  {"patterns":[]}
```

Open <http://localhost:5173>, click the `?` icon (top right) for the welcome tour, then `ENGAGE` a target.

---

## Troubleshooting

| Symptom                                         | Fix                                                                            |
|-------------------------------------------------|--------------------------------------------------------------------------------|
| `Failed to resolve import "zustand"` in Vite    | `cd frontend && npm install` (deps are not vendored)                           |
| `getaddrinfo ENOTFOUND backend`                 | Vite is proxying to Docker hostname. Set `VITE_BACKEND_URL=http://127.0.0.1:8000` in `frontend/.env.local`. |
| `too many values to unpack` on Windows SQLAlchemy URL | Use relative path `sqlite:///./kangal.db`, not `C:/...`                  |
| `Interactive shell requires a POSIX host`       | PTY needs `forkpty` — run backend in Linux / macOS / WSL, not native Windows   |
| `aiosqlite` import error                        | `pip install aiosqlite`                                                        |
| Port 8000 or 5173 already in use                | `lsof -i :8000` / `netstat -ano \| findstr :8000`, then kill the PID           |
| Recon hangs at portscan                         | Install `nmap` and ensure it's on PATH, or disable portscan in agent config    |

---

## Verifying your install

Run the end-to-end smoke test (after both backend and frontend are up):

```bash
node tests/e2e/kangal.spec.mjs
```

Expected output ends with `PASS: 57  FAIL: 0` (or `PASS: 56 FAIL: 0` on native Windows — the PTY echo test is reported as "shell route correctly rejects non-POSIX host", which is correct behaviour).
