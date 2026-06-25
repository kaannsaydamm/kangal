# Kangal Dashboard

Multi-stage threat intelligence & recon platform. Real asset graph, real findings, real cross-scan memory, live CVE/MITRE intel, 100+ tool wrappers, interactive PTY shell, and a first-class CLI.

> **Authorized use only.** Kangal is built for red teams operating under a signed scope-of-work. Unauthorized scanning, exploitation, credential testing, or post-exploitation activity is illegal in most jurisdictions. The operator bears all legal responsibility. See [LICENSE](#license) for the full notice.

## Quick start (one command)

```bash
# Linux / macOS / WSL
./scripts/setup.sh           # installs backend + frontend deps
./scripts/setup.sh --cli     # also installs kangal-cli
./scripts/dev.sh             # starts backend (8000) + Vite (5173)
# → open http://127.0.0.1:5173
```

```powershell
# Windows PowerShell
.\scripts\setup.ps1
.\scripts\setup.ps1 -Cli
.\scripts\dev.ps1
# → open http://127.0.0.1:5173
```

Manual install? See [INSTALL.md](./INSTALL.md) for the OS-by-OS walkthrough.

## Features

- **7-stage recon pipeline** — subdomain → DNS → HTTP probe → portscan → tech → path → vuln correlator
- **Real asset graph** — `@xyflow/react` graph with drag-persistence + per-node detail panel
- **100+ tool wrappers** — nmap, nuclei, subfinder, amass, sqlmap, hydra, ffuf, bloodhound-python, msfconsole, ghidra, sliver, burp, kerbrute, certipy, roadtools, pacu, prowler, kube-hunter, Ghidra, JADX, frida, and more
- **Interactive PTY shell** — real `bash --login -i` with xterm.js + WebSocket bridge (POSIX hosts)
- **Pre-shell capability check** — detects Docker / WSL / nmap / nuclei / etc. before opening the shell
- **Onboard v2 wizard** — 6 steps with environment detect → install path choice → typed "yes i consent" gate → live install progress
- **Engagements + scope check** — kill switch, panic button, scope-violation guard
- **Cross-scan intel** — shared findings + memory search across scans
- **Live threat intel** — NVD CVE feed + MITRE ATT&CK technique browser (1h cache, offline fallback)
- **Live event stream** — per-scan WebSocket fan-out, xterm.js render
- **Tool Manager** — install / inspect / filter the 100-tool registry
- **Reports** — per-scan and combined markdown export
- **CLI** — full `kangal` command-line client (Click + httpx + rich)
- **Diagnostics modal** — header Activity button → full-screen capability matrix
- **Easter egg** — click the kangal logo 5 times for an animated bark + sound 🐶

## Stack

- **Backend**: FastAPI 0.109 + SQLAlchemy 2.0 (async) + SQLite (dev) / PostgreSQL (prod)
- **Frontend**: React 19 + Vite + Zustand + @xyflow/react + xterm.js
- **Recon agents** (Python async): crt.sh + DNS brute, Cloudflare DoH, httpx probe, nmap, tech fingerprint, path enumeration, vuln correlator

## Running (no Docker required)

Kangal runs natively on Linux, macOS, and Windows. You need:

- Python 3.11+
- Node 20+
- A C toolchain only if you want `nmap` / raw-socket scans (optional, agents fall back to TCP connect)

Detailed per-OS walkthrough: see [INSTALL.md](./INSTALL.md).

### Quick start (Linux / macOS / WSL)

```bash
# 1. Backend
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. Frontend (new shell)
cd ../frontend
npm install
npm run dev   # http://localhost:5173
```

### Quick start (Windows / PowerShell)

```powershell
# 1. Backend
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. Frontend (new shell)
cd ..\frontend
npm install
npm run dev   # http://localhost:5173
```

> **Note on the interactive shell**: the PTY-backed bash (`/ws/shell/...`) requires a POSIX host
> (forkpty). On native Windows it returns `501 Not Implemented` with a clean message; run the
> backend in WSL or Linux to use the interactive shell. All other features work on Windows.

## Architecture

```
  ┌────────────────────────────────────────────────────────────┐
  │  Frontend (Vite :5173) — 3-column recon console            │
  │  scan history │ target + stage + terminal + findings │ graph│
  └────────────┬───────────────────────────────────────────────┘
               │ REST  /api/*    +  WebSocket  /ws/scan/{id}
  ┌────────────▼───────────────────────────────────────────────┐
  │  FastAPI :8000 — REST, WebSocket, lifespan: init_db        │
  │     POST /api/scan → enqueue scan task                     │
  │     GET  /api/scan/{id}/{assets,findings,events}           │
  │     GET  /api/intel/{search,patterns}                      │
  │     POST /api/engagement/scope-check                       │
  │     POST /api/shell/sessions  + WS /ws/shell/{id}          │
  └────────────┬───────────────────────────────────────────────┘
               │ async SQLAlchemy
  ┌────────────▼───────────────────────────────────────────────┐
  │  SQLite (./kangal.db, dev)  /  PostgreSQL (prod)           │
  │   scans, assets, findings, events                          │
  └────────────────────────────────────────────────────────────┘
```

## Recon pipeline

Each stage writes to the database and pushes events to the WebSocket fan-out. On completion, all findings and per-agent outcomes are indexed into a local cross-scan intel store, queryable from the IntelSearch sidebar.

| Stage       | Discovers                                      | Tool              |
|-------------|------------------------------------------------|-------------------|
| subdomain   | subdomains                                     | crt.sh + brute    |
| dns         | A/AAAA records                                 | Cloudflare DoH    |
| http_probe  | status, title, server, headers, redirect chain | httpx             |
| portscan    | open ports + service banners                   | nmap (optional)   |
| tech        | Apache, nginx, IIS, PHP, ASP.NET, etc.         | regex             |
| pathscan    | admin, .env, .git, swagger, robots, sitemap    | httpx (80 paths)  |
| vuln        | missing CSP/HSTS, exposed panels, version leak | pattern matching  |

## Project layout

```
backend/
  app/
    main.py            FastAPI routes + WebSocket
    orchestrator.py    ReconOrchestrator (background task)
    models.py          SQLAlchemy ORM (Scan, Asset, Finding, Event)
    db.py              async + sync engines, init_db, session_scope
    intel.py           cross-scan memory + pattern store
    patterns.py        port/header/path/tech vuln patterns
    shell.py           PTY-backed interactive bash (POSIX only)
    agents/
      base.py          AgentContext, store_asset, store_finding
      subdomain.py     crt.sh + 50-prefix DNS brute
      dns.py           Cloudflare DoH + system resolver
      http_probe.py    httpx async
      portscan.py      nmap -sT -sV --top-ports 100
      tech.py          header + body regex
      pathscan.py      80-path wordlist
      vuln.py          correlator

frontend/
  src/
    App.tsx            3-column layout
    lib/
      api.ts           REST client + types
      ws.ts            per-scan WebSocket with auto-reconnect
      store.ts         Zustand store
      biStream.ts      shell WebSocket client
    components/
      TargetInput.tsx     target + passive/active mode
      StageProgress.tsx   7-stage pipeline indicator
      LiveTerminal.tsx    xterm.js live event stream
      ShellPanel.tsx      interactive PTY shell (xterm)
      AssetGraph.tsx      @xyflow/react graph
      FindingsPanel.tsx   severity filter, expand evidence
      ScanHistory.tsx     past scans list
      IntelSearch.tsx     cross-scan intel query
      EngagementPanel.tsx scope + panic + scope-check
      OnboardModal.tsx    first-run tour
```

## Notes

- **Scope**: full-spectrum offensive security — recon, active probing, vulnerability verification, exploitation, post-exploitation reconnaissance, and lateral movement mapping. Designed for authorized red team engagements and penetration tests where the operator has explicit written permission.
- **Authorization required**: Only run this against targets you own or have a signed scope-of-work for. Unauthorized scanning, exploitation, or credential testing is illegal in most jurisdictions (CFAA, GDPR, Türk Ceza Kanunu m.243-245, etc.). The operator assumes all legal responsibility.
- **Tools used externally**: crt.sh, 1.1.1.1 DoH, nmap binary (optional), target hosts you point it at. All outbound traffic is logged and attributed to the scan.
- **Storage (dev)**: SQLite at `backend/kangal.db`. Intel + patterns at `backend/.data/`.
