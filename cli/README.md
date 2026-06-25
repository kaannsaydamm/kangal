# Kangal CLI

A Click-based command-line client for the [Kangal Dashboard](../README.md) backend.

## Install

```bash
cd cli
pip install -e .
```

After installation, the `kangal` executable is on your PATH.

## Backend URL

The CLI talks to `KANGAL_BACKEND_URL`. Default: `http://127.0.0.1:8000`.

```bash
export KANGAL_BACKEND_URL="http://127.0.0.1:8000"
kangal --help
kangal system diag
```

## Quick start

```bash
kangal --help
kangal system diag
kangal system onboard              # interactive wizard
kangal scan list
kangal scan start evilcorp.com --mode active --wait
kangal scan get <scan_id>
kangal scan events <scan_id> --follow
kangal tool list --tier 1
kangal tool list --category web_exploit
kangal tool run nuclei --target evilcorp.com --engagement-mode passive
kangal intel patterns
kangal intel search "open port"
kangal engagement list
kangal engagement create --name "Q3 Audit" --client acme --operator me --scope-domains evilcorp.com
kangal engagement scope-check evilcorp.com --engagement <id>
kangal toolbox summary
```

## Global flags

| Flag      | Effect                                                   |
| --------- | -------------------------------------------------------- |
| `--json`  | Emit raw JSON to stdout instead of formatted tables.     |
| `--backend-url URL` | Override `KANGAL_BACKEND_URL` for this invocation. |

## Exit codes

| Code | Meaning                                          |
| ---- | ------------------------------------------------ |
| 0    | Success                                          |
| 1    | Backend returned a 4xx / 5xx                     |
| 2    | Backend unreachable (network / connection error) |
| 3    | Invalid user input                               |

## Subcommand reference

```
kangal scan (list | get <id> | start <target> [--mode …] [--engagement <id>] [--wait] | events <id> [--follow] [--tail N])
kangal intel (search <query> | patterns | memory (list | search <query>))
kangal engagement (list | get <id> | create --name … --client … --operator … [--scope-domains …] [--scope-cidrs …] [--profile …] [--destructive] | scope-check <target> [--engagement <id>] | panic <id>)
kangal tool (list [--category …] [--tier 1|2] [--search …] | run <name> <args…> | install <name> | info <name>)
kangal shell (sessions | open [--cols 120] [--rows 32] | close <session_id>)
kangal system (diag [--binary <name>] | onboard | install <binary>)
kangal toolbox (summary)
```

## Interactive PTY shell

`kangal shell open` spawns a bash PTY on the backend and streams its I/O
through a WebSocket to your terminal. Requires:

- A POSIX host (Linux / WSL / macOS) on the backend side.
- The optional `websocket-client` package for full-duplex I/O. Without it,
  the CLI uses a built-in text-only WS fallback.

## Onboard wizard

`kangal system onboard` walks the user through the same state machine as
the frontend's onboarding modal:

1. Welcome / skip
2. Detect host capabilities (calls `/api/system/diag`)
3. Choose install path: native / wsl / skip
4. Type `yes i consent` to record consent
5. Install missing recommended binaries (polls `/api/system/install/<id>/status`)
6. Finish (`POST /api/onboard/finish`)

Use `--json` to skip prompts and dump the current state snapshot.

## Troubleshooting

- `Backend not reachable at …` — start the FastAPI backend (`uvicorn app.main:app` from `backend/`) or set `KANGAL_BACKEND_URL`.
- `install requires root/admin` — run the backend with sudo / as Administrator, or pre-install the binary manually.
- `501 Interactive shell requires a POSIX host` — the backend is on Windows natively. Run it under WSL or Docker.