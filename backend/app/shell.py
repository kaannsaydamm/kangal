"""Kangal Interactive Shell — PTY-backed bash sessions.

The dashboard exposes a real interactive bash inside the backend container so
operators can run recon tools (nmap, dig, curl, jq, whois…) interactively.
Each session is a `bash --login -i` spawned under `ptyprocess.spawn()`; the
process file descriptor is wrapped in a non-blocking loop that pipes bytes
both ways via asyncio.

Security posture
----------------
* Sessions are scoped to the backend container — they have the same
  capability set as the API (NET_RAW/NET_ADMIN if compose granted them).
* Cwd is the shared `/data` volume so intel persists across sessions.
* HOME=/tmp because we don't want sessions to read user dotfiles.
* PATH includes `/opt/kangal-toolbox/bin` so operators can call the
  recon tools (subfinder, nuclei, …) that live in the toolbox image
  (volume-mounted from the host).  If the directory is missing (e.g.
  dev compose without toolbox), bash still works.
* Sessions expire after `SESSION_TTL_S` (900 s) of inactivity; an
  asyncio reaper task in main.py's lifespan loop enforces it.
"""
from __future__ import annotations

import asyncio
import base64
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

# PTY size is Unix-only — fcntl/termios live in libutil on POSIX, and
# ptyprocess.spawn needs forkpty.  On Windows the dashboard shows a
# clean "not supported on this platform" response rather than crashing
# the whole backend.  KISS: try/except import, gate session creation.
try:
    import fcntl  # type: ignore[import-not-found]
    import termios  # type: ignore[import-not-found]
    import struct  # used by set_winsize ioctl
    import ptyprocess  # type: ignore[import-not-found]
    _SHELL_SUPPORTED = sys.platform != "win32" and hasattr(os, "forkpty")
except Exception:
    fcntl = None  # type: ignore[assignment]
    termios = None  # type: ignore[assignment]
    struct = None  # type: ignore[assignment]
    ptyprocess = None  # type: ignore[assignment]
    _SHELL_SUPPORTED = False


def is_supported() -> bool:
    """False on platforms where we can't open a PTY (e.g. native Windows)."""
    return _SHELL_SUPPORTED


class ShellUnsupported(RuntimeError):
    """Raised by create_session on platforms without a working PTY."""


# PTY size defaults — xterm will resize on first WS message.
DEFAULT_COLS = 120
DEFAULT_ROWS = 32
SESSION_TTL_S = 900  # 15 min idle TTL


@dataclass
class ShellSession:
    """A single bash process owned by one WebSocket client."""
    session_id: str
    proc: "ptyprocess.PtyProcess"
    cols: int
    rows: int
    created_at: float
    last_activity: float = field(default_factory=time.time)

    def touch(self) -> None:
        self.last_activity = time.time()

    @property
    def alive(self) -> bool:
        return self.proc.isalive()

    def write(self, data: bytes) -> None:
        try:
            self.proc.write(data)
        except OSError:
            # PTY closed — caller will see exit frame shortly
            pass

    def set_winsize(self, cols: int, rows: int) -> None:
        if cols <= 0 or rows <= 0:
            return
        # TIOCSWINSZ ioctl — POSIX only. On platforms without fcntl
        # (e.g. Windows) the session simply ignores resize; the client
        # still gets bytes flowing.
        if fcntl is None or termios is None or struct is None:
            self.cols = cols
            self.rows = rows
            return
        fcntl.ioctl(
            self.proc.fd,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", rows, cols, 0, 0),
        )
        self.cols = cols
        self.rows = rows

    def read(self, size: int = 4096) -> bytes:
        try:
            return self.proc.read(size)
        except EOFError:
            return b""
        except OSError:
            return b""

    def close(self) -> int:
        """Terminate the bash process. Returns the exit code or 0 if already dead."""
        if not self.alive:
            return 0
        try:
            self.proc.terminate(force=False)
        except Exception:
            try:
                self.proc.terminate(force=True)
            except Exception:
                pass
        # Wait briefly for graceful exit
        for _ in range(20):
            if not self.alive:
                break
            time.sleep(0.05)
        if self.alive:
            try:
                self.proc.kill()
            except Exception:
                pass
        try:
            return self.proc.exitstatus or 0
        except Exception:
            return 0


_SESSIONS: dict[str, ShellSession] = {}
_LOCK = asyncio.Lock()


def _build_env(cwd: str, home: str) -> dict[str, str]:
    """Construct a minimal, predictable env for the operator's bash."""
    # Start from a sanitized subset — we never want a 50 MB cloud token
    # the API process inherited leaking into the operator's shell.
    path = (
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
        "/sbin:/bin:/opt/kangal-toolbox/bin"
    )
    return {
        "PATH": path,
        "HOME": home,
        "PWD": cwd,
        "SHELL": "/bin/bash",
        "TERM": "xterm-256color",
        "PS1": "\\u@\\h:\\w\\$ ",
        # keep docker/k8s probes quiet
        "DOCKER_CLI_HINTS": "false",
    }


def _ensure_data_dir() -> str:
    """The shell starts in `/data` (the shared intel volume)."""
    cwd = os.getenv("KANGAL_SHELL_CWD", "/data")
    try:
        os.makedirs(cwd, exist_ok=True)
    except Exception:
        cwd = "/tmp"
    return cwd


def create_session(cols: int = DEFAULT_COLS, rows: int = DEFAULT_ROWS) -> ShellSession:
    """Spawn a new bash --login -i under a fresh PTY."""
    if not _SHELL_SUPPORTED or ptyprocess is None:
        raise ShellUnsupported(
            "Interactive shell requires a POSIX host (forkpty). "
            "Run the backend in Docker / WSL / Linux, not native Windows."
        )
    cols = max(20, min(cols, 400))
    rows = max(5, min(rows, 200))
    cwd = _ensure_data_dir()
    home = "/tmp"

    env = _build_env(cwd=cwd, home=home)
    argv = ["/bin/bash", "--login", "-i"]

    # ptyprocess.spawn handles forkpty internally; this is the lowest
    # possible layer (no asyncio.create_subprocess_exec shim).
    proc = ptyprocess.spawn(
        argv,
        cwd=cwd,
        env=env,
        dimensions=(rows, cols),
        echo=True,           # let the terminal handle echo (xterm does)
        preexec_fn=os.setsid,
    )

    sid = uuid.uuid4().hex[:16]
    sess = ShellSession(
        session_id=sid,
        proc=proc,
        cols=cols,
        rows=rows,
        created_at=time.time(),
    )
    _SESSIONS[sid] = sess
    return sess


def get_session(session_id: str) -> Optional[ShellSession]:
    return _SESSIONS.get(session_id)


def list_sessions() -> list[dict]:
    return [
        {
            "session_id": s.session_id,
            "cols": s.cols,
            "rows": s.rows,
            "created_at": s.created_at,
            "last_activity": s.last_activity,
            "alive": s.alive,
        }
        for s in _SESSIONS.values()
    ]


def kill_session(session_id: str) -> bool:
    """Tear down one session and remove it from the registry."""
    sess = _SESSIONS.pop(session_id, None)
    if not sess:
        return False
    try:
        sess.close()
    except Exception:
        pass
    return True


def kill_all() -> int:
    """Force-kill every session. Called from FastAPI shutdown."""
    count = 0
    for sid in list(_SESSIONS.keys()):
        if kill_session(sid):
            count += 1
    return count


# ---------- WebSocket wire helpers (base64 over text frames) ----------
#
# Why base64: xterm sends keystrokes as binary; binary over a text-only
# WebSocket frame trips strict proxies.  Base64 keeps the wire text-only
# and the CPU cost is negligible at shell-keystroke rates.

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=False)
