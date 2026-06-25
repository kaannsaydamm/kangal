"""Onboarding state machine: drives the user from welcome → done.

Used by:
  GET  /api/onboard/state         current step + completed steps + detected caps
  POST /api/onboard/choose-path   {"path": "native"|"wsl"|"skip"}
  POST /api/onboard/consent       {"consent_text": "yes i consent"}
  POST /api/onboard/install       {"binaries": ["nmap", "nuclei", ...]}
  POST /api/onboard/finish        mark onboard complete
  POST /api/onboard/reset         wipe state (testing / re-onboard)

State is in-memory only (per-process dict). Frontend mirrors the same
boolean in localStorage so the gate doesn't flicker across reloads,
but the backend is the source of truth for what step to show next.

Step ordering:
  welcome  → detect (auto) → choose → consent → install → done
"""
from __future__ import annotations

import time
from typing import Any

from . import diagnostics as _diag
from . import installer as _installer


# ---------- constants ----------

VALID_PATHS = {"native", "wsl", "skip"}

# Tools we recommend installing if missing. Order is the order the UI
# will display them in.
RECOMMENDED_BINARIES: list[str] = [
    "nuclei",
    "httpx",
    "nmap",
    "sqlmap",
    "ffuf",
    "impacket-scripts",
]

STEPS: list[str] = ["welcome", "detect", "choose", "consent", "install", "done"]


# ---------- state ----------

_STATE: dict[str, Any] = {
    "path_chosen": None,
    "consent_at": None,
    "install_started": [],     # binary names we've kicked off
    "install_completed": [],   # binary names that finished ok
    "completed": False,
    "created_at": time.time(),
}


# ---------- step computation ----------

def _completed_steps() -> list[str]:
    """Steps the user has cleared, ordered by STEPS."""
    s = _STATE
    done: list[str] = []
    # welcome + detect are auto-completed as soon as we have any state at all
    done.append("welcome")
    done.append("detect")
    if s["path_chosen"]:
        done.append("choose")
    if s["consent_at"]:
        done.append("consent")
    if s["install_started"]:
        done.append("install")
    return done


def current_step() -> str:
    """Next step the UI should render. Returns 'done' when finished."""
    s = _STATE
    if s["completed"]:
        return "done"
    if not s["path_chosen"]:
        return "choose"
    # "skip" path bypasses consent + install — it's the "I just want to look" mode.
    if s["path_chosen"] == "skip":
        return "done"
    if not s["consent_at"]:
        return "consent"
    if not s["install_started"]:
        return "install"
    return "done"


# ---------- diagnostics + recommendations ----------

def _capabilities_summary() -> tuple[dict[str, bool], list[str]]:
    """Probe host once; return (binary → present map, list of missing tools)."""
    try:
        diag = _diag.detect_all_sync()
    except Exception:
        # If diagnostics blow up (e.g. dead `which`), don't fail onboarding —
        # just report everything as unknown.
        return ({b: False for b in RECOMMENDED_BINARIES}, list(RECOMMENDED_BINARIES))
    bins: dict[str, Any] = diag.get("binaries") or {}
    summary: dict[str, bool] = {}
    for name in RECOMMENDED_BINARIES:
        info = bins.get(name) or {}
        summary[name] = bool(info.get("present"))
    recommendations = [name for name in RECOMMENDED_BINARIES if not summary.get(name)]
    return summary, recommendations


def _detected_block() -> dict[str, Any]:
    """The 'detected' sub-block returned by GET /api/onboard/state."""
    try:
        diag = _diag.detect_all_sync()
        host = diag.get("host") or {}
        caps, recs = _capabilities_summary()
        return {
            "platform": host.get("system"),
            "is_wsl": bool(host.get("is_wsl")),
            "is_admin": bool(host.get("is_admin")),
            "capabilities_summary": caps,
            "recommendations": recs,
        }
    except Exception:
        return {
            "platform": None,
            "is_wsl": False,
            "is_admin": False,
            "capabilities_summary": {},
            "recommendations": list(RECOMMENDED_BINARIES),
        }


# ---------- public state snapshot ----------

def snapshot() -> dict[str, Any]:
    """Return the full state object the frontend expects."""
    s = _STATE
    return {
        "current_step": current_step(),
        "completed_steps": _completed_steps(),
        "path_chosen": s["path_chosen"],
        "consent_at": s["consent_at"],
        "install_started": list(s["install_started"]),
        "install_completed": list(s["install_completed"]),
        "completed": bool(s["completed"]),
        "created_at": s["created_at"],
        "detected": _detected_block(),
    }


# ---------- mutators ----------

def choose_path(path: str) -> dict[str, Any]:
    """Validate + record the user's chosen install path."""
    if path not in VALID_PATHS:
        raise ValueError(
            f"path must be one of {sorted(VALID_PATHS)}, got {path!r}"
        )
    _STATE["path_chosen"] = path
    # skip short-circuits to done — auto-finish if user picked skip.
    if path == "skip":
        _STATE["completed"] = True
    return snapshot()


def record_consent(consent_text: str) -> dict[str, Any]:
    """Validate the consent string then stamp an ISO timestamp.

    Validation: lowered string must contain BOTH 'yes' and 'consent'.
    Raises ValueError with a user-facing message on failure.
    """
    text = (consent_text or "").lower()
    if "yes" not in text or "consent" not in text:
        raise ValueError("consent must include 'yes' and 'consent'")
    from datetime import datetime, timezone

    _STATE["consent_at"] = datetime.now(timezone.utc).isoformat()
    return snapshot()


def start_installs(binaries: list[str]) -> dict[str, Any]:
    """Kick off an install for each binary. Returns one entry per request."""
    out: list[dict[str, Any]] = []
    for binary in binaries or []:
        cmd = _installer.install_command_for(binary)
        if not cmd:
            out.append(
                {
                    "binary": binary,
                    "install_id": None,
                    "status": "skipped",
                    "reason": "no install command for this platform",
                }
            )
            continue
        # Refuse sudo without root just like the public install endpoint —
        # we never want onboarding to silently run privileged commands.
        if _installer.needs_root(cmd) and not _installer.is_admin():
            out.append(
                {
                    "binary": binary,
                    "install_id": None,
                    "status": "skipped",
                    "reason": "install requires root/admin; re-run backend as root",
                }
            )
            continue
        job = _installer.start_install(binary)
        if not job:
            out.append(
                {
                    "binary": binary,
                    "install_id": None,
                    "status": "skipped",
                    "reason": "no install command for this platform",
                }
            )
            continue
        _STATE["install_started"].append(binary)
        out.append(
            {
                "binary": binary,
                "install_id": job.install_id,
                "status": "started",
                "command": list(job.command),
                "command_str": " ".join(job.command),
            }
        )
    return {"installs": out, "state": snapshot()}


def finish() -> dict[str, Any]:
    """Mark onboard complete (mirrors localStorage flag on the backend)."""
    _STATE["completed"] = True
    return snapshot()


def reset() -> dict[str, Any]:
    """Wipe state — useful for testing and re-onboarding."""
    _STATE["path_chosen"] = None
    _STATE["consent_at"] = None
    _STATE["install_started"] = []
    _STATE["install_completed"] = []
    _STATE["completed"] = False
    _STATE["created_at"] = time.time()
    return snapshot()


def mark_install_completed(binary: str) -> None:
    """Called by background install watcher (or tests) to record success."""
    if binary and binary not in _STATE["install_completed"]:
        _STATE["install_completed"].append(binary)