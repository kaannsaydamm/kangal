"""Background installer: run platform-appropriate install commands.

Used by:
  POST /api/system/install/{binary_name}   start a background install
  GET  /api/system/install/{install_id}/status   poll install state
  WS   /ws/install/{install_id}                  stream log lines + final frame

Each install:
  - gets a UUID v4 install_id
  - runs in a daemon thread (Popen, shell=False, args list — never a string)
  - streams stdout+stderr into a deque(maxlen=200)
  - completes with exit_code, duration_s, status in {ok, failed}
  - is subject to a default 600 s timeout (per-binary override possible)
  - shares a semaphore that caps concurrency at MAX_CONCURRENT_INSTALLS

A binary whose install command contains "sudo" is refused with 403 unless
the host is_admin (so we never silently run privileged commands).
"""
from __future__ import annotations

import platform
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any


# ---------- constants ----------

MAX_CONCURRENT_INSTALLS = 2
DEFAULT_TIMEOUT_S = 600
LOG_MAX_LINES = 200


# ---------- install command matrix ----------
# Each binary maps to platform-tagged install commands. Dispatch order
# matches diagnostics.py:
#   Windows  -> windows_choco, then windows_winget
#   Darwin   -> macos_brew
#   Linux    -> linux_apt, then linux_dnf
# New keys (pip / go / git) are used for tools that aren't packaged and
# must be installed via language toolchains or source clone. They bypass
# the OS-package dispatch (caller checks the key first).

INSTALL_CMDS: dict[str, dict[str, list[str]]] = {
    # ----- network / port scanners -----
    "nmap": {
        "linux_apt": ["sudo", "apt", "install", "-y", "nmap"],
        "linux_dnf": ["sudo", "dnf", "install", "-y", "nmap"],
        "macos_brew": ["brew", "install", "nmap"],
        "windows_choco": ["choco", "install", "nmap", "-y"],
        "windows_winget": ["winget", "install", "-e", "--id", "Insecure.Nmap"],
    },
    "masscan": {
        "linux_apt": ["sudo", "apt", "install", "-y", "masscan"],
        "linux_dnf": ["sudo", "dnf", "install", "-y", "masscan"],
        "macos_brew": ["brew", "install", "masscan"],
    },
    "rustscan": {
        "linux_apt": ["sudo", "apt", "install", "-y", "rustscan"],
        "macos_brew": ["brew", "install", "rustscan"],
        "windows_choco": ["choco", "install", "rustscan", "-y"],
    },
    "naabu": {
        "go": ["go", "install", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"],
    },

    # ----- web recon / probing -----
    "nuclei": {
        "go": ["go", "install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
        "macos_brew": ["brew", "install", "nuclei"],
        "linux_apt": ["sudo", "apt", "install", "-y", "nuclei"],
    },
    "httpx": {
        "go": ["go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
        "macos_brew": ["brew", "install", "httpx"],
        "linux_apt": ["sudo", "apt", "install", "-y", "httpx"],
    },
    "katana": {
        "go": ["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"],
        "macos_brew": ["brew", "install", "katana"],
    },
    "subfinder": {
        "go": ["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
        "macos_brew": ["brew", "install", "subfinder"],
        "linux_apt": ["sudo", "apt", "install", "-y", "subfinder"],
    },
    "amass": {
        "linux_apt": ["sudo", "apt", "install", "-y", "amass"],
        "macos_brew": ["brew", "install", "amass"],
    },
    "assetfinder": {
        "go": ["go", "install", "github.com/tomnomnom/assetfinder@latest"],
        "macos_brew": ["brew", "install", "assetfinder"],
    },
    "dnsx": {
        "go": ["go", "install", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"],
        "macos_brew": ["brew", "install", "dnsx"],
        "linux_apt": ["sudo", "apt", "install", "-y", "dnsx"],
    },

    # ----- fuzzers / brute force web -----
    "ffuf": {
        "go": ["go", "install", "github.com/ffuf/ffuf/v2@latest"],
        "linux_apt": ["sudo", "apt", "install", "-y", "ffuf"],
        "macos_brew": ["brew", "install", "ffuf"],
    },
    "gobuster": {
        "linux_apt": ["sudo", "apt", "install", "-y", "gobuster"],
        "macos_brew": ["brew", "install", "gobuster"],
    },

    # ----- web app vuln scanners -----
    "sqlmap": {
        "linux_apt": ["sudo", "apt", "install", "-y", "sqlmap"],
        "macos_brew": ["brew", "install", "sqlmap"],
    },

    # ----- credential / brute force -----
    "hydra": {
        "linux_apt": ["sudo", "apt", "install", "-y", "hydra"],
        "linux_dnf": ["sudo", "dnf", "install", "-y", "hydra"],
        "macos_brew": ["brew", "install", "hydra"],
        "windows_choco": ["choco", "install", "hydra", "-y"],
    },
    "hashcat": {
        "linux_apt": ["sudo", "apt", "install", "-y", "hashcat"],
        "linux_dnf": ["sudo", "dnf", "install", "-y", "hashcat"],
        "macos_brew": ["brew", "install", "hashcat"],
        "windows_choco": ["choco", "install", "hashcat", "-y"],
    },
    "john": {
        "linux_apt": ["sudo", "apt", "install", "-y", "john"],
        "linux_dnf": ["sudo", "dnf", "install", "-y", "john"],
        "macos_brew": ["brew", "install", "john"],
        "windows_choco": ["choco", "install", "john", "-y"],
    },
    "patator": {
        "linux_apt": ["sudo", "apt", "install", "-y", "patator"],
        "macos_brew": ["brew", "install", "patator"],
    },

    # ----- AD / Windows (Python pip) -----
    "impacket-scripts": {
        "linux_apt": ["sudo", "apt", "install", "-y", "impacket-scripts"],
        "macos_brew": ["brew", "install", "impacket"],
        "pip": ["pip", "install", "--break-system-packages", "impacket"],
    },
    "nxc": {
        "linux_apt": ["sudo", "apt", "install", "-y", "netexec"],
        "macos_brew": ["brew", "install", "netexec"],
        "pip": ["pip", "install", "--break-system-packages", "netexec"],
    },
    "evil-winrm": {
        "linux_apt": ["sudo", "apt", "install", "-y", "evil-winrm"],
        "macos_brew": ["brew", "install", "evil-winrm"],
        "pip": ["pip", "install", "--break-system-packages", "evil-winrm"],
    },
    "kerbrute": {
        "linux_apt": ["sudo", "apt", "install", "-y", "kerbrute"],
        "macos_brew": ["brew", "install", "kerbrute"],
    },
    "bloodhound-python": {
        "linux_apt": ["sudo", "apt", "install", "-y", "bloodhound"],
        "macos_brew": ["brew", "install", "bloodhound"],
        "pip": ["pip", "install", "--break-system-packages", "bloodhound"],
    },
    "certipy": {
        "linux_apt": ["sudo", "apt", "install", "-y", "certipy"],
        "macos_brew": ["brew", "install", "certipy"],
        "pip": ["pip", "install", "--break-system-packages", "certipy-ad"],
    },
    "responder": {
        "linux_apt": ["sudo", "apt", "install", "-y", "responder"],
        "macos_brew": ["brew", "install", "responder"],
        "git": ["git", "clone", "https://github.com/lgandx/Responder.git", "/opt/Responder"],
    },
    "roadtools": {
        "linux_apt": ["sudo", "apt", "install", "-y", "roadtools"],
        "macos_brew": ["brew", "install", "roadtools"],
        "pip": ["pip", "install", "--break-system-packages", "roadtools"],
    },

    # ----- exploitation frameworks -----
    "msfconsole": {
        "linux_apt": ["sudo", "apt", "install", "-y", "metasploit-framework"],
        "macos_brew": ["brew", "install", "metasploit"],
    },

    # ----- RE / mobile (git clone to /opt) -----
    "ghidra": {
        "git": ["git", "clone", "https://github.com/NationalSecurityAgency/ghidra.git", "/opt/ghidra"],
        "linux_apt": ["sudo", "apt", "install", "-y", "ghidra"],
        "macos_brew": ["brew", "install", "ghidra"],
    },
    "sliver": {
        "git": ["git", "clone", "https://github.com/BishopFox/sliver.git", "/opt/sliver"],
        "linux_apt": ["sudo", "apt", "install", "-y", "sliver"],
        "macos_brew": ["brew", "install", "sliver"],
    },
    "jadx": {
        "linux_apt": ["sudo", "apt", "install", "-y", "jadx"],
        "macos_brew": ["brew", "install", "jadx"],
    },
    "frida": {
        "pip": ["pip", "install", "--break-system-packages", "frida-tools"],
        "linux_apt": ["sudo", "apt", "install", "-y", "frida"],
        "macos_brew": ["brew", "install", "frida"],
    },
    "objection": {
        "pip": ["pip", "install", "--break-system-packages", "objection"],
        "linux_apt": ["sudo", "apt", "install", "-y", "objection"],
        "macos_brew": ["brew", "install", "objection"],
    },
    "radare2": {
        "linux_apt": ["sudo", "apt", "install", "-y", "radare2"],
        "linux_dnf": ["sudo", "dnf", "install", "-y", "radare2"],
        "macos_brew": ["brew", "install", "radare2"],
    },
    "apktool": {
        "linux_apt": ["sudo", "apt", "install", "-y", "apktool"],
        "macos_brew": ["brew", "install", "apktool"],
    },

    # ----- cloud / k8s / container -----
    "maltego": {
        "linux_apt": ["sudo", "apt", "install", "-y", "maltego"],
        "macos_brew": ["brew", "install", "--cask", "maltego"],
        "windows_choco": ["choco", "install", "maltego", "-y"],
    },
    "prowler": {
        "linux_apt": ["sudo", "apt", "install", "-y", "prowler"],
        "macos_brew": ["brew", "install", "prowler"],
        "pip": ["pip", "install", "--break-system-packages", "prowler"],
    },
    "kube-hunter": {
        "linux_apt": ["sudo", "apt", "install", "-y", "kube-hunter"],
        "macos_brew": ["brew", "install", "kube-hunter"],
        "pip": ["pip", "install", "--break-system-packages", "kube-hunter"],
    },
    "trivy": {
        "linux_apt": ["sudo", "apt", "install", "-y", "trivy"],
        "macos_brew": ["brew", "install", "trivy"],
        "windows_choco": ["choco", "install", "trivy", "-y"],
    },
    "grype": {
        "linux_apt": ["sudo", "apt", "install", "-y", "grype"],
        "macos_brew": ["brew", "install", "grype"],
        "windows_choco": ["choco", "install", "grype", "-y"],
    },
    "syft": {
        "linux_apt": ["sudo", "apt", "install", "-y", "syft"],
        "macos_brew": ["brew", "install", "syft"],
        "windows_choco": ["choco", "install", "syft", "-y"],
    },
    "pacu": {
        "linux_apt": ["sudo", "apt", "install", "-y", "pacu"],
        "macos_brew": ["brew", "install", "pacu"],
        "pip": ["pip", "install", "--break-system-packages", "pacu"],
    },
    "caldera": {
        "git": ["git", "clone", "https://github.com/mitre/caldera.git", "/opt/caldera"],
        "linux_apt": ["sudo", "apt", "install", "-y", "caldera"],
    },
}


# ---------- dispatch ----------

def install_command_for(binary: str) -> list[str] | None:
    """Return the right install command for current platform, or None if not installable."""
    cmds = INSTALL_CMDS.get(binary, {})
    if not cmds:
        return None
    if platform.system() == "Windows":
        c = cmds.get("windows_choco") or cmds.get("windows_winget")
    elif platform.system() == "Darwin":
        c = cmds.get("macos_brew")
    else:  # Linux
        c = cmds.get("linux_apt") or cmds.get("linux_dnf")
    if not c:
        return None
    return list(c)


def is_admin() -> bool:
    """True if the current process has admin/root privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        import os

        return os.geteuid() == 0
    except Exception:
        return False


def needs_root(cmd: list[str]) -> bool:
    """True if the command asks for privilege escalation (sudo / runas)."""
    if not cmd:
        return False
    head = cmd[0].lower()
    return head in ("sudo", "runas", "doas")


# ---------- job model ----------

@dataclass
class InstallJob:
    install_id: str
    binary: str
    command: list[str]
    timeout_s: int
    status: str = "running"  # running | ok | failed
    exit_code: int | None = None
    log: deque = field(default_factory=lambda: deque(maxlen=LOG_MAX_LINES))
    new_lines: deque = field(default_factory=deque)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    error: str | None = None

    def summary(self) -> dict[str, Any]:
        duration = None
        if self.finished_at is not None:
            duration = round(self.finished_at - self.started_at, 3)
        else:
            duration = round(time.time() - self.started_at, 3)
        return {
            "install_id": self.install_id,
            "binary": self.binary,
            "command": self.command,
            "command_str": " ".join(self.command),
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_s": duration,
            "log": list(self.log),
            "error": self.error,
        }


# ---------- registry + semaphore ----------

_INSTALL_JOBS: dict[str, InstallJob] = {}
_INSTALL_LOCK = threading.Lock()
_INSTALL_SEM = threading.BoundedSemaphore(MAX_CONCURRENT_INSTALLS)


def get_job(install_id: str) -> InstallJob | None:
    with _INSTALL_LOCK:
        return _INSTALL_JOBS.get(install_id)


def list_jobs() -> list[dict[str, Any]]:
    with _INSTALL_LOCK:
        return [j.summary() for j in _INSTALL_JOBS.values()]


# ---------- runner ----------

def _run_job(job: InstallJob) -> None:
    """Thread body: spawn the subprocess, stream lines into the deque."""
    job.log.append(f"[installer] running: {' '.join(job.command)}")
    try:
        proc = subprocess.Popen(
            job.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as e:
        job.log.append(f"[installer] failed to launch: {e}")
        job.status = "failed"
        job.error = f"executable not found: {job.command[0]}"
        job.finished_at = time.time()
        return
    except Exception as e:
        job.log.append(f"[installer] launch error: {e}")
        job.status = "failed"
        job.error = str(e)
        job.finished_at = time.time()
        return

    assert proc.stdout is not None
    try:
        deadline = time.time() + job.timeout_s
        for line in proc.stdout:
            job.log.append(line.rstrip("\n"))
            job.new_lines.append(line.rstrip("\n"))
            if time.time() > deadline:
                job.log.append(f"[installer] timeout after {job.timeout_s}s — killing")
                try:
                    proc.kill()
                except Exception:
                    pass
                break
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
        rc = proc.returncode
        job.exit_code = rc
        job.status = "ok" if rc == 0 else "failed"
        if rc != 0:
            job.error = f"non-zero exit code: {rc}"
    except Exception as e:
        job.log.append(f"[installer] runner error: {e}")
        job.status = "failed"
        job.error = str(e)
    finally:
        job.finished_at = time.time()


def _thread_wrapper(job: InstallJob) -> None:
    """Acquire the concurrency semaphore around the actual run."""
    try:
        _run_job(job)
    finally:
        try:
            _INSTALL_SEM.release()
        except ValueError:
            pass


# ---------- public entrypoint ----------

def start_install(binary: str, timeout_s: int | None = None) -> InstallJob | None:
    """Start an install in a background thread. Returns None if unknown.

    The caller is responsible for refusing sudo commands when not admin —
    see ``installer.refuse_if_privileged`` for the helper.
    """
    cmd = install_command_for(binary)
    if not cmd:
        return None
    job = InstallJob(
        install_id=str(uuid.uuid4()),
        binary=binary,
        command=cmd,
        timeout_s=timeout_s or DEFAULT_TIMEOUT_S,
    )
    with _INSTALL_LOCK:
        _INSTALL_JOBS[job.install_id] = job
    # Non-blocking acquire — if the cap is hit, refuse immediately.
    if not _INSTALL_SEM.acquire(blocking=False):
        job.status = "failed"
        job.error = (
            f"install concurrency limit reached "
            f"({MAX_CONCURRENT_INSTALLS} simultaneous installs)"
        )
        job.finished_at = time.time()
        return job
    t = threading.Thread(
        target=_thread_wrapper, args=(job,), daemon=True, name=f"install-{binary}-{job.install_id[:8]}"
    )
    t.start()
    return job
