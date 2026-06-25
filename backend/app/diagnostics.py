"""System diagnostics: detect host environment + tool availability.

Used by:
  GET /api/system/diag           full capability matrix
  GET /api/system/diag/{binary}  one binary's status + install cmd

Concurrency: binaries are probed in parallel via a thread pool.  Each
subprocess is bounded by a 5 s timeout.  Missing binaries return
present=False — never raise.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import ctypes
import os
import platform
import re
import shutil
import subprocess
from typing import Any


SUBPROC_TIMEOUT_S = 5
_WORKERS = 20
_VERSION_LINE_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)*)\b")


# ---------- install command matrix ----------
# Keys are the binary names; values are platform-tagged install commands.
# Tags are tried in dispatch order: windows → windows_choco OR windows_winget,
# darwin → macos_brew, linux → linux_apt OR linux_dnf.

INSTALL_CMDS: dict[str, dict[str, str]] = {
    # ----- core interpreters -----
    "python3": {
        "linux_apt": "sudo apt install -y python3",
        "linux_dnf": "sudo dnf install -y python3",
        "macos_brew": "brew install python@3",
        "windows_choco": "choco install python -y",
        "windows_winget": "winget install Python.Python.3.12",
    },
    "node": {
        "linux_apt": "sudo apt install -y nodejs",
        "linux_dnf": "sudo dnf install -y nodejs",
        "macos_brew": "brew install node",
        "windows_choco": "choco install nodejs -y",
        "windows_winget": "winget install OpenJS.NodeJS.LTS",
    },
    "npm": {
        "linux_apt": "sudo apt install -y npm",
        "macos_brew": "brew install node",
        "windows_choco": "choco install nodejs -y",
        "windows_winget": "winget install OpenJS.NodeJS.LTS",
    },

    # ----- network / port scanners -----
    "nmap": {
        "linux_apt": "sudo apt install -y nmap",
        "linux_dnf": "sudo dnf install -y nmap",
        "macos_brew": "brew install nmap",
        "windows_choco": "choco install nmap -y",
        "windows_winget": "winget install Insecure.Nmap",
    },
    "masscan": {
        "linux_apt": "sudo apt install -y masscan",
        "linux_dnf": "sudo dnf install -y masscan",
        "macos_brew": "brew install masscan",
    },
    "rustscan": {
        "linux_apt": "sudo apt install -y rustscan",
        "macos_brew": "brew install rustscan",
        "windows_choco": "choco install rustscan -y",
    },
    "naabu": {
        "macos_brew": "brew install naabu",
    },
    "nrich": {
        "macos_brew": "brew install nrich",
    },
    "vulners": {
        "linux_apt": "sudo apt install -y vulners",
    },
    "autorecon": {
        "linux_apt": "sudo apt install -y autorecon",
        "macos_brew": "brew install autorecon",
    },

    # ----- web recon / probing -----
    "nuclei": {
        "macos_brew": "brew install nuclei",
    },
    "httpx": {
        "macos_brew": "brew install httpx",
    },
    "katana": {
        "macos_brew": "brew install katana",
    },
    "subfinder": {
        "macos_brew": "brew install subfinder",
    },
    "amass": {
        "linux_apt": "sudo apt install -y amass",
        "macos_brew": "brew install amass",
    },
    "assetfinder": {
        "macos_brew": "brew install assetfinder",
    },
    "dnsx": {
        "macos_brew": "brew install dnsx",
    },
    "massdns": {
        "linux_apt": "sudo apt install -y massdns",
        "macos_brew": "brew install massdns",
    },
    "puredns": {
        "macos_brew": "brew install puredns",
    },
    "shuffledns": {
        "macos_brew": "brew install shuffledns",
    },
    "subjack": {
        "macos_brew": "brew install subjack",
    },
    "waybackurls": {
        "macos_brew": "brew install waybackurls",
    },
    "gau": {
        "macos_brew": "brew install gau",
    },

    # ----- fuzzers / brute force web -----
    "ffuf": {
        "linux_apt": "sudo apt install -y ffuf",
        "macos_brew": "brew install ffuf",
    },
    "gobuster": {
        "linux_apt": "sudo apt install -y gobuster",
        "macos_brew": "brew install gobuster",
    },
    "feroxbuster": {
        "linux_apt": "sudo apt install -y feroxbuster",
        "macos_brew": "brew install feroxbuster",
    },

    # ----- web app vuln scanners -----
    "sqlmap": {
        "linux_apt": "sudo apt install -y sqlmap",
        "macos_brew": "brew install sqlmap",
    },
    "commix": {
        "linux_apt": "sudo apt install -y commix",
        "macos_brew": "brew install commix",
    },
    "dalfox": {
        "macos_brew": "brew install dalfox",
    },
    "xsstrike": {
        "macos_brew": "brew install xsstrike",
    },
    "jwt_tool": {
        "macos_brew": "brew install jwt-tool",
    },
    "smuggler": {
        "macos_brew": "brew install smuggler",
    },
    "nuclei": {  # duplicate key collapsed — see all_binaries()
    },

    # ----- credential / brute force -----
    "hydra": {
        "linux_apt": "sudo apt install -y hydra",
        "linux_dnf": "sudo dnf install -y hydra",
        "macos_brew": "brew install hydra",
        "windows_choco": "choco install hydra -y",
    },
    "patator": {
        "linux_apt": "sudo apt install -y patator",
        "macos_brew": "brew install patator",
    },
    "hashcat": {
        "linux_apt": "sudo apt install -y hashcat",
        "linux_dnf": "sudo dnf install -y hashcat",
        "macos_brew": "brew install hashcat",
        "windows_choco": "choco install hashcat -y",
    },
    "john": {
        "linux_apt": "sudo apt install -y john",
        "linux_dnf": "sudo dnf install -y john",
        "macos_brew": "brew install john",
        "windows_choco": "choco install john -y",
    },

    # ----- AD / Windows -----
    "impacket-secretsdump": {
        "linux_apt": "sudo apt install -y impacket-scripts",
        "macos_brew": "brew install impacket",
    },
    "nxc": {
        "linux_apt": "sudo apt install -y netexec",
        "macos_brew": "brew install netexec",
    },
    "evil-winrm": {
        "linux_apt": "sudo apt install -y evil-winrm",
        "macos_brew": "brew install evil-winrm",
    },
    "kerbrute": {
        "linux_apt": "sudo apt install -y kerbrute",
        "macos_brew": "brew install kerbrute",
    },
    "rubeus": {
    },
    "mimikatz": {
    },
    "bloodhound-python": {
        "linux_apt": "sudo apt install -y bloodhound",
        "macos_brew": "brew install bloodhound",
    },
    "sharphound": {
    },
    "azurehound": {
        "macos_brew": "brew install azurehound",
    },
    "certipy": {
        "linux_apt": "sudo apt install -y certipy",
        "macos_brew": "brew install certipy",
    },
    "petitpotam": {
        "linux_apt": "sudo apt install -y petitpotam",
    },
    "coercer": {
        "linux_apt": "sudo apt install -y coercer",
    },
    "responder": {
        "linux_apt": "sudo apt install -y responder",
        "macos_brew": "brew install responder",
    },
    "roadtools": {
        "linux_apt": "sudo apt install -y roadtools",
        "macos_brew": "brew install roadtools",
    },

    # ----- cloud -----
    "pacu": {
        "linux_apt": "sudo apt install -y pacu",
        "macos_brew": "brew install pacu",
    },
    "principalmapper": {
        "linux_apt": "sudo apt install -y principalmapper",
        "macos_brew": "brew install principalmapper",
    },
    "cloudsplaining": {
        "linux_apt": "sudo apt install -y cloudsplaining",
        "macos_brew": "brew install cloudsplaining",
    },
    "cloudfox": {
        "linux_apt": "sudo apt install -y cloudfox",
        "macos_brew": "brew install cloudfox",
    },
    "o365reopen": {
        "linux_apt": "sudo apt install -y o365reopen",
    },
    "prowler": {
        "linux_apt": "sudo apt install -y prowler",
        "macos_brew": "brew install prowler",
        "windows_choco": "choco install prowler -y",
    },

    # ----- Kubernetes -----
    "kube-hunter": {
        "linux_apt": "sudo apt install -y kube-hunter",
        "macos_brew": "brew install kube-hunter",
    },
    "kubescape": {
        "linux_apt": "sudo apt install -y kubescape",
        "macos_brew": "brew install kubescape",
    },

    # ----- container / image scanning -----
    "trivy": {
        "linux_apt": "sudo apt install -y trivy",
        "macos_brew": "brew install trivy",
        "windows_choco": "choco install trivy -y",
    },
    "grype": {
        "linux_apt": "sudo apt install -y grype",
        "macos_brew": "brew install grype",
        "windows_choco": "choco install grype -y",
    },
    "syft": {
        "linux_apt": "sudo apt install -y syft",
        "macos_brew": "brew install syft",
        "windows_choco": "choco install syft -y",
    },

    # ----- C2 / implant frameworks -----
    "msfconsole": {
        "linux_apt": "sudo apt install -y metasploit-framework",
        "macos_brew": "brew install metasploit",
    },
    "msfvenom": {
        "linux_apt": "sudo apt install -y metasploit-framework",
        "macos_brew": "brew install metasploit",
    },
    "sliver": {
        "linux_apt": "sudo apt install -y sliver",
        "macos_brew": "brew install sliver",
    },
    "havoc": {
        "linux_apt": "sudo apt install -y havoc",
        "macos_brew": "brew install havoc",
    },
    "mythic": {
        "linux_apt": "sudo apt install -y mythic",
    },
    "caldera": {
        "linux_apt": "sudo apt install -y caldera",
    },

    # ----- reverse engineering / mobile -----
    "ghidra": {
        "linux_apt": "sudo apt install -y ghidra",
        "macos_brew": "brew install ghidra",
    },
    "binaryninja": {
        "linux_apt": "sudo apt install -y binaryninja",
        "macos_brew": "brew install binaryninja",
    },
    "jadx": {
        "linux_apt": "sudo apt install -y jadx",
        "macos_brew": "brew install jadx",
    },
    "frida": {
        "linux_apt": "sudo apt install -y frida",
        "macos_brew": "brew install frida",
    },
    "objection": {
        "linux_apt": "sudo apt install -y objection",
        "macos_brew": "brew install objection",
    },
    "radare2": {
        "linux_apt": "sudo apt install -y radare2",
        "linux_dnf": "sudo dnf install -y radare2",
        "macos_brew": "brew install radare2",
    },
    "r2": {
        "linux_apt": "sudo apt install -y radare2",
        "macos_brew": "brew install radare2",
    },
    "cutter": {
        "linux_apt": "sudo apt install -y cutter",
        "macos_brew": "brew install cutter",
    },
    "apktool": {
        "linux_apt": "sudo apt install -y apktool",
        "macos_brew": "brew install apktool",
    },
    "dex2jar": {
        "linux_apt": "sudo apt install -y dex2jar",
        "macos_brew": "brew install dex2jar",
    },
    "jd-gui": {
        "linux_apt": "sudo apt install -y jd-gui",
        "macos_brew": "brew install jd-gui",
    },

    # ----- recon / OSINT -----
    "maltego": {
        "linux_apt": "sudo apt install -y maltego",
        "macos_brew": "brew install --cask maltego",
        "windows_choco": "choco install maltego -y",
    },
    "recon-ng": {
        "linux_apt": "sudo apt install -y recon-ng",
        "macos_brew": "brew install recon-ng",
    },
    "spiderfoot": {
        "linux_apt": "sudo apt install -y spiderfoot",
        "macos_brew": "brew install spiderfoot",
    },
    "theharvester": {
        "linux_apt": "sudo apt install -y theharvester",
        "macos_brew": "brew install theharvester",
    },

    # ----- secrets -----
    "gitleaks": {
        "linux_apt": "sudo apt install -y gitleaks",
        "macos_brew": "brew install gitleaks",
    },
    "trufflehog": {
        "linux_apt": "sudo apt install -y trufflehog",
        "macos_brew": "brew install trufflehog",
    },
    "dnsreaper": {
        "linux_apt": "sudo apt install -y dnsreaper",
        "macos_brew": "brew install dnsreaper",
    },

    # ----- generic CLI / package managers -----
    "jq": {
        "linux_apt": "sudo apt install -y jq",
        "linux_dnf": "sudo dnf install -y jq",
        "macos_brew": "brew install jq",
        "windows_choco": "choco install jq -y",
        "windows_winget": "winget install jqlang.jq",
    },
    "curl": {
        "linux_apt": "sudo apt install -y curl",
        "linux_dnf": "sudo dnf install -y curl",
        "macos_brew": "brew install curl",
        "windows_choco": "choco install curl -y",
    },
    "git": {
        "linux_apt": "sudo apt install -y git",
        "linux_dnf": "sudo dnf install -y git",
        "macos_brew": "brew install git",
        "windows_choco": "choco install git -y",
        "windows_winget": "winget install Git.Git",
    },
    "docker": {
        "linux_apt": "sudo apt install -y docker.io",
        "linux_dnf": "sudo dnf install -y docker",
        "macos_brew": "brew install --cask docker",
        "windows_choco": "choco install docker-desktop -y",
        "windows_winget": "winget install Docker.DockerDesktop",
    },
    "wsl.exe": {
        "windows_choco": "choco install wsl -y",
        "windows_winget": "winget install Microsoft.WSL",
    },
    "choco": {
        "windows_choco": "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))",
        "windows_winget": "winget install Chocolatey.Chocolatey",
    },
    "winget": {
        "windows_choco": "choco install winget -y",
    },
    "brew": {
        "macos_brew": '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
    },
    "apt": {
        "linux_apt": "sudo apt update",
    },
    "dnf": {
        "linux_dnf": "sudo dnf install -y dnf",
    },
}


# Canonical list, ordered for stable JSON output.
def all_binaries() -> list[str]:
    """Return the deduplicated ordered list of binaries we probe."""
    seen: set[str] = set()
    out: list[str] = []
    for name in [
        # core
        "python3", "node", "npm",
        # network / port scanners
        "nmap", "masscan", "naabu", "rustscan", "nrich", "vulners", "autorecon",
        # web recon
        "nuclei", "httpx", "katana", "subfinder", "amass", "assetfinder",
        "dnsx", "massdns", "puredns", "shuffledns", "subjack",
        "waybackurls", "gau",
        # fuzzers
        "ffuf", "gobuster", "feroxbuster",
        # web app vuln
        "sqlmap", "commix", "dalfox", "xsstrike", "jwt_tool", "smuggler",
        # credential / brute
        "hydra", "patator", "hashcat", "john",
        # AD / Windows
        "impacket-secretsdump", "nxc", "evil-winrm", "kerbrute", "rubeus",
        "mimikatz", "bloodhound-python", "sharphound", "azurehound",
        "certipy", "petitpotam", "coercer", "responder", "roadtools",
        # cloud
        "pacu", "principalmapper", "cloudsplaining", "cloudfox",
        "o365reopen", "prowler",
        # k8s
        "kube-hunter", "kubescape",
        # container
        "trivy", "grype", "syft",
        # C2
        "msfconsole", "msfvenom", "sliver", "havoc", "mythic", "caldera",
        # RE / mobile
        "ghidra", "binaryninja", "jadx", "frida", "objection",
        "radare2", "r2", "cutter", "apktool", "dex2jar", "jd-gui",
        # OSINT
        "maltego", "recon-ng", "spiderfoot", "theharvester",
        # secrets
        "gitleaks", "trufflehog", "dnsreaper",
        # generic / pkg mgrs (cross-platform first, then platform-specific)
        "jq", "curl", "git", "docker",
        # platform-specific pkg mgrs
        "wsl.exe", "choco", "winget", "brew", "apt", "dnf",
    ]:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


# ---------- platform / privilege detection ----------

def _wsl_detect() -> bool:
    if platform.system() != "Linux":
        return False
    try:
        with open("/proc/version", "r", encoding="utf-8", errors="replace") as f:
            data = f.read().lower()
        return "microsoft" in data or "wsl" in data
    except Exception:
        return False


def _is_admin() -> bool:
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    # POSIX
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def host_info() -> dict[str, Any]:
    """Snapshot of the host environment."""
    sysname = platform.system()
    return {
        "system": sysname,
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "is_wsl": _wsl_detect(),
        "is_admin": _is_admin(),
        "platform_id": (
            "windows_choco"
            if sysname == "Windows"
            else "macos_brew"
            if sysname == "Darwin"
            else "linux_apt"
        ),
    }


# ---------- install-command dispatch ----------

def install_cmd_for(binary: str) -> str | None:
    """Return the install command for *binary* on the current platform.

    Returns None when no install hint is registered for this platform.
    """
    cmds = INSTALL_CMDS.get(binary)
    if not cmds:
        return None
    sysname = platform.system()
    if sysname == "Windows":
        # Prefer choco (less interactive), fall back to winget.
        return cmds.get("windows_choco") or cmds.get("windows_winget")
    if sysname == "Darwin":
        return cmds.get("macos_brew")
    # linux — apt first, dnf second.
    return cmds.get("linux_apt") or cmds.get("linux_dnf")


# ---------- version parsing ----------

def _parse_version(output: str) -> str | None:
    """Pick the first semver-ish token from `--version` / `-V` output."""
    if not output:
        return None
    for line in output.splitlines():
        if not line.strip():
            continue
        m = _VERSION_LINE_RE.search(line)
        if m:
            return m.group(1)
    return None


def _version_args(binary: str) -> list[str]:
    """Per-binary `--version` flag.  Most tools accept `--version`,
    a handful (notably Go-style binaries) prefer `-version` or `-V`."""
    if binary in ("frida", "objection"):
        return ["--version"]
    return ["--version"]


# ---------- single-binary probe ----------

def _probe(binary: str) -> dict[str, Any]:
    """Synchronous probe: presence + path + version + install cmd."""
    info: dict[str, Any] = {
        "name": binary,
        "present": False,
        "path": None,
        "version": None,
        "install_cmd": install_cmd_for(binary),
    }
    path = shutil.which(binary)
    if not path:
        return info
    info["present"] = True
    info["path"] = path
    try:
        cp = subprocess.run(
            [binary, *_version_args(binary)],
            capture_output=True,
            text=True,
            timeout=SUBPROC_TIMEOUT_S,
        )
        combined = (cp.stdout or "") + "\n" + (cp.stderr or "")
        info["version"] = _parse_version(combined)
    except subprocess.TimeoutExpired:
        info["version"] = None  # ran but slow — keep present=True
    except Exception:
        # binary might be there but refuse to run (e.g. missing .so).
        # Don't crash the whole matrix; we already have presence+path.
        info["version"] = None
    return info


# ---------- sync API ----------

def detect_one(binary: str) -> dict[str, Any] | None:
    """Return the entry for *binary*, or None if not in our registry."""
    if binary not in INSTALL_CMDS and binary not in set(all_binaries()):
        return None
    return _probe(binary)


def detect_all_sync() -> dict[str, Any]:
    """Probe every registered binary in parallel (thread pool).

    Returns a dict shaped:
      {
        "host":  {...host_info()},
        "binaries": {name: {...}, ...},
        "summary": {present: int, total: int}
      }
    """
    bins = all_binaries()
    results: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as ex:
        for name, info in zip(bins, ex.map(_probe, bins)):
            results[name] = info
    present = sum(1 for v in results.values() if v["present"])
    return {
        "host": host_info(),
        "binaries": results,
        "summary": {"present": present, "total": len(results)},
    }


# ---------- async API ----------

async def detect_all() -> dict[str, Any]:
    """Async wrapper around detect_all_sync (for FastAPI async routes)."""
    return await asyncio.to_thread(detect_all_sync)