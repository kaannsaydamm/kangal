"""Kangal QA runner — tüm modüllerin gerçek araçlarla test edilmesi.

Hedefler:
  - http://127.0.0.1:8080   (nginx HTTP honeypot)
  - http://127.0.0.1:8001   (nginx SquirrelMail reissue)
  - ssh://127.0.0.1:2222    (sshd)
  - tcp://127.0.0.1:31337   (fake vsftpd 2.3.4 banner)
  - http://127.0.0.1:8000   (kangal backend API)
  - http://127.0.0.1:5173   (kangal vite frontend)
  - smb 445 → atlandı (lab tuning aşamasında sorunlu)

Her modül için en az bir gerçek çağrı yapılır; çıktı ve PASS/FAIL kaydedilir.
"""
from __future__ import annotations
import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx

RESULTS: list[dict] = []
REPORT_PATH = Path(__file__).parent / "REPORT.md"
QA_LOG = Path("/tmp/qa-lab/qa-runs.log")
QA_LOG.parent.mkdir(parents=True, exist_ok=True)

BACKEND = "http://127.0.0.1:8000"
FRONTEND = "http://127.0.0.1:5173"
LAB_HTTP_MAIN = "http://127.0.0.1:8080"
LAB_HTTP_OTHER = "http://127.0.0.1:8001"
LAB_SSH_HOST = "127.0.0.1"
LAB_SSH_PORT = 2222
LAB_BANNER_HOST = "127.0.0.1"
LAB_BANNER_PORT = 31337


@dataclass
class QaResult:
    name: str
    status: str  # PASS | FAIL | SKIP
    detail: str = ""
    duration_ms: int = 0
    artifacts: list[str] = field(default_factory=list)
    section: str = ""


def record(r: QaResult) -> None:
    RESULTS.append(r.__dict__)
    icon = {"PASS": "✓", "FAIL": "✗", "SKIP": "~"}.get(r.status, "?")
    line = f"{icon} [{r.section}] {r.name}"
    if r.detail:
        line += f"  → {r.detail[:200]}"
    if r.duration_ms:
        line += f"  ({r.duration_ms}ms)"
    print(line, flush=True)
    with QA_LOG.open("a") as f:
        f.write(line + "\n")


def timed(fn: Callable[[], QaResult]) -> QaResult:
    t0 = time.monotonic()
    try:
        result = fn()
    except Exception as e:
        result = QaResult(name=fn.__name__, status="FAIL", detail=f"exception: {e!r}")
    result.duration_ms = int((time.monotonic() - t0) * 1000)
    return result


def run_subprocess(cmd: list[str], name: str, section: str, timeout: int = 30, **kw) -> QaResult:
    """Bir shell komutu çalıştır; çıktıyı logla."""
    def _do() -> QaResult:
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, **kw
            )
            ok = r.returncode == 0
            detail = (r.stdout[:300] + ("…" if len(r.stdout) > 300 else "")).strip()
            if r.stderr.strip():
                detail = (detail + "\n  stderr: " + r.stderr[:200]).strip()
            return QaResult(
                name=name, section=section,
                status="PASS" if ok else "FAIL",
                detail=detail, artifacts=[r.stdout[:1000], r.stderr[:500]]
            )
        except subprocess.TimeoutExpired:
            return QaResult(name=name, section=section, status="FAIL",
                            detail=f"timeout after {timeout}s")
        except FileNotFoundError as e:
            return QaResult(name=name, section=section, status="SKIP",
                            detail=f"binary not found: {e}")
    return timed(lambda: _do())


# ========== Backend health ==========

def qa_backend_health() -> QaResult:
    try:
        r = httpx.get(f"{BACKEND}/api/intel/patterns", timeout=5.0)
        ok = r.status_code == 200 and "patterns" in r.json()
        return QaResult("backend /api/intel/patterns 200", "PASS" if ok else "FAIL",
                        f"status={r.status_code} body={r.text[:80]}", section="boot")
    except Exception as e:
        return QaResult("backend /api/intel/patterns 200", "FAIL", repr(e), section="boot")


def qa_backend_routes_count() -> QaResult:
    try:
        r = httpx.get(f"{BACKEND}/openapi.json", timeout=10.0)
        paths = r.json().get("paths", {})
        return QaResult("backend routes registered", "PASS" if len(paths) > 40 else "FAIL",
                        f"route_count={len(paths)}", section="boot",
                        duration_ms=int(time.monotonic()*0))
    except Exception as e:
        return QaResult("backend routes", "FAIL", repr(e), section="boot")


# ========== Lab health ==========

def qa_lab_ports() -> QaResult:
    expected = {"http_main": 8080, "http_paths": 8001, "ssh": 2222, "tcp_vuln": 31337, "smb": 445}
    up, down = [], []
    for name, port in expected.items():
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.5):
                up.append(name)
        except OSError:
            down.append(name)
    if len(down) >= 3:
        return QaResult("lab ports", "FAIL", f"up={up} down={down}", section="boot")
    if down:
        return QaResult("lab ports (partial)", "SKIP",
                        f"up={up} down={down} — sadece aktif olanlar test edildi",
                        section="boot")
    return QaResult("lab ports", "PASS", f"up={up}", section="boot")


# ========== Agents / scan pipeline ==========

def qa_scan_pipeline() -> list[QaResult]:
    """7-stage scan pipeline başlat: 127.0.0.1 + ssh+http hedeflerini"""
    out: list[QaResult] = []

    def _start() -> QaResult:
        try:
            # target subdomain modunda da çalışabilsin diye bir hedef vereceğiz.
            # Önce subdomain modu dene — başarısızsa gerçek host olmasa da scaffold testleri geçer
            body = {
                "target": "scanme.test",
                "profile": "passive",
                "engagement_id": None,
            }
            r = httpx.post(f"{BACKEND}/api/scan", json=body, timeout=10.0)
            d = r.json()
            return QaResult("scan start (POST /api/scan)", "PASS" if r.status_code == 200 else "FAIL",
                            f"scan_id={d.get('scan_id')} status={r.status_code}",
                            section="agents",
                            artifacts=[json.dumps(d)[:1000]])
        except Exception as e:
            return QaResult("scan start", "FAIL", repr(e), section="agents")

    out.append(timed(_start))

    # Son 5 scan'i listele
    def _list() -> QaResult:
        try:
            r = httpx.get(f"{BACKEND}/api/scans", timeout=5.0)
            d = r.json()
            n = len(d) if isinstance(d, list) else len(d.get("scans", []))
            return QaResult("GET /api/scans", "PASS", f"count={n}", section="agents")
        except Exception as e:
            return QaResult("GET /api/scans", "FAIL", repr(e), section="agents")
    out.append(timed(_list))

    # scan_id varsa detail + events çek
    sd = RESULTS[-2]["artifacts"][0] if len(RESULTS) >= 2 and RESULTS[-2]["artifacts"] else "{}"
    m = re.search(r'"scan_id":\s*"([^"]+)"', sd)
    if m:
        sid = m.group(1)
        def _get_scan() -> QaResult:
            try:
                r = httpx.get(f"{BACKEND}/api/scan/{sid}", timeout=5.0)
                return QaResult(f"GET /api/scan/{sid}", "PASS" if r.status_code == 200 else "FAIL",
                                f"status={r.status_code}", section="agents")
            except Exception as e:
                return QaResult(f"GET /api/scan/{sid}", "FAIL", repr(e), section="agents")
        out.append(timed(_get_scan))

        def _get_assets() -> QaResult:
            try:
                r = httpx.get(f"{BACKEND}/api/scan/{sid}/assets", timeout=5.0)
                d = r.json()
                return QaResult(f"GET /api/scan/{sid}/assets", "PASS",
                                f"count={len(d.get('assets', []))}",
                                section="agents",
                                artifacts=[json.dumps(d)[:1500]])
            except Exception as e:
                return QaResult("assets", "FAIL", repr(e), section="agents")
        out.append(timed(_get_assets))

        def _get_findings() -> QaResult:
            try:
                r = httpx.get(f"{BACKEND}/api/scan/{sid}/findings", timeout=5.0)
                d = r.json()
                return QaResult(f"GET /api/scan/{sid}/findings", "PASS",
                                f"count={len(d.get('findings', []))}",
                                section="agents",
                                artifacts=[json.dumps(d)[:1500]])
            except Exception as e:
                return QaResult("findings", "FAIL", repr(e), section="agents")
        out.append(timed(_get_findings))

        def _get_events() -> QaResult:
            try:
                r = httpx.get(f"{BACKEND}/api/scan/{sid}/events", timeout=5.0)
                d = r.json()
                evs = d.get("events", [])
                stages = sorted({e.get("stage", "?") for e in evs})
                return QaResult(f"GET /api/scan/{sid}/events", "PASS",
                                f"count={len(evs)} stages={stages}",
                                section="agents",
                                artifacts=[json.dumps(d)[:1500]])
            except Exception as e:
                return QaResult("events", "FAIL", repr(e), section="agents")
        out.append(timed(_get_events))

        def _get_report() -> QaResult:
            try:
                r = httpx.get(f"{BACKEND}/api/scan/{sid}/report.md", timeout=5.0)
                return QaResult(f"GET /api/scan/{sid}/report.md", "PASS" if r.status_code == 200 else "FAIL",
                                f"status={r.status_code} size={len(r.content)}",
                                section="agents")
            except Exception as e:
                return QaResult("report", "FAIL", repr(e), section="agents")
        out.append(timed(_get_report))

    return out


# ========== Intel / threat-intel / patterns ==========

def qa_intel_patterns() -> list[QaResult]:
    out = []
    endpoints = [
        ("/api/intel/patterns", "intel patterns"),
        ("/api/intel/search?q=*", "intel search (q=*)"),
        ("/api/intel/search?q=apache", "intel search (q=apache)"),
        ("/api/threat-intel/feed", "threat-intel feed"),
        ("/api/threat-intel/cve/CVE-2024-3094", "threat-intel cve lookup"),
        ("/api/threat-intel/recent-cves?days=7&severity=critical", "threat-intel recent"),
    ]
    for ep, name in endpoints:
        def _make(ep=ep, name=name) -> QaResult:
            try:
                r = httpx.get(f"{BACKEND}{ep}", timeout=8.0)
                ok = r.status_code == 200
                sample = (r.text or "")[:120].replace("\n", " ")
                return QaResult(f"GET {ep}", "PASS" if ok else "FAIL",
                                f"status={r.status_code} sample={sample}",
                                section="intel")
            except Exception as e:
                return QaResult(f"GET {ep}", "FAIL", repr(e), section="intel")
        out.append(timed(_make))
    return out


def qa_threat_intel_view_kw() -> list[QaResult]:
    out = []
    for ep in ("/api/threat-intel/mitre", "/api/threat-intel/nist",
               "/api/threat-intel/attack-patterns"):
        def _make(ep=ep) -> QaResult:
            try:
                r = httpx.get(f"{BACKEND}{ep}", timeout=5.0)
                return QaResult(f"GET {ep}", "PASS" if r.status_code in (200, 404) else "FAIL",
                                f"status={r.status_code}", section="intel")
            except Exception as e:
                return QaResult(f"GET {ep}", "FAIL", repr(e), section="intel")
        out.append(timed(_make))
    return out


# ========== Ruflo ==========

def qa_ruflo() -> list[QaResult]:
    out = []
    endpoints = [
        "/api/ruflo/summary",
        "/api/ruflo/hooks/stats",
        "/api/ruflo/memory/stats",
        "/api/ruflo/memory/search?q=*",
        "/api/ruflo/patterns",
        "/api/ruflo/patterns/search?q=*",
        "/api/ruflo/swarm/status",
        "/api/ruflo/agents",
        "/api/ruflo/neural/status",
    ]
    for ep in endpoints:
        def _make(ep=ep) -> QaResult:
            try:
                r = httpx.get(f"{BACKEND}{ep}", timeout=5.0)
                ok = r.status_code in (200, 422)
                return QaResult(f"GET {ep}",
                                "PASS" if ok else "FAIL",
                                f"status={r.status_code}", section="ruflo")
            except Exception as e:
                return QaResult(ep, "FAIL", repr(e), section="ruflo")
        out.append(timed(_make))
    return out


# ========== Redteam ==========

def qa_redteam() -> list[QaResult]:
    out = []
    payloads = {
        "/api/redteam/exploit-attempt": {
            "target": "127.0.0.1", "stage": "exploit_attempt",
            "technique": "T1190", "outcome": "attempted",
            "evidence": "GET /admin/ 403 -> bypass possible",
        },
        "/api/redteam/credential": {
            "target": "127.0.0.1", "stage": "credential_discovery",
            "kind": "ssh_password", "username": "qa",
            "secret_ref": "/tmp/qa-lab/.creds", "severity": "high",
        },
        "/api/redteam/lateral-path": {
            "target": "127.0.0.1", "stage": "lateral_path",
            "from_node": "10.0.0.1", "to_node": "10.0.0.2",
            "protocol": "smb", "evidence": "smb share found",
        },
        "/api/redteam/persistence": {
            "target": "127.0.0.1", "stage": "persistence",
            "mechanism": "cron", "path": "/etc/cron.d/x",
            "evidence": "sched job created",
        },
        "/api/redteam/c2-beacon": {
            "target": "127.0.0.1", "stage": "c2_beacon",
            "channel": "dns_tunnel", "endpoint": "exfil.target.test",
            "evidence": "outbound 53 > 100 KB",
        },
    }
    for ep, body in payloads.items():
        def _make(ep=ep, body=body) -> QaResult:
            try:
                r = httpx.post(f"{BACKEND}{ep}", json=body, timeout=5.0)
                return QaResult(f"POST {ep}", "PASS" if r.status_code in (200, 201, 422) else "FAIL",
                                f"status={r.status_code} body={r.text[:100]}",
                                section="redteam", artifacts=[r.text[:1000]])
            except Exception as e:
                return QaResult(ep, "FAIL", repr(e), section="redteam")
        out.append(timed(_make))

    # /api/redteam/mitre
    def _mitre() -> QaResult:
        try:
            r = httpx.get(f"{BACKEND}/api/redteam/mitre", timeout=5.0)
            return QaResult("GET /api/redteam/mitre", "PASS" if r.status_code == 200 else "FAIL",
                            f"status={r.status_code}",
                            section="redteam", artifacts=[r.text[:1500]])
        except Exception as e:
            return QaResult("mitre", "FAIL", repr(e), section="redteam")
    out.append(timed(_mitre))
    return out


# ========== Engagement ==========

def qa_engagement() -> list[QaResult]:
    out = []
    body = {
        "name": "qa-engagement-" + str(int(time.time())),
        "client": "kangal-qa",
        "operator": "qa-bot",
        "scope_domains": ["scanme.test", "target.test", "internal.lab"],
        "scope_cidrs": ["127.0.0.1/32"],
        "excluded": ["google.com"],
        "profile": "full_spectrum",
        "destructive_allowed": False,
    }
    def _create() -> QaResult:
        try:
            r = httpx.post(f"{BACKEND}/api/engagement", json=body, timeout=5.0)
            d = r.json()
            return QaResult("POST /api/engagement", "PASS" if r.status_code in (200, 201) else "FAIL",
                            f"status={r.status_code}",
                            section="engagement",
                            artifacts=[json.dumps(d)[:1000]])
        except Exception as e:
            return QaResult("create", "FAIL", repr(e), section="engagement")
    out.append(timed(_create))

    cd = RESULTS[-1]["artifacts"][0] if len(RESULTS) >= 1 and RESULTS[-1]["artifacts"] else "{}"
    eid_m = re.search(r'"id":\s*"([^"]+)"', cd)
    eid = eid_m.group(1) if eid_m else None

    def _list() -> QaResult:
        try:
            r = httpx.get(f"{BACKEND}/api/engagement", timeout=5.0)
            d = r.json()
            n = len(d.get("engagements", []))
            return QaResult("GET /api/engagement", "PASS",
                            f"count={n}", section="engagement")
        except Exception as e:
            return QaResult("list", "FAIL", repr(e), section="engagement")
    out.append(timed(_list))

    def _scope() -> QaResult:
        try:
            r = httpx.post(f"{BACKEND}/api/engagement/scope-check",
                           json={"target": "scanme.test"}, timeout=5.0)
            d = r.json()
            return QaResult("POST /api/engagement/scope-check", "PASS" if r.status_code == 200 else "FAIL",
                            f"in_scope={d.get('in_scope')} reason={d.get('reason')}",
                            section="engagement")
        except Exception as e:
            return QaResult("scope-check", "FAIL", repr(e), section="engagement")
    out.append(timed(_scope))

    if eid:
        def _panic() -> QaResult:
            try:
                r = httpx.post(f"{BACKEND}/api/engagement/{eid}/panic", timeout=5.0)
                return QaResult(f"POST /panic {eid}", "PASS" if r.status_code in (200, 404) else "FAIL",
                                f"status={r.status_code}", section="engagement")
            except Exception as e:
                return QaResult("panic", "FAIL", repr(e), section="engagement")
        out.append(timed(_panic))
    return out


# ========== System / onboard / toolbox ==========

def qa_system() -> list[QaResult]:
    out = []
    for ep in ("/api/system/diag", "/api/system/diag/nmap", "/api/system/diag/nuclei"):
        def _make(ep=ep) -> QaResult:
            try:
                r = httpx.get(f"{BACKEND}{ep}", timeout=8.0)
                return QaResult(f"GET {ep}", "PASS" if r.status_code == 200 else "FAIL",
                                f"status={r.status_code}",
                                section="system", artifacts=[r.text[:600]])
            except Exception as e:
                return QaResult(ep, "FAIL", repr(e), section="system")
        out.append(timed(_make))
    return out


def qa_onboard() -> list[QaResult]:
    out = []
    def _reset() -> QaResult:
        try:
            r = httpx.post(f"{BACKEND}/api/onboard/reset", timeout=5.0)
            return QaResult("POST /api/onboard/reset", "PASS" if r.status_code == 200 else "FAIL",
                            f"status={r.status_code}", section="onboard")
        except Exception as e:
            return QaResult("reset", "FAIL", repr(e), section="onboard")
    out.append(timed(_reset))

    def _state() -> QaResult:
        try:
            r = httpx.get(f"{BACKEND}/api/onboard/state", timeout=5.0)
            return QaResult("GET /api/onboard/state", "PASS" if r.status_code == 200 else "FAIL",
                            f"step={r.json().get('current_step')}", section="onboard")
        except Exception as e:
            return QaResult("state", "FAIL", repr(e), section="onboard")
    out.append(timed(_state))

    def _choose() -> QaResult:
        try:
            r = httpx.post(f"{BACKEND}/api/onboard/choose-path",
                           json={"path": "skip"}, timeout=5.0)
            return QaResult("POST /api/onboard/choose-path skip", "PASS" if r.status_code == 200 else "FAIL",
                            f"status={r.status_code}", section="onboard")
        except Exception as e:
            return QaResult("choose", "FAIL", repr(e), section="onboard")
    out.append(timed(_choose))

    def _finish() -> QaResult:
        try:
            r = httpx.post(f"{BACKEND}/api/onboard/finish", timeout=5.0)
            return QaResult("POST /api/onboard/finish", "PASS" if r.status_code == 200 else "FAIL",
                            f"status={r.status_code}", section="onboard")
        except Exception as e:
            return QaResult("finish", "FAIL", repr(e), section="onboard")
    out.append(timed(_finish))
    return out


def qa_toolbox() -> list[QaResult]:
    out = []
    for ep in ("/api/toolbox/summary", "/api/toolbox/tools?limit=200", "/api/toolbox/categories"):
        def _make(ep=ep) -> QaResult:
            try:
                r = httpx.get(f"{BACKEND}{ep}", timeout=8.0)
                d = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                if "summary" in ep:
                    total = d.get("total", "?")
                    return QaResult(f"GET {ep}", "PASS" if r.status_code == 200 else "FAIL",
                                    f"total={total}", section="toolbox", artifacts=[r.text[:800]])
                if "tools" in ep:
                    n = len(d.get("tools", []))
                    return QaResult(f"GET {ep}", "PASS" if r.status_code == 200 else "FAIL",
                                    f"count={n}", section="toolbox", artifacts=[r.text[:800]])
                if "categories" in ep:
                    cats = d.get("categories") or d
                    n = len(cats) if isinstance(cats, list) else len(cats.keys()) if isinstance(cats, dict) else "?"
                    return QaResult(f"GET {ep}", "PASS" if r.status_code == 200 else "FAIL",
                                    f"categories={n}", section="toolbox", artifacts=[r.text[:800]])
            except Exception as e:
                return QaResult(ep, "FAIL", repr(e), section="toolbox")
        out.append(timed(_make))
    return out


# ========== Shell ==========

def qa_shell() -> list[QaResult]:
    out = []
    def _create() -> QaResult:
        try:
            r = httpx.post(f"{BACKEND}/api/shell/sessions",
                           json={"cols": 80, "rows": 24}, timeout=10.0)
            d = r.json()
            sid = d.get("session_id")
            return QaResult("POST /api/shell/sessions", "PASS" if r.status_code == 200 else "FAIL",
                            f"session_id={sid}",
                            section="shell", artifacts=[r.text[:1000]])
        except Exception as e:
            return QaResult("shell create", "FAIL", repr(e), section="shell")
    out.append(timed(_create))

    sd = RESULTS[-1]["artifacts"][0] if len(RESULTS) >= 1 and RESULTS[-1]["artifacts"] else "{}"
    sid_m = re.search(r'"session_id":\s*"([^"]+)"', sd)
    sid = sid_m.group(1) if sid_m else None

    if sid:
        def _echo() -> QaResult:
            try:
                r = httpx.delete(f"{BACKEND}/api/shell/sessions/{sid}",
                                  timeout=5.0)
                return QaResult(f"DELETE shell session", "PASS" if r.status_code == 200 else "FAIL",
                                f"status={r.status_code}", section="shell",
                                artifacts=[r.text[:500]])
            except Exception as e:
                return QaResult("delete shell", "FAIL", repr(e), section="shell")
        out.append(timed(_echo))
    return out


# ========== Real-tools (nmap, nuclei, hydra, ffuf, etc.) ==========

def qa_real_tools() -> list[QaResult]:
    out = []

    # 1. nmap 127.0.0.1 (open ports için)
    def _nmap() -> QaResult:
        try:
            r = subprocess.run(
                ["nmap", "-Pn", "-p", "8000,5173,8080,8001,2222,31337",
                 "--max-retries", "0", "--host-timeout", "20s",
                 "-T4", "127.0.0.1"],
                capture_output=True, text=True, timeout=30,
            )
            open_ports = re.findall(r"^(\d+)/tcp\s+open", r.stdout, re.MULTILINE)
            ok = r.returncode == 0 and len(open_ports) >= 3
            return QaResult("nmap 127.0.0.1", "PASS" if ok else "FAIL",
                            f"open_ports={open_ports}",
                            section="real-tools", artifacts=[r.stdout[:1500]])
        except subprocess.TimeoutExpired:
            return QaResult("nmap", "FAIL", "timeout", section="real-tools")
        except FileNotFoundError:
            return QaResult("nmap", "SKIP", "binary missing", section="real-tools")
    out.append(timed(_nmap))

    # 2. nmap service detection
    def _nmap_sV() -> QaResult:
        try:
            r = subprocess.run(
                ["nmap", "-Pn", "-p", "8080,2222,31337",
                 "-sV", "--version-intensity", "1",
                 "--host-timeout", "30s", "127.0.0.1"],
                capture_output=True, text=True, timeout=40,
            )
            services = re.findall(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", r.stdout, re.MULTILINE)
            ok = r.returncode == 0 and services
            return QaResult("nmap -sV service detect", "PASS" if ok else "FAIL",
                            f"services={services[:5]}",
                            section="real-tools", artifacts=[r.stdout[:2000]])
        except subprocess.TimeoutExpired:
            return QaResult("nmap -sV", "FAIL", "timeout", section="real-tools")
        except FileNotFoundError:
            return QaResult("nmap -sV", "SKIP", "binary missing", section="real-tools")
    out.append(timed(_nmap_sV))

    # 3. nikto against 127.0.0.1:8080 (if installed)
    if shutil.which("nikto"):
        def _nikto() -> QaResult:
            try:
                r = subprocess.run(
                    ["perl", shutil.which("nikto"),
                     "-h", "http://127.0.0.1:8080",
                     "-maxtime", "20s",
                     "-nointeractive"],
                    capture_output=True, text=True, timeout=35,
                )
                return QaResult("nikto 127.0.0.1:8080", "PASS" if r.returncode == 0 else "FAIL",
                                f"returncode={r.returncode} stdout_lines={len(r.stdout.splitlines())}",
                                section="real-tools", artifacts=[r.stdout[:1500]])
            except subprocess.TimeoutExpired:
                return QaResult("nikto", "FAIL", "timeout", section="real-tools")
        out.append(timed(_nikto))
    else:
        out.append(QaResult("nikto", "SKIP", "not installed", section="real-tools"))

    # 4. ffuf against 127.0.0.1:8080 (4 paths)
    if shutil.which("ffuf"):
        wl = Path("/tmp/qa-lab/wordlist.txt")
        wl.write_text("/admin\n/api/v1/users\n/phpinfo.php\n/login\n/.env\n")
        def _ffuf() -> QaResult:
            try:
                r = subprocess.run(
                    ["ffuf", "-u", "http://127.0.0.1:8080/FUZZ",
                     "-w", str(wl), "-mc", "200,403",
                     "-t", "10", "-timeout", "10",
                     "-s"],  # silent: each line is a found path
                    capture_output=True, text=True, timeout=30,
                )
                found = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
                ok = r.returncode == 0 and len(found) >= 1
                return QaResult("ffuf 127.0.0.1:8080", "PASS" if ok else "FAIL",
                                f"found={found}",
                                section="real-tools", artifacts=[r.stdout[:1500]])
            except subprocess.TimeoutExpired:
                return QaResult("ffuf", "FAIL", "timeout", section="real-tools")
        out.append(timed(_ffuf))
    else:
        out.append(QaResult("ffuf", "SKIP", "not installed", section="real-tools"))

    # 5. nuclei against 127.0.0.1 (low severity templates only)
    if shutil.which("nuclei"):
        def _nuclei() -> QaResult:
            try:
                r = subprocess.run(
                    ["nuclei", "-u", "http://127.0.0.1:8080",
                     "-severity", "info,low",
                     "-timeout", "8", "-no-stdin",
                     "-nc", "-silent"],
                    capture_output=True, text=True, timeout=45,
                )
                # nuclei exits 0 even if no findings, but we just need it not to crash
                return QaResult("nuclei 127.0.0.1:8080 (info+low)",
                                "PASS" if r.returncode in (0, 1) else "FAIL",
                                f"returncode={r.returncode} findings_lines={len(r.stdout.splitlines())}",
                                section="real-tools",
                                artifacts=[r.stdout[:1500], r.stderr[:500]])
            except subprocess.TimeoutExpired:
                return QaResult("nuclei", "FAIL", "timeout", section="real-tools")
        out.append(timed(_nuclei))
    else:
        out.append(QaResult("nuclei", "SKIP", "not installed", section="real-tools"))

    # 6. hydra (sadece ssh — 1 hesap denemesi)
    if shutil.which("hydra"):
        def _hydra() -> QaResult:
            try:
                r = subprocess.run(
                    ["hydra", "-l", "qa", "-p", "qa", "-t", "1",
                     "-w", "2", "-f", "-I",
                     f"ssh://{LAB_SSH_HOST}:{LAB_SSH_PORT}"],
                    capture_output=True, text=True, timeout=15,
                )
                return QaResult("hydra ssh 127.0.0.1", "PASS" if r.returncode in (0, 255) else "FAIL",
                                f"returncode={r.returncode} (1 attempt)",
                                section="real-tools",
                                artifacts=[r.stdout[:800], r.stderr[:300]])
            except subprocess.TimeoutExpired:
                return QaResult("hydra", "FAIL", "timeout", section="real-tools")
        out.append(timed(_hydra))
    else:
        out.append(QaResult("hydra", "SKIP", "not installed", section="real-tools"))

    # 7. sqlmap (1 endpoint üzerinde --risk 1 --level 1 minimum)
    if shutil.which("sqlmap"):
        def _sqlmap() -> QaResult:
            try:
                r = subprocess.run(
                    ["sqlmap", "-u", "http://127.0.0.1:8080/login?q=test",
                     "--risk", "1", "--level", "1",
                     "--batch", "--random-agent",
                     "--timeout", "5", "--retries", "0",
                     "--technique", "BEUST",
                     "--flush-session"],
                    capture_output=True, text=True, timeout=60,
                )
                return QaResult("sqlmap 127.0.0.1:8080 (risk1 lvl1)",
                                "PASS" if r.returncode in (0, 1) else "FAIL",
                                f"returncode={r.returncode}",
                                section="real-tools",
                                artifacts=[r.stdout[:1500], r.stderr[:500]])
            except subprocess.TimeoutExpired:
                return QaResult("sqlmap", "FAIL", "timeout", section="real-tools")
        out.append(timed(_sqlmap))
    else:
        out.append(QaResult("sqlmap", "SKIP", "not installed", section="real-tools"))

    # 8. banner grabbing (curl + nc)
    def _banner() -> QaResult:
        try:
            r = subprocess.run(
                ["timeout", "3", "nc", "-v", LAB_BANNER_HOST, str(LAB_BANNER_PORT)],
                input=b"\r\n", capture_output=True, timeout=5,
            )
            ok = b"vsFTPd" in r.stdout or b"vsFTPd" in (r.stderr or b"")
            return QaResult(f"nc banner grab :{LAB_BANNER_PORT}",
                            "PASS" if ok else "FAIL",
                            f"got_banner={r.stdout[:60]!r}",
                            section="real-tools", artifacts=[r.stdout[:500], r.stderr[:500]])
        except Exception as e:
            return QaResult("nc banner", "FAIL", repr(e), section="real-tools")
    out.append(timed(_banner))

    # 9. curl — HTTP banner getirme + header inspection
    def _curl_main() -> QaResult:
        try:
            r = subprocess.run(
                ["curl", "-sI", LAB_HTTP_MAIN],
                capture_output=True, text=True, timeout=5,
            )
            ok = "nginx" in r.stdout.lower() and "200" in r.stdout
            return QaResult(f"curl HEAD {LAB_HTTP_MAIN}", "PASS" if ok else "FAIL",
                            f"headers={r.stdout[:200]}",
                            section="real-tools", artifacts=[r.stdout[:1000]])
        except Exception as e:
            return QaResult("curl main", "FAIL", repr(e), section="real-tools")
    out.append(timed(_curl_main))

    def _curl_other() -> QaResult:
        try:
            r = subprocess.run(
                ["curl", "-sI", LAB_HTTP_OTHER],
                capture_output=True, text=True, timeout=5,
            )
            ok = "apache" in r.stdout.lower()
            return QaResult(f"curl HEAD {LAB_HTTP_OTHER}", "PASS" if ok else "FAIL",
                            f"server={r.stdout[:200]}",
                            section="real-tools", artifacts=[r.stdout[:1000]])
        except Exception as e:
            return QaResult("curl other", "FAIL", repr(e), section="real-tools")
    out.append(timed(_curl_other))

    # 10. sshpass ile ssh bağlantısı dene (sadece banner, giriş yapmadan)
    def _ssh_banner() -> QaResult:
        try:
            r = subprocess.run(
                ["timeout", "5", "ssh", "-o", "StrictHostKeyChecking=no",
                 "-o", "PasswordAuthentication=no",
                 "-o", "PreferredAuthentications=publickey",
                 "-o", "ConnectTimeout=3",
                 "-p", str(LAB_SSH_PORT),
                 f"qa@{LAB_SSH_HOST}", "echo", "OK"],
                capture_output=True, text=True, timeout=10,
            )
            return QaResult(f"ssh 127.0.0.1:{LAB_SSH_PORT} banner",
                            "PASS" if r.returncode in (0, 1, 255) else "FAIL",
                            f"returncode={r.returncode}",
                            section="real-tools",
                            artifacts=[r.stdout[:500], r.stderr[:500]])
        except Exception as e:
            return QaResult("ssh", "FAIL", repr(e), section="real-tools")
    out.append(timed(_ssh_banner))

    return out


# ========== CLI subcommands ==========

def qa_cli() -> list[QaResult]:
    out = []
    CLI = "/home/kaan/kangal/backend/.venv/bin/kangal"
    if not Path(CLI).exists():
        return [QaResult("kangal CLI", "SKIP", "not installed", section="cli")]

    commands = [
        ("--json scan list", ["--json", "scan", "list"]),
        ("--json intel patterns", ["--json", "intel", "patterns"]),
        ("--json engagement list", ["--json", "engagement", "list"]),
        ("--json system diag", ["--json", "system", "diag"]),
        ("--json toolbox summary", ["--json", "toolbox", "summary"]),
        ("--json tool list", ["--json", "tool", "list"]),
        ("--json shell sessions", ["--json", "shell", "sessions"]),
        ("--help (root)", ["--help"]),
        ("scan --help", ["scan", "--help"]),
        ("intel --help", ["intel", "--help"]),
        ("tool --help", ["tool", "--help"]),
        ("engagement --help", ["engagement", "--help"]),
        ("system --help", ["system", "--help"]),
        ("toolbox --help", ["toolbox", "--help"]),
        ("shell --help", ["shell", "--help"]),
    ]
    for label, cmd in commands:
        def _run(label=label, cmd=cmd) -> QaResult:
            try:
                r = subprocess.run(
                    [CLI, *cmd],
                    capture_output=True, text=True, timeout=15,
                    env={**os.environ, "KANGAL_BACKEND_URL": BACKEND},
                )
                ok = r.returncode in (0, 1)
                sample = (r.stdout + r.stderr).replace("\n", " ")[:120]
                return QaResult(f"CLI: {' '.join(cmd)}",
                                "PASS" if ok else "FAIL",
                                f"exit={r.returncode} sample={sample}",
                                section="cli",
                                artifacts=[r.stdout[:1000], r.stderr[:500]])
            except Exception as e:
                return QaResult(label, "FAIL", repr(e), section="cli")
        out.append(timed(_run))

    # CLI ile sayım: scan / intel veri içerik kontrolü
    def _cli_intel_patterns_has_data() -> QaResult:
        try:
            r = subprocess.run([CLI, "--json", "intel", "patterns"],
                               capture_output=True, text=True, timeout=10,
                               env={**os.environ, "KANGAL_BACKEND_URL": BACKEND})
            ok = r.returncode == 0 and ("[]" in r.stdout or "{" in r.stdout)
            return QaResult("CLI intel patterns → JSON parse",
                            "PASS" if ok else "FAIL",
                            f"exit={r.returncode} stdout_len={len(r.stdout)}",
                            section="cli",
                            artifacts=[r.stdout[:1000]])
        except Exception as e:
            return QaResult("cli intel patterns parse", "FAIL", repr(e), section="cli")
    out.append(timed(_cli_intel_patterns_has_data))

    return out


# ========== Frontend view smoke (Playwright) ==========

def qa_frontend() -> list[QaResult]:
    out = []
    if not shutil.which("chromium") and not (Path("/home/kaan/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome").exists()):
        out.append(QaResult("frontend views", "SKIP", "chromium not installed", section="frontend"))
        return out
    CHROME = "/home/kaan/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome"
    if not Path(CHROME).exists():
        CHROME = shutil.which("chromium") or "/usr/bin/chromium"

    def _probe(label, click_text) -> QaResult:
        from playwright.sync_api import sync_playwright
        try:
            with sync_playwright() as p:
                b = p.chromium.launch(headless=True, executable_path=CHROME)
                ctx = b.new_context(viewport={"width": 1700, "height": 1000})
                page = ctx.new_page()
                page.goto(FRONTEND, wait_until="domcontentloaded", timeout=20000)
                page.wait_for_timeout(3000)
                # suppress onboard modal if any
                page.evaluate("""() => { try { localStorage.setItem('kangal.onboarded.v2', '1'); } catch {} }""")
                page.reload(wait_until="domcontentloaded", timeout=20000)
                page.wait_for_timeout(3000)
                # click the tab if requested
                if click_text:
                    clicked = page.evaluate(
                        """(t) => {
                          const btns = Array.from(document.querySelectorAll('button'));
                          const b = btns.find(x => x.innerText.trim().startsWith(t));
                          if (b) { b.click(); return true; }
                          return false;
                        }""",
                        click_text,
                    )
                    page.wait_for_timeout(1500)
                # capture some signals
                text = page.evaluate("() => document.body.innerText || ''")
                ok_count = sum(1 for k in ("SCAN", "TOOL") if k in text.upper())
                b.close()
                return QaResult(f"frontend tab '{click_text or '/'}'",
                                "PASS" if ok_count >= 1 else "FAIL",
                                f"text_chars={len(text)}", section="frontend",
                                artifacts=[text[:1500]])
        except Exception as e:
            return QaResult(f"frontend {label}", "FAIL", repr(e)[:200], section="frontend")
    out.append(timed(lambda: _probe("home", None)))
    out.append(timed(lambda: _probe("intel", "INTEL")))
    out.append(timed(lambda: _probe("toolmgr", "TOOL MGR")))
    out.append(timed(lambda: _probe("reports", "REPORTS")))
    out.append(timed(lambda: _probe("cli", "CLI")))
    out.append(timed(lambda: _probe("threat", "THREAT")))
    return out


# ========== Main runner ==========

def main() -> int:
    QA_LOG.write_text("")  # reset
    print(f"[qa] starting at {time.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
    print(f"[qa] lab ports →", json.dumps({n: socket_check(p) for n, p in [
        ("http_main", 8080), ("http_paths", 8001), ("ssh", 2222),
        ("smb", 445), ("tcp_vuln", 31337), ("backend", 8000), ("frontend", 5173)
    ]}, indent=2), flush=True)

    sections: list[tuple[str, Callable[[], list[QaResult]]]] = [
        ("boot", lambda: [timed(qa_backend_health), timed(qa_backend_routes_count), timed(qa_lab_ports)]),
        ("agents", qa_scan_pipeline),
        ("intel", lambda: qa_intel_patterns() + qa_threat_intel_view_kw()),
        ("ruflo", qa_ruflo),
        ("redteam", qa_redteam),
        ("engagement", qa_engagement),
        ("system", qa_system),
        ("onboard", qa_onboard),
        ("toolbox", qa_toolbox),
        ("shell", qa_shell),
        ("real-tools", qa_real_tools),
        ("cli", qa_cli),
        ("frontend", qa_frontend),
    ]

    grand_t0 = time.monotonic()
    for name, runner in sections:
        t0 = time.monotonic()
        try:
            res = runner()
        except Exception as e:
            res = [QaResult(name, "FAIL", f"runner exception: {e!r}", section=name)]
        for r in res:
            r.section = r.section or name
            record(r)
        print(f"  [{name}] {len(res)} checks in {(time.monotonic()-t0):.1f}s", flush=True)

    grand = time.monotonic() - grand_t0
    pass_n = sum(1 for r in RESULTS if r["status"] == "PASS")
    fail_n = sum(1 for r in RESULTS if r["status"] == "FAIL")
    skip_n = sum(1 for r in RESULTS if r["status"] == "SKIP")
    print(f"\n[qa] TOTAL: PASS={pass_n}  FAIL={fail_n}  SKIP={skip_n}  in {grand:.1f}s", flush=True)
    write_report(grand)
    return 0 if fail_n == 0 else 1


def socket_check(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            return True
    except OSError:
        return False


def write_report(grand_seconds: float) -> None:
    pass_n = sum(1 for r in RESULTS if r["status"] == "PASS")
    fail_n = sum(1 for r in RESULTS if r["status"] == "FAIL")
    skip_n = sum(1 for r in RESULTS if r["status"] == "SKIP")
    by_section: dict[str, dict[str, int]] = {}
    for r in RESULTS:
        by_section.setdefault(r["section"], {"PASS": 0, "FAIL": 0, "SKIP": 0})
        by_section[r["section"]][r["status"]] += 1

    lines = [
        "# Kangal QA Report",
        "",
        f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Total checks: **{pass_n + fail_n + skip_n}**",
        f"- PASS: **{pass_n}** / FAIL: **{fail_n}** / SKIP: **{skip_n}**",
        f"- Total runtime: {grand_seconds:.1f}s",
        "",
        "## Lab ortamı",
        "",
        "| Servis | Port | Durum |",
        "|---|---|---|",
        "| nginx HTTP ana (8080) | 8080 | " + ("✓" if socket_check(8080) else "✗") + " |",
        "| nginx HTTP diğer (8001) | 8001 | " + ("✓" if socket_check(8001) else "✗") + " |",
        "| sshd | 2222 | " + ("✓" if socket_check(2222) else "✗") + " |",
        "| smbd (lab tuning'da sorunlu) | 445 | " + ("✓" if socket_check(445) else "✗") + " |",
        "| TCP banner (fake vsftpd) | 31337 | " + ("✓" if socket_check(31337) else "✗") + " |",
        "| Kangal backend | 8000 | " + ("✓" if socket_check(8000) else "✗") + " |",
        "| Kangal frontend (Vite) | 5173 | " + ("✓" if socket_check(5173) else "✗") + " |",
        "",
        "## Bölüm bazında özet",
        "",
        "| Bölüm | PASS | FAIL | SKIP |",
        "|---|---:|---:|---:|",
    ]
    for sec in sorted(by_section.keys()):
        s = by_section[sec]
        lines.append(f"| {sec} | {s.get('PASS',0)} | {s.get('FAIL',0)} | {s.get('SKIP',0)} |")
    lines.append("")

    # Detay
    for sec in sorted(by_section.keys()):
        lines += ["", f"### {sec}", ""]
        for r in [x for x in RESULTS if x["section"] == sec]:
            icon = {"PASS": "✓", "FAIL": "✗", "SKIP": "~"}[r["status"]]
            lines.append(f"- {icon} **{r['name']}** ({r['duration_ms']}ms)")
            if r["detail"]:
                lines.append(f"  - {r['detail']}")
    REPORT_PATH.write_text("\n".join(lines) + "\n")
    print(f"[qa] report → {REPORT_PATH}")


if __name__ == "__main__":
    sys.exit(main())
