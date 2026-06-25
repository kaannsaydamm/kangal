"""Ruflo-compatible telemetry + memory layer (extended for toolbox v2).

Mirrors the public surface of the ruflo MCP toolset. The MCP names are kept
as comments throughout so it's easy to swap a real MCP server in here later
without changing the call sites.

Mirrored MCP surface (each row: kangal name ←→ MCP name):
  memory_store               ← mcp__claude-flow__memory_store
  memory_search              ← mcp__claude-flow__memory_search
  memory_stats               ← (derived)
  pattern_store              ← mcp__agentic-flow__agentdb_pattern_store
  pattern_search             ← mcp__agentic-flow__agentdb_pattern_search
  hook_pre / hook_post       ← mcp__claude-flow__hooks_pre_task / _post_task
  swarm_init / swarm_set_status / swarm_status
                             ← mcp__claude-flow__swarm_init / _status
  agent_spawn / agent_list   ← mcp__claude-flow__agent_spawn / _list
  neural_train / neural_status
                             ← mcp__claude-flow__neural_train / _status
  engagement_*               ← (kangal extension; ATT&CK stage tracker)
  exploit_attempt_*          ← (kangal extension; red team event sink)
  credential_discovered      ← (kangal extension; red team event sink)
  lateral_path_identified    ← (kangal extension; red team event sink)
  persistence_detected       ← (kangal extension; red team event sink)
  c2_beacon_detected         ← (kangal extension; red team event sink)
  mitre_map                  ← (kangal extension; technique ID lookup)

Storage: in-process + small JSON at $KANGAL_RUFLO.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any


_LOCK = threading.Lock()
_PATH = Path(os.environ.get("KANGAL_RUFLO", "/tmp/kangal-ruflo.json"))


# ---------- static agent catalog (mirrors mcp__claude-flow__agent_spawn) ----------

AGENT_CATALOG: list[dict[str, Any]] = [
    # Tier 0 — original recon pipeline
    {
        "id": "subdomain", "type": "recon",
        "capabilities": ["crt.sh", "DNS brute", "subdomain enumeration"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "dns", "type": "recon",
        "capabilities": ["DoH", "A/AAAA resolve", "parent_id chain"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "http_probe", "type": "recon",
        "capabilities": ["httpx async", "header capture", "redirect chain"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "portscan", "type": "recon",
        "capabilities": ["nmap -sT -sV", "top-100 ports", "service banner"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "tech", "type": "fingerprint",
        "capabilities": ["header regex", "body regex", "version disclosure"],
        "cognitive_pattern": "lateral",
    },
    {
        "id": "pathscan", "type": "recon",
        "capabilities": ["common wordlist", "path bruteforce", "exposed panels"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "vuln", "type": "correlator",
        "capabilities": ["port→CVE", "header patterns", "tech→CVE", "path→finding"],
        "cognitive_pattern": "critical",
    },
    # Tier 1 — exploitation + network agents
    {
        "id": "exploit_sqli", "type": "exploit",
        "capabilities": ["sqlmap", "error-based", "time-based", "boolean-based"],
        "cognitive_pattern": "critical",
    },
    {
        "id": "exploit_xss", "type": "exploit",
        "capabilities": ["dalfox", "xsstrike", "reflected XSS", "DOM-XSS surface"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "exploit_cmdi", "type": "exploit",
        "capabilities": ["time-based cmdi", "echo-back", "OS detection"],
        "cognitive_pattern": "critical",
    },
    {
        "id": "exploit_lfi", "type": "exploit",
        "capabilities": ["path traversal", "PHP wrappers", "RFI"],
        "cognitive_pattern": "critical",
    },
    {
        "id": "vuln_nuclei", "type": "vuln_scan",
        "capabilities": ["nuclei templates", "9k+ checks", "CVE correlation"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "vuln_nikto", "type": "vuln_scan",
        "capabilities": ["nikto", "6700+ checks", "web server fingerprint"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "cms_wpscan", "type": "cms_scan",
        "capabilities": ["wpscan", "WordPress", "plugin/theme vuln", "user enum"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "fuzz_ffuf", "type": "fuzz",
        "capabilities": ["ffuf", "fast web fuzzer", "header/param/path"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "fuzz_feroxbuster", "type": "fuzz",
        "capabilities": ["feroxbuster", "recursive content discovery"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "fuzz_kiterunner", "type": "api_discovery",
        "capabilities": ["kiterunner", "API endpoint", "Swagger/GraphQL/REST"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "fuzz_arjun", "type": "fuzz",
        "capabilities": ["arjun", "hidden HTTP parameter discovery"],
        "cognitive_pattern": "lateral",
    },
    {
        "id": "subdomain_subfinder", "type": "recon",
        "capabilities": ["subfinder", "40+ passive sources", "JSON"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "subdomain_amass", "type": "recon",
        "capabilities": ["amass", "passive+active+brute", "deepest enum"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "dns_dnsx", "type": "recon",
        "capabilities": ["dnsx", "bulk DNS", "CNAME chain"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "probe_httpx", "type": "recon",
        "capabilities": ["httpx", "title/status/tech/chain"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "creds_hydra", "type": "online_brute",
        "capabilities": ["hydra", "50+ protocols", "rate-limited"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "crack_john", "type": "offline_crack",
        "capabilities": ["john", "auto-format detect", "CPU"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "crack_hashcat", "type": "offline_crack",
        "capabilities": ["hashcat", "GPU", "300+ hash types"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "ad_impacket", "type": "ad_exploit",
        "capabilities": ["impacket", "psexec/wmiexec/smbexec/secretsdump"],
        "cognitive_pattern": "critical",
    },
    {
        "id": "ad_nxc", "type": "ad_exploit",
        "capabilities": ["NetExec", "SMB/LDAP/RDP/WinRM", "credential spray"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "ad_bloodhound", "type": "ad_recon",
        "capabilities": ["bloodhound-python", "attack path mapping"],
        "cognitive_pattern": "systems",
    },
    {
        "id": "ad_evilwinrm", "type": "ad_exploit",
        "capabilities": ["evil-winrm", "PowerShell remote"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "smb_enum4linux", "type": "ad_enum",
        "capabilities": ["enum4linux-ng", "users/shares/groups/OS"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "smb_smbmap", "type": "ad_enum",
        "capabilities": ["smbmap", "share permission"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "mitm_responder", "type": "mitm",
        "capabilities": ["responder", "LLMNR/NBT-NS/MDNS/DHCP poison"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "tunnel_chisel", "type": "pivoting",
        "capabilities": ["chisel", "TCP tunnel", "SOCKS"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "tunnel_ligolo", "type": "pivoting",
        "capabilities": ["ligolo-ng", "TUN interface", "full TCP"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "privesc_linpeas", "type": "post_exploit",
        "capabilities": ["linpeas", "100+ Linux privesc checks"],
        "cognitive_pattern": "systems",
    },
    {
        "id": "privesc_winpeas", "type": "post_exploit",
        "capabilities": ["winpeas", "Windows privesc checks"],
        "cognitive_pattern": "systems",
    },
    {
        "id": "osint_harvester", "type": "osint",
        "capabilities": ["theHarvester", "email/subdomain/host", "50+ sources"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "osint_reconng", "type": "osint",
        "capabilities": ["recon-ng", "modular OSINT framework"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "osint_spiderfoot", "type": "osint",
        "capabilities": ["spiderfoot", "200+ modules", "auto-OSINT"],
        "cognitive_pattern": "systems",
    },
    {
        "id": "osint_holehe", "type": "osint",
        "capabilities": ["holehe", "email → registered accounts"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "secret_trufflehog", "type": "secret_scan",
        "capabilities": ["trufflehog", "800+ secret patterns"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "secret_gitleaks", "type": "secret_scan",
        "capabilities": ["gitleaks", "git history secrets"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "sast_semgrep", "type": "sast",
        "capabilities": ["semgrep", "multi-language SAST"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "cloud_prowler", "type": "cloud_audit",
        "capabilities": ["prowler", "AWS/Azure/GCP CIS"],
        "cognitive_pattern": "systems",
    },
    {
        "id": "cloud_scoutsuite", "type": "cloud_audit",
        "capabilities": ["scoutsuite", "multi-cloud posture"],
        "cognitive_pattern": "systems",
    },
    {
        "id": "cloud_trivy", "type": "vuln_scan",
        "capabilities": ["trivy", "container/IaC/misconfig"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "k8s_hunter", "type": "k8s_recon",
        "capabilities": ["kube-hunter", "active K8s scanning"],
        "cognitive_pattern": "critical",
    },
    {
        "id": "waf_wafw00f", "type": "waf_detect",
        "capabilities": ["wafw00f", "150+ WAF fingerprint"],
        "cognitive_pattern": "convergent",
    },
    {
        "id": "wordlist_cewl", "type": "wordlist_gen",
        "capabilities": ["cewl", "target content → wordlist"],
        "cognitive_pattern": "divergent",
    },
    {
        "id": "smtp_swaks", "type": "smtp_test",
        "capabilities": ["swaks", "SMTP testing", "open relay"],
        "cognitive_pattern": "convergent",
    },
]


# ---------- persistence ----------

def _load() -> dict[str, Any]:
    if not _PATH.exists():
        return _fresh()
    try:
        return json.loads(_PATH.read_text(encoding="utf-8"))
    except Exception:
        return _fresh()


def _fresh() -> dict[str, Any]:
    return {
        "hooks": {"pre": 0, "post": 0, "by_stage": {}},
        "memory": {"stores": 0, "searches": 0},
        "patterns": {"stores": 0, "searches": 0},
        "swarms": {},  # swarm_id -> {scan_id, target, mode, started_at, agents, status, ...}
        "neural": {"trajectories": []},  # last 1000
        "engagement": {  # kangal extension
            "active": {},
            "history": [],
        },
        "exploit_attempts": [],   # last 2000
        "credentials": [],        # discovered creds, hashed
        "lateral_paths": [],      # identified lateral movement paths
        "persistence": [],        # persistence mechanism detections
        "c2_beacons": [],         # suspected C2 beacons
        "mitre": {},              # technique_id -> count
    }


def _save(d: dict[str, Any]) -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    _PATH.write_text(json.dumps(d, ensure_ascii=False, default=str), encoding="utf-8")


# ---------- hooks (pre/post-task) ----------
# mcp__claude-flow__hooks_pre_task
# mcp__claude-flow__hooks_post_task

def hook_pre(stage: str) -> None:
    with _LOCK:
        d = _load()
        d["hooks"]["pre"] += 1
        d["hooks"]["by_stage"][stage] = d["hooks"]["by_stage"].get(stage, 0) + 1
        _save(d)


def hook_post(stage: str) -> None:
    with _LOCK:
        d = _load()
        d["hooks"]["post"] += 1
        _save(d)


def hooks_stats() -> dict[str, Any]:
    with _LOCK:
        d = _load()
    return {
        "pre": d["hooks"]["pre"],
        "post": d["hooks"]["post"],
        "by_stage": d["hooks"]["by_stage"],
    }


# ---------- memory (store / search) ----------
# mcp__claude-flow__memory_store
# mcp__claude-flow__memory_search

def memory_store(key: str, value: str, tags: list[str] | None = None) -> None:
    from . import intel
    intel.store_finding(
        scan_id=key,
        finding={
            "severity": "info",
            "vuln_class": "memory",
            "title": value[:200],
            "evidence": {"tags": tags or [], "key": key},
        },
    )
    with _LOCK:
        d = _load()
        d["memory"]["stores"] += 1
        _save(d)


def memory_search(query: str, limit: int = 20) -> list[dict[str, Any]]:
    from . import intel
    results = intel.search(query, limit=limit)
    with _LOCK:
        d = _load()
        d["memory"]["searches"] += 1
        _save(d)
    return results


def memory_stats() -> dict[str, Any]:
    with _LOCK:
        d = _load()
    from . import intel
    local = intel._load()
    return {
        "stores": d["memory"]["stores"],
        "searches": d["memory"]["searches"],
        "findings_indexed": len(local.get("findings", [])),
        "patterns_indexed": len(local.get("patterns", [])),
    }


# ---------- patterns (agentdb) ----------
# mcp__agentic-flow__agentdb_pattern_store
# mcp__agentic-flow__agentdb_pattern_search

def pattern_store(agent: str, pattern: str, confidence: float = 0.5) -> None:
    from . import intel
    intel.store_pattern(agent=agent, target=pattern, outcome="pattern", confidence=confidence)
    with _LOCK:
        d = _load()
        d["patterns"]["stores"] += 1
        _save(d)


def pattern_search(query: str, limit: int = 20) -> list[dict[str, Any]]:
    from . import intel
    pats = intel.list_patterns(limit=200)
    q_tokens = [t.lower() for t in (query or "").split() if len(t) >= 2]
    if not q_tokens:
        out = pats[:limit]
    else:
        scored = []
        for p in pats:
            hay = " ".join(
                [
                    str(p.get("agent") or ""),
                    str(p.get("target") or ""),
                    str(p.get("outcome") or ""),
                ]
            ).lower()
            score = sum(1 for t in q_tokens if t in hay) / max(1, len(q_tokens))
            if score > 0:
                scored.append((score, p))
        scored.sort(key=lambda x: x[0], reverse=True)
        out = [p for _, p in scored[:limit]]
    with _LOCK:
        d = _load()
        d["patterns"]["searches"] += 1
        _save(d)
    return out


# ---------- swarm (init / status) ----------
# mcp__claude-flow__swarm_init
# mcp__claude-flow__swarm_status

def swarm_init(scan_id: str, target: str, mode: str, max_agents: int = 7) -> str:
    swarm_id = f"swarm-{scan_id[:8]}"
    with _LOCK:
        d = _load()
        d["swarms"][swarm_id] = {
            "scan_id": scan_id,
            "target": target,
            "mode": mode,
            "started_at": time.time(),
            "status": "running",
            "topology": "hierarchical-mesh",
            "max_agents": max_agents,
            "agents": [a["id"] for a in AGENT_CATALOG],
        }
        _save(d)
    return swarm_id


def swarm_set_status(swarm_id: str, status: str) -> None:
    with _LOCK:
        d = _load()
        if swarm_id in d["swarms"]:
            d["swarms"][swarm_id]["status"] = status
            d["swarms"][swarm_id]["finished_at"] = time.time()
            _save(d)


def swarm_status(swarm_id: str | None = None) -> dict[str, Any]:
    with _LOCK:
        d = _load()
    if swarm_id:
        return d["swarms"].get(swarm_id, {})
    return {"swarms": d["swarms"], "count": len(d["swarms"])}


def swarm_list() -> list[dict[str, Any]]:
    with _LOCK:
        d = _load()
    items = list(d["swarms"].values())
    items.sort(key=lambda s: s.get("started_at", 0), reverse=True)
    return items


# ---------- agent catalog (spawn / list) ----------
# mcp__claude-flow__agent_spawn
# mcp__claude-flow__agent_list

def agent_list() -> list[dict[str, Any]]:
    return list(AGENT_CATALOG)


def agent_spawn(agent_id: str) -> dict[str, Any]:
    for a in AGENT_CATALOG:
        if a["id"] == agent_id:
            return {"spawned": True, **a}
    return {"spawned": False, "error": f"unknown agent: {agent_id}"}


# ---------- neural (train / status) ----------
# mcp__claude-flow__neural_train
# mcp__claude-flow__neural_status

def neural_train(agent: str, scan_id: str, target: str, ok: bool, duration_s: float) -> None:
    with _LOCK:
        d = _load()
        d["neural"]["trajectories"].append({
            "ts": time.time(),
            "agent": agent,
            "scan_id": scan_id,
            "target": target,
            "ok": ok,
            "duration_s": round(duration_s, 3),
        })
        d["neural"]["trajectories"] = d["neural"]["trajectories"][-1000:]
        _save(d)


def neural_status() -> dict[str, Any]:
    with _LOCK:
        d = _load()
    traj = d["neural"]["trajectories"]
    by_agent: dict[str, dict[str, Any]] = {}
    for t in traj:
        a = t["agent"]
        b = by_agent.setdefault(a, {"ok": 0, "fail": 0, "total_dur_s": 0.0, "n": 0})
        if t["ok"]:
            b["ok"] += 1
        else:
            b["fail"] += 1
        b["total_dur_s"] += t["duration_s"]
        b["n"] += 1
    for a, b in by_agent.items():
        b["avg_dur_s"] = round(b["total_dur_s"] / max(1, b["n"]), 3)
        b["success_rate"] = round(b["ok"] / max(1, b["n"]), 3)
        del b["total_dur_s"]
    return {
        "trajectory_count": len(traj),
        "by_agent": by_agent,
        "last_5": traj[-5:],
    }


# ---------- kangal extension: engagement manager ----------

def engagement_create(
    name: str,
    client: str,
    operator: str,
    scope_cidrs: list[str],
    scope_domains: list[str],
    excluded: list[str] | None = None,
    profile: str = "full_spectrum",
    start_at: float | None = None,
    end_at: float | None = None,
    destructive_allowed: bool = False,
) -> str:
    eid = f"eng-{uuid.uuid4().hex[:10]}"
    with _LOCK:
        d = _load()
        d["engagement"]["active"][eid] = {
            "id": eid,
            "name": name,
            "client": client,
            "operator": operator,
            "scope_cidrs": scope_cidrs,
            "scope_domains": scope_domains,
            "excluded": excluded or [],
            "profile": profile,
            "start_at": start_at or time.time(),
            "end_at": end_at,
            "destructive_allowed": destructive_allowed,
            "status": "active",
            "scans_run": 0,
            "findings_count": 0,
            "created_at": time.time(),
        }
        _save(d)
    return eid


def engagement_status(eid: str | None = None) -> dict[str, Any]:
    with _LOCK:
        d = _load()
    if eid:
        return d["engagement"]["active"].get(eid, {})
    return {
        "active": d["engagement"]["active"],
        "count": len(d["engagement"]["active"]),
    }


def engagement_stop(eid: str, reason: str = "manual") -> None:
    with _LOCK:
        d = _load()
        if eid in d["engagement"]["active"]:
            eng = d["engagement"]["active"].pop(eid)
            eng["status"] = "stopped"
            eng["stopped_at"] = time.time()
            eng["stop_reason"] = reason
            d["engagement"]["history"].append(eng)
            _save(d)


def engagement_panic(eid: str) -> dict[str, Any]:
    """Kill switch: stop engagement + flag all active swarms as killed."""
    with _LOCK:
        d = _load()
        if eid not in d["engagement"]["active"]:
            return {"killed": False, "reason": "engagement not active"}
        eng = d["engagement"]["active"][eid]
        # mark all swarms belonging to this engagement as killed
        killed_swarms = []
        for swarm_id, s in list(d["swarms"].items()):
            if s.get("engagement_id") == eid and s.get("status") == "running":
                s["status"] = "killed"
                s["finished_at"] = time.time()
                killed_swarms.append(swarm_id)
        eng["status"] = "killed"
        eng["stopped_at"] = time.time()
        eng["stop_reason"] = "panic"
        d["engagement"]["history"].append(dict(eng))
        del d["engagement"]["active"][eid]
        _save(d)
    return {
        "killed": True,
        "engagement_id": eid,
        "killed_swarms": killed_swarms,
    }


# ---------- kangal extension: red team event sinks ----------

def exploit_attempt(
    scan_id: str,
    target: str,
    technique: str,
    payload_id: str | None = None,
    success: bool = False,
    severity: str = "info",
    evidence: dict[str, Any] | None = None,
    mitre_technique: str | None = None,
) -> str:
    aid = f"ex-{uuid.uuid4().hex[:10]}"
    with _LOCK:
        d = _load()
        d["exploit_attempts"].append({
            "id": aid,
            "ts": time.time(),
            "scan_id": scan_id,
            "target": target,
            "technique": technique,
            "payload_id": payload_id,
            "success": success,
            "severity": severity,
            "evidence": evidence or {},
            "mitre_technique": mitre_technique,
        })
        d["exploit_attempts"] = d["exploit_attempts"][-2000:]
        if mitre_technique:
            d["mitre"][mitre_technique] = d["mitre"].get(mitre_technique, 0) + 1
        _save(d)
    return aid


def credential_discovered(
    scan_id: str,
    target: str,
    service: str,
    username: str,
    secret_hash: str,
    source: str,
) -> str:
    cid = f"cred-{uuid.uuid4().hex[:10]}"
    with _LOCK:
        d = _load()
        d["credentials"].append({
            "id": cid,
            "ts": time.time(),
            "scan_id": scan_id,
            "target": target,
            "service": service,
            "username": username,
            "secret_hash": secret_hash,
            "source": source,
        })
        d["credentials"] = d["credentials"][-500:]
        _save(d)
    return cid


def lateral_path_identified(
    scan_id: str,
    from_host: str,
    to_host: str,
    via_service: str,
    credential_ref: str | None = None,
) -> str:
    lid = f"lat-{uuid.uuid4().hex[:10]}"
    with _LOCK:
        d = _load()
        d["lateral_paths"].append({
            "id": lid,
            "ts": time.time(),
            "scan_id": scan_id,
            "from_host": from_host,
            "to_host": to_host,
            "via_service": via_service,
            "credential_ref": credential_ref,
        })
        d["lateral_paths"] = d["lateral_paths"][-200:]
        _save(d)
    return lid


def persistence_detected(
    scan_id: str,
    target: str,
    kind: str,
    detail: str,
) -> str:
    pid = f"per-{uuid.uuid4().hex[:10]}"
    with _LOCK:
        d = _load()
        d["persistence"].append({
            "id": pid,
            "ts": time.time(),
            "scan_id": scan_id,
            "target": target,
            "kind": kind,
            "detail": detail,
        })
        d["persistence"] = d["persistence"][-200:]
        _save(d)
    return pid


def c2_beacon_detected(
    scan_id: str,
    target: str,
    indicator: str,
    destination: str,
    pattern: str,
) -> str:
    bid = f"c2-{uuid.uuid4().hex[:10]}"
    with _LOCK:
        d = _load()
        d["c2_beacons"].append({
            "id": bid,
            "ts": time.time(),
            "scan_id": scan_id,
            "target": target,
            "indicator": indicator,
            "destination": destination,
            "pattern": pattern,
        })
        d["c2_beacons"] = d["c2_beacons"][-200:]
        _save(d)
    return bid


def mitre_summary() -> dict[str, Any]:
    with _LOCK:
        d = _load()
    return {
        "counts": d.get("mitre", {}),
        "techniques_total": len(d.get("mitre", {})),
        "attempts_total": len(d.get("exploit_attempts", [])),
        "success_total": sum(1 for x in d.get("exploit_attempts", []) if x.get("success")),
    }


# ---------- top-level summary ----------

def summary() -> dict[str, Any]:
    return {
        "hooks": hooks_stats(),
        "memory": memory_stats(),
        "swarms": swarm_status(),
        "neural": neural_status(),
        "engagement": engagement_status(),
        "exploits": {
            "total": len(_load().get("exploit_attempts", [])),
            "successful": sum(1 for x in _load().get("exploit_attempts", []) if x.get("success")),
        },
        "credentials": len(_load().get("credentials", [])),
        "lateral_paths": len(_load().get("lateral_paths", [])),
        "persistence": len(_load().get("persistence", [])),
        "c2_beacons": len(_load().get("c2_beacons", [])),
        "mitre": mitre_summary(),
        "agents": agent_list(),
    }
