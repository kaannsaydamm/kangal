"""Kangal FastAPI entrypoint.

REST:
  GET  /                              health
  POST /api/scan                      queue a new scan, returns scan_id
  GET  /api/scans                     list past scans
  GET  /api/scan/{id}                 scan summary + stats
  GET  /api/scan/{id}/assets          nodes/edges for the asset graph
  GET  /api/scan/{id}/findings        findings list
  GET  /api/scan/{id}/events          full event log (terminal replay)
  GET  /api/scan/{id}/report.md       markdown report (target, status, agents, findings)

  GET  /api/intel/search?q=...        search cross-scan memory
  GET  /api/intel/patterns            stored recon patterns

  GET  /api/toolbox/summary           registry summary (tier/category buckets)
  GET  /api/toolbox/tools             list tools (filter by ?tier= ?category=)
  GET  /api/toolbox/categories        categories + tier counts
  POST /api/toolbox/execute           run a tool synchronously via ToolExecutor

  POST /api/engagement                create engagement (scope, profile)
  GET  /api/engagement                list active engagements
  GET  /api/engagement/{id}           engagement details
  DELETE /api/engagement/{id}         stop engagement
  POST /api/engagement/{id}/panic     kill switch — stop + kill all swarms
  POST /api/engagement/scope-check    {target, engagement_id?} -> in_scope?

  POST /api/redteam/exploit-attempt   sink: exploit_attempt()
  POST /api/redteam/credential        sink: credential_discovered()
  POST /api/redteam/lateral-path      sink: lateral_path_identified()
  POST /api/redteam/persistence       sink: persistence_detected()
  POST /api/redteam/c2-beacon         sink: c2_beacon_detected()
  GET  /api/redteam/mitre             ATT&CK technique counts

  GET  /api/ruflo/summary             ruflo one-shot dashboard
  GET  /api/ruflo/hooks/stats         hooks_pre / hooks_post counters
  GET  /api/ruflo/memory/{stats,search}
  GET  /api/ruflo/patterns[/search]
  GET  /api/ruflo/swarm/status
  GET  /api/ruflo/agents
  GET  /api/ruflo/neural/status

  GET  /api/shell/sessions              list live PTY bash sessions
  POST /api/shell/sessions              spawn a new bash session, returns session_id
  DELETE /api/shell/sessions/{id}       kill one session explicitly

  GET  /api/system/diag                 host capability matrix (binaries + install cmds)
  GET  /api/system/diag/{binary_name}   one binary's status + install command
  POST /api/system/install/{binary_name}  start a background install (returns install_id)
  GET  /api/system/install/{install_id}/status  poll install state + log buffer

  GET  /api/onboard/state               current step + completed steps + detected caps
  POST /api/onboard/choose-path         {"path": "native"|"wsl"|"skip"}
  POST /api/onboard/consent             {"consent_text": "yes i consent"}
  POST /api/onboard/install             {"binaries": ["nmap","nuclei",...]}
  POST /api/onboard/finish              mark onboard complete
  POST /api/onboard/reset               wipe onboard state

WS:
  /ws/scan/{id}                        subscribe to scan:{id}:events
  /ws/shell/{session_id}               bidirectional PTY bridge for bash
  /ws/install/{install_id}             stream install log lines + final frame
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select

from . import installer as _installer
from . import shell as _shell
from .db import AsyncSessionLocal, init_db, session_scope
from .models import Asset, Event, Finding, Scan


# ---------- background task runner ----------
# When Redis + Celery are available, scans run via Celery worker.
# Otherwise (local dev / e2e without Docker), scans run inline on a
# background thread so the API still responds quickly.

try:
    from .celery_app import run_scan_task as _celery_run_scan_task  # type: ignore

    _USE_CELERY = bool(os.getenv("REDIS_URL")) or bool(os.getenv("CELERY_BROKER_URL"))
except Exception:
    _celery_run_scan_task = None
    _USE_CELERY = False


def _dispatch_scan(scan_id: str) -> None:
    if _USE_CELERY and _celery_run_scan_task is not None:
        try:
            _celery_run_scan_task.delay(scan_id)
            return
        except Exception as e:
            print(f"[scan] celery dispatch failed ({e}); running inline")
    # Inline background-thread runner for environments without Celery.
    import threading

    def _runner() -> None:
        try:
            from .orchestrator import run_scan_sync

            run_scan_sync(scan_id)
        except Exception as e:
            print(f"[scan] inline run failed: {e}")

    t = threading.Thread(target=_runner, daemon=True, name=f"scan-{scan_id[:8]}")
    t.start()


REDIS_URL = os.getenv("REDIS_URL", "")


async def _shell_reaper_loop() -> None:
    """Periodic reaper: kill PTY sessions that have been idle for SESSION_TTL_S.

    Runs every 30 s.  A session is considered dead when its bash process
    exits OR when its `last_activity` timestamp is older than the TTL.
    """
    while True:
        try:
            await asyncio.sleep(30)
            now = __import__("time").time()
            for s in list(_shell.list_sessions()):
                sess = _shell.get_session(s["session_id"])
                if not sess:
                    continue
                idle = now - sess.last_activity
                if (not sess.alive) or idle > _shell.SESSION_TTL_S:
                    print(
                        f"[shell-reaper] killing session {sess.session_id[:8]} "
                        f"(alive={sess.alive}, idle={int(idle)}s)"
                    )
                    _shell.kill_session(sess.session_id)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[shell-reaper] error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    reaper_task = asyncio.create_task(_shell_reaper_loop())
    try:
        yield
    finally:
        reaper_task.cancel()
        try:
            await reaper_task
        except (asyncio.CancelledError, Exception):
            pass
        _shell.kill_all()


app = FastAPI(title="Kangal Dashboard API", version="2.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- request/response models ----------

class ScanRequest(BaseModel):
    target: str
    mode: str = "active"  # passive|active|web_only|network_only|full_spectrum


VALID_MODES = {"passive", "active", "web_only", "network_only", "full_spectrum"}


def _scan_to_dict(s: Scan) -> dict:
    return {
        "id": s.id,
        "target": s.target,
        "mode": s.mode,
        "status": s.status,
        "current_stage": s.current_stage,
        "stats": s.stats or {},
        "error": s.error,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
    }


def _asset_to_node(a: Asset) -> dict:
    return {
        "id": a.id,
        "type": a.type,
        "value": a.value,
        "parent_id": a.parent_id,
        "meta": a.meta or {},
        "discovered_by": a.discovered_by,
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "asset_id": f.asset_id,
        "severity": f.severity,
        "vuln_class": f.vuln_class,
        "title": f.title,
        "evidence": f.evidence or {},
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


# ---------- root ----------

@app.get("/")
def root():
    return {"status": "online", "service": "kangal-dashboard", "version": "2.0.0"}


# ---------- scans ----------

@app.post("/api/scan")
def start_scan(req: ScanRequest):
    target = (req.target or "").strip()
    if not target:
        raise HTTPException(400, "target is required")
    mode = (req.mode or "active").lower()
    if mode not in VALID_MODES:
        raise HTTPException(
            400,
            f"mode must be one of {sorted(VALID_MODES)}",
        )

    # Create scan row in a sync session
    scan_id = None
    for s in session_scope():
        sc = Scan(
            id=str(uuid.uuid4()),
            target=target,
            mode=mode,
            status="queued",
            stats={},
        )
        s.add(sc)
        s.flush()
        scan_id = sc.id

    if not scan_id:
        raise HTTPException(500, "could not create scan row")

    # Hand off to Celery (or inline runner if no broker)
    _dispatch_scan(scan_id)
    return {"scan_id": scan_id, "status": "queued", "target": target, "mode": mode}


@app.get("/api/scans")
def list_scans(limit: int = 50):
    out = []
    for s in session_scope():
        rows = s.execute(
            select(Scan).order_by(Scan.started_at.desc()).limit(limit)
        ).scalars()
        out = [_scan_to_dict(r) for r in rows]
    return out


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    for s in session_scope():
        sc = s.get(Scan, scan_id)
        if not sc:
            raise HTTPException(404, "scan not found")
        return _scan_to_dict(sc)
    raise HTTPException(500, "session failed")


@app.get("/api/scan/{scan_id}/assets")
def get_assets(scan_id: str):
    for s in session_scope():
        sc = s.get(Scan, scan_id)
        if not sc:
            raise HTTPException(404, "scan not found")
        rows = s.execute(select(Asset).where(Asset.scan_id == scan_id)).scalars()
        assets = [_asset_to_node(a) for a in rows]
        nodes = [
            {
                "id": a["id"],
                "type": "data",
                "data": {
                    "label": a["value"],
                    "type": a["type"],
                    "discovered_by": a["discovered_by"],
                },
            }
            for a in assets
        ]
        edges = [
            {"id": f"e-{a['parent_id']}-{a['id']}", "source": a["parent_id"], "target": a["id"]}
            for a in assets
            if a["parent_id"]
        ]
        return {"nodes": nodes, "edges": edges, "assets": assets}


@app.get("/api/scan/{scan_id}/findings")
def get_findings(scan_id: str):
    for s in session_scope():
        sc = s.get(Scan, scan_id)
        if not sc:
            raise HTTPException(404, "scan not found")
        rows = s.execute(
            select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at)
        ).scalars()
        return [_finding_to_dict(f) for f in rows]


@app.get("/api/scan/{scan_id}/events")
def get_events(scan_id: str, since: int = 0):
    """Return events (for terminal replay). since: skip first N."""
    for s in session_scope():
        sc = s.get(Scan, scan_id)
        if not sc:
            raise HTTPException(404, "scan not found")
        rows = s.execute(
            select(Event)
            .where(Event.scan_id == scan_id)
            .order_by(Event.id)
            .offset(since)
        ).scalars()
        return [
            {
                "id": e.id,
                "stage": e.stage,
                "level": e.level,
                "message": e.message,
                "ts": e.ts.isoformat() if e.ts else None,
            }
            for e in rows
        ]


def _render_scan_markdown(sc: Scan, assets: list, findings: list, events: list) -> str:
    """Compose a self-contained Markdown report for one scan.

    Used by GET /api/scan/{id}/report.md — drives the Reports view's
    EXPORT / EXPORT ALL buttons. Sections: header, target/mode/status,
    asset counts by type, agent stats, findings (sorted by severity), and
    a tail of error/warn events.
    """
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (sev_order.get(f.severity, 9), f.vuln_class, f.title),
    )

    lines: list[str] = []
    lines.append(f"# Kangal Scan Report — `{sc.target}`")
    lines.append("")
    lines.append(f"- **scan_id**: `{sc.id}`")
    lines.append(f"- **target**: `{sc.target}`")
    lines.append(f"- **mode**: `{sc.mode}`")
    lines.append(f"- **status**: `{sc.status}`")
    if sc.current_stage:
        lines.append(f"- **current_stage**: `{sc.current_stage}`")
    if sc.started_at:
        lines.append(f"- **started_at**: `{sc.started_at.isoformat()}`")
    if sc.finished_at:
        lines.append(f"- **finished_at**: `{sc.finished_at.isoformat()}`")
    if sc.error:
        lines.append(f"- **error**: `{sc.error}`")
    lines.append("")

    # Asset summary
    by_type: dict[str, int] = {}
    for a in assets:
        by_type[a.type] = by_type.get(a.type, 0) + 1
    lines.append("## Assets")
    lines.append("")
    lines.append(f"Total: **{len(assets)}**")
    if by_type:
        lines.append("")
        lines.append("| Type | Count |")
        lines.append("|------|------:|")
        for t, n in sorted(by_type.items(), key=lambda kv: -kv[1]):
            lines.append(f"| `{t}` | {n} |")
    lines.append("")

    # Agent stats (from scan.stats dict)
    stats = sc.stats or {}
    if stats:
        lines.append("## Agent stats")
        lines.append("")
        lines.append("| Agent | OK | Duration (s) | Error |")
        lines.append("|-------|----|--------------|-------|")
        for agent, st in stats.items():
            ok = "✓" if (isinstance(st, dict) and st.get("ok")) else "✗"
            dur = (st.get("duration_s") if isinstance(st, dict) else None) or "—"
            err = (st.get("error") if isinstance(st, dict) else None) or ""
            lines.append(f"| `{agent}` | {ok} | {dur} | {err} |")
        lines.append("")

    # Findings
    lines.append(f"## Findings ({len(findings)})")
    lines.append("")
    if not sorted_findings:
        lines.append("_No findings._")
        lines.append("")
    else:
        lines.append("| Sev | Class | Title | MITRE | Evidence |")
        lines.append("|-----|-------|-------|-------|----------|")
        for f in sorted_findings:
            ev = f.evidence or {}
            mitre = ev.get("mitre_technique") or ev.get("mitre") or "—"
            ev_str = ", ".join(f"{k}={json.dumps(v)[:60]}" for k, v in ev.items()) or "—"
            lines.append(
                f"| `{f.severity}` | `{f.vuln_class}` | {f.title} | `{mitre}` | {ev_str} |"
            )
        lines.append("")
        # Detailed findings list (full evidence JSON per finding)
        lines.append("### Finding details")
        lines.append("")
        for f in sorted_findings:
            ev = f.evidence or {}
            mitre = ev.get("mitre_technique") or ev.get("mitre") or "—"
            lines.append(f"#### [{f.severity.upper()}] {f.title}")
            lines.append("")
            lines.append(f"- **id**: `{f.id}`")
            lines.append(f"- **class**: `{f.vuln_class}`")
            lines.append(f"- **severity**: `{f.severity}`")
            lines.append(f"- **mitre**: `{mitre}`")
            if f.asset_id:
                lines.append(f"- **asset_id**: `{f.asset_id}`")
            if f.created_at:
                lines.append(f"- **created_at**: `{f.created_at.isoformat()}`")
            if ev:
                lines.append("- **evidence**:")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(ev, indent=2, default=str))
                lines.append("```")
                lines.append("")

    # Tail of warn/error events (most recent 20) — useful context without dumping everything
    interesting_events = [e for e in events if e.level in ("warn", "error")][-20:]
    if interesting_events:
        lines.append("## Notable events")
        lines.append("")
        for e in interesting_events:
            ts = e.ts.isoformat() if e.ts else ""
            lines.append(f"- `{ts}` **{e.level.upper()}** [{e.stage}] {e.message}")
        lines.append("")

    lines.append("---")
    lines.append(f"_Generated by Kangal Dashboard at {datetime.utcnow().isoformat()}Z_")
    lines.append("")
    return "\n".join(lines)


@app.get("/api/scan/{scan_id}/report.md")
def scan_report_md(scan_id: str):
    """Markdown report for one scan (target, status, agents, findings).

    Used by the Reports view's EXPORT button. Returns text/markdown so
    `kangal-cli` and curl can pipe it straight to a file.
    """
    for s in session_scope():
        sc = s.get(Scan, scan_id)
        if not sc:
            raise HTTPException(404, "scan not found")
        assets = list(s.execute(select(Asset).where(Asset.scan_id == scan_id)).scalars())
        findings = list(
            s.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars()
        )
        events = list(
            s.execute(
                select(Event).where(Event.scan_id == scan_id).order_by(Event.id)
            ).scalars()
        )
        body = _render_scan_markdown(sc, assets, findings, events)
        return PlainTextResponse(body, media_type="text/markdown; charset=utf-8")
    raise HTTPException(500, "session failed")


# ---------- intel (cross-scan memory + patterns) ----------

@app.get("/api/intel/search")
def intel_search(q: str = Query(..., min_length=1), limit: int = 25):
    """Search the cross-scan intel store.

    The store is fed by orchestrator.run_scan after every scan
    (intel.store_finding for each finding, intel.store_pattern for each
    per-stage outcome). The same role ruflo's memory_store +
    agentdb_pattern-store play — but locally persistent in this service.
    """
    from . import intel

    results = intel.search(q, limit=limit)
    return {"query": q, "results": results, "count": len(results)}


@app.get("/api/intel/patterns")
def intel_patterns(limit: int = 50):
    """Return stored recon patterns (per-agent, per-target) sorted by confidence."""
    from . import intel

    return {"patterns": intel.list_patterns(limit=limit)}


# ---------- ruflo-compatible telemetry + memory surface ----------
#
# Mirrors of the ruflo MCP toolset, exposed as plain REST so the frontend
# can poll them with vanilla fetch(). Backend stores the actual telemetry
# in `ruflo.py` (process memory + small JSON file).
#
# Tools covered:
#   /api/ruflo/summary         — one-shot dashboard
#   /api/ruflo/hooks/stats     — hooks_pre-task / hooks_post-task counters
#   /api/ruflo/memory/stats    — memory_store count + indexed findings
#   /api/ruflo/memory/search   — ruflo memory_search shape
#   /api/ruflo/patterns        — agentdb_pattern-store list
#   /api/ruflo/patterns/search — agentdb_pattern-search shape
#   /api/ruflo/swarm/status    — swarm_init registry
#   /api/ruflo/agents          — agent_spawn catalog
#   /api/ruflo/neural/status   — neural_train trajectory summary

@app.get("/api/ruflo/summary")
def ruflo_summary():
    from . import ruflo

    return ruflo.summary()


@app.get("/api/ruflo/hooks/stats")
def ruflo_hooks_stats():
    from . import ruflo

    return ruflo.hooks_stats()


@app.get("/api/ruflo/memory/stats")
def ruflo_memory_stats():
    from . import ruflo

    return ruflo.memory_stats()


@app.get("/api/ruflo/memory/search")
def ruflo_memory_search(q: str = Query(..., min_length=1), limit: int = 20):
    from . import ruflo

    results = ruflo.memory_search(q, limit=limit)
    return {"query": q, "results": results, "count": len(results)}


@app.get("/api/ruflo/patterns")
def ruflo_patterns(limit: int = 50):
    from . import ruflo

    return {"patterns": ruflo.pattern_search("", limit=limit)}


@app.get("/api/ruflo/patterns/search")
def ruflo_patterns_search(q: str = Query(..., min_length=1), limit: int = 20):
    from . import ruflo

    results = ruflo.pattern_search(q, limit=limit)
    return {"query": q, "results": results, "count": len(results)}


@app.get("/api/ruflo/swarm/status")
def ruflo_swarm_status(swarm_id: str | None = None):
    from . import ruflo

    if swarm_id:
        return ruflo.swarm_status(swarm_id=swarm_id)
    return ruflo.swarm_status()


@app.get("/api/ruflo/agents")
def ruflo_agents():
    from . import ruflo

    return {"agents": ruflo.agent_list(), "count": len(ruflo.agent_list())}


@app.get("/api/ruflo/neural/status")
def ruflo_neural_status():
    from . import ruflo

    return ruflo.neural_status()


# ---------- toolbox: registry + execute ----------

@app.get("/api/toolbox/summary")
def toolbox_summary():
    """Registry summary: how many tools, by tier, by category."""
    from . import tools

    return tools.summary()


@app.get("/api/toolbox/tools")
def toolbox_tools(tier: int | None = None, category: str | None = None):
    """List all known tools. Filterable by tier (1|2) and/or category."""
    from . import tools

    pool = tools.all_tools()
    if tier is not None:
        pool = [t for t in pool if t.tier == tier]
    if category:
        pool = [t for t in pool if t.category == category]
    return {
        "tools": [
            {
                "name": t.name,
                "tier": t.tier,
                "category": t.category,
                "binary": t.binary,
                "timeout_default_s": t.timeout_default_s,
                "rate_limit_per_min": t.rate_limit_per_min,
                "requires_root": t.requires_root,
                "engagement_modes": t.engagement_modes,
                "produces": t.produces,
                "output_format": t.output_format,
            }
            for t in pool
        ],
        "count": len(pool),
    }


@app.get("/api/toolbox/categories")
def toolbox_categories():
    """Distinct (category, tier) buckets — drives the frontend's tab system."""
    from . import tools

    by_cat: dict[str, dict[str, Any]] = {}
    for t in tools.all_tools():
        b = by_cat.setdefault(t.category, {"category": t.category, "tools": 0, "tiers": set()})
        b["tools"] += 1
        b["tiers"].add(t.tier)
    return {
        "categories": [
            {**b, "tiers": sorted(b["tiers"])} for b in by_cat.values()
        ]
    }


class ToolRunRequest(BaseModel):
    tool: str
    target: str = ""
    params: dict[str, Any] | None = None
    scan_id: str = ""
    timeout: int | None = None
    engagement_mode: str | None = None


@app.post("/api/toolbox/execute")
async def toolbox_execute(req: ToolRunRequest):
    """Synchronous tool execution through the Ruflo-instrumented executor.

    Use sparingly — most tools are heavy and the orchestrator should call
    them via Celery. This endpoint is for interactive runs from the
    frontend "Run now" buttons.
    """
    from .services.executor import ToolExecutor

    executor = ToolExecutor()
    result = await executor.run(
        tool_name=req.tool,
        params=req.params or {},
        scan_id=req.scan_id,
        target=req.target,
        timeout=req.timeout,
        engagement_mode=req.engagement_mode,
    )
    return {
        "tool": result.tool,
        "target": result.target,
        "scan_id": result.scan_id,
        "ok": result.ok,
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "scope_violation": result.scope_violation,
        "rate_limited": result.rate_limited,
        "duration_s": result.duration_s,
        "raw_count": result.raw_count,
        "ruflo_pattern_id": result.ruflo_pattern_id,
        "error": result.error,
        "parsed": result.parsed[:50],
        "stdout_excerpt": result.stdout_excerpt,
        "stderr_excerpt": result.stderr_excerpt,
    }


# ---------- engagement manager (scope guard + kill switch) ----------


class EngagementCreate(BaseModel):
    name: str
    client: str
    operator: str
    scope_cidrs: list[str] = []
    scope_domains: list[str] = []
    excluded: list[str] = []
    profile: str = "full_spectrum"
    start_at: float | None = None
    end_at: float | None = None
    destructive_allowed: bool = False


@app.post("/api/engagement")
def engagement_create(req: EngagementCreate):
    from . import ruflo

    eid = ruflo.engagement_create(
        name=req.name,
        client=req.client,
        operator=req.operator,
        scope_cidrs=req.scope_cidrs,
        scope_domains=req.scope_domains,
        excluded=req.excluded,
        profile=req.profile,
        start_at=req.start_at,
        end_at=req.end_at,
        destructive_allowed=req.destructive_allowed,
    )
    return {"id": eid, "status": "active"}


@app.get("/api/engagement")
def engagement_list():
    from . import ruflo

    return ruflo.engagement_status()


@app.get("/api/engagement/{eid}")
def engagement_get(eid: str):
    from . import ruflo

    e = ruflo.engagement_status(eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    return e


@app.delete("/api/engagement/{eid}")
def engagement_stop(eid: str, reason: str = "manual"):
    from . import ruflo

    ruflo.engagement_stop(eid, reason=reason)
    return {"id": eid, "status": "stopped"}


@app.post("/api/engagement/{eid}/panic")
def engagement_panic(eid: str):
    """Kill switch. Stops the engagement and all its running swarms."""
    from . import ruflo

    result = ruflo.engagement_panic(eid)
    return result


class ScopeCheckRequest(BaseModel):
    target: str
    engagement_id: str | None = None


@app.post("/api/engagement/scope-check")
def engagement_scope_check(req: ScopeCheckRequest):
    """Returns whether a given target is in the engagement's scope.

    Uses the global SCOPE_CIDRS / SCOPE_DOMAINS env vars unless an
    engagement_id is provided, in which case the engagement's scope wins.
    """
    from .services.executor import _in_scope

    e = None
    if req.engagement_id:
        from . import ruflo

        e = ruflo.engagement_status(req.engagement_id)
        if not e:
            raise HTTPException(404, "engagement not found")

    target = (req.target or "").strip()
    if not target:
        return {"target": target, "in_scope": False, "reason": "empty target"}

    if e:
        # explicit scope from engagement record
        cidrs = e.get("scope_cidrs", [])
        domains = e.get("scope_domains", [])
        excluded = e.get("excluded", []) or []
        if any(target == x or target.endswith("." + x) for x in excluded):
            return {"target": target, "in_scope": False, "reason": "explicitly excluded"}
        # naive domain match
        ok = any(target.endswith("." + d) or target == d for d in domains)
        return {
            "target": target,
            "in_scope": ok,
            "reason": "matched engagement domain" if ok else "not in any engagement domain",
        }

    in_scope = _in_scope(target)
    return {
        "target": target,
        "in_scope": in_scope,
        "reason": "matched env scope" if in_scope else "no scope configured / out of scope",
    }


# ---------- red team event sinks (exploit / creds / lateral / persistence) ----------


class ExploitAttemptRequest(BaseModel):
    scan_id: str
    target: str
    technique: str
    payload_id: str | None = None
    success: bool = False
    severity: str = "info"
    evidence: dict[str, Any] | None = None
    mitre_technique: str | None = None


@app.post("/api/redteam/exploit-attempt")
def redteam_exploit_attempt(req: ExploitAttemptRequest):
    from . import ruflo

    aid = ruflo.exploit_attempt(
        scan_id=req.scan_id,
        target=req.target,
        technique=req.technique,
        payload_id=req.payload_id,
        success=req.success,
        severity=req.severity,
        evidence=req.evidence,
        mitre_technique=req.mitre_technique,
    )
    return {"id": aid, "ok": True}


class CredentialRequest(BaseModel):
    scan_id: str
    target: str
    service: str
    username: str
    secret_hash: str  # hashed / encrypted locally — never plaintext
    source: str


@app.post("/api/redteam/credential")
def redteam_credential(req: CredentialRequest):
    from . import ruflo

    cid = ruflo.credential_discovered(
        scan_id=req.scan_id,
        target=req.target,
        service=req.service,
        username=req.username,
        secret_hash=req.secret_hash,
        source=req.source,
    )
    return {"id": cid, "ok": True}


class LateralPathRequest(BaseModel):
    scan_id: str
    from_host: str
    to_host: str
    via_service: str
    credential_ref: str | None = None


@app.post("/api/redteam/lateral-path")
def redteam_lateral_path(req: LateralPathRequest):
    from . import ruflo

    lid = ruflo.lateral_path_identified(
        scan_id=req.scan_id,
        from_host=req.from_host,
        to_host=req.to_host,
        via_service=req.via_service,
        credential_ref=req.credential_ref,
    )
    return {"id": lid, "ok": True}


class PersistenceRequest(BaseModel):
    scan_id: str
    target: str
    kind: str
    detail: str


@app.post("/api/redteam/persistence")
def redteam_persistence(req: PersistenceRequest):
    from . import ruflo

    pid = ruflo.persistence_detected(
        scan_id=req.scan_id,
        target=req.target,
        kind=req.kind,
        detail=req.detail,
    )
    return {"id": pid, "ok": True}


class C2BeaconRequest(BaseModel):
    scan_id: str
    target: str
    indicator: str
    destination: str
    pattern: str


@app.post("/api/redteam/c2-beacon")
def redteam_c2_beacon(req: C2BeaconRequest):
    from . import ruflo

    bid = ruflo.c2_beacon_detected(
        scan_id=req.scan_id,
        target=req.target,
        indicator=req.indicator,
        destination=req.destination,
        pattern=req.pattern,
    )
    return {"id": bid, "ok": True}


@app.get("/api/redteam/mitre")
def redteam_mitre():
    from . import ruflo

    return ruflo.mitre_summary()


# ---------- system diagnostics (host + tool availability) ----------


@app.get("/api/system/diag")
def system_diag():
    """Full capability matrix: host info + every binary's status."""
    from . import diagnostics

    return diagnostics.detect_all_sync()


@app.get("/api/system/diag/{binary_name}")
def system_diag_one(binary_name: str):
    """One binary's status + platform-appropriate install command."""
    from . import diagnostics

    info = diagnostics.detect_one(binary_name)
    if not info:
        raise HTTPException(404, f"unknown binary: {binary_name}")
    return info


# ---------- system installer (background install + WS progress) ----------


@app.post("/api/system/install/{binary_name}")
def start_install(binary_name: str, background: bool = True):
    """Start a background install of *binary_name*.

    Refuses sudo/install commands when the host is not admin, and refuses
    when the install concurrency cap is full (the job is still created so
    the caller can surface a 429 with a useful payload).
    """
    cmd = _installer.install_command_for(binary_name)
    if not cmd:
        raise HTTPException(404, f"no install command for {binary_name} on this platform")
    if _installer.needs_root(cmd) and not _installer.is_admin():
        raise HTTPException(
            403,
            (
                f"install command for {binary_name} requires root/admin "
                f"({' '.join(cmd)[:80]}). Re-run the backend as root, "
                f"or pre-install {binary_name} manually."
            ),
        )
    job = _installer.start_install(binary_name)
    if not job:
        raise HTTPException(404, f"no install command for {binary_name} on this platform")
    s = job.summary()
    # Concurrency cap exhausted — start_install created a job but
    # immediately failed it. Surface as 429.
    if s["status"] == "failed" and "concurrency limit" in (s.get("error") or ""):
        raise HTTPException(429, s["error"])
    return s


@app.get("/api/system/install/{install_id}/status")
def install_status(install_id: str):
    job = _installer.get_job(install_id)
    if not job:
        raise HTTPException(404, "install not found")
    return job.summary()


@app.websocket("/ws/install/{install_id}")
async def ws_install(websocket: WebSocket, install_id: str):
    """Stream install log lines as text frames, then a final done frame.

    Wire protocol (text frames, JSON):
      server -> client:
        {kind:"log",  line:"..."}
        {kind:"done", status:"ok"|"failed", exit_code:N}
        {kind:"error", message:"..."}
    """
    await websocket.accept()
    job = _installer.get_job(install_id)
    if not job:
        await websocket.send_text(json.dumps({"kind": "error", "message": "install not found"}))
        await websocket.close()
        return

    # Replay everything we already have so the client never misses a line.
    for line in list(job.log):
        await websocket.send_text(json.dumps({"kind": "log", "line": line}))
    if job.status in ("ok", "failed"):
        await websocket.send_text(
            json.dumps({"kind": "done", "status": job.status, "exit_code": job.exit_code})
        )
        await websocket.close()
        return

    # Otherwise poll job.new_lines until the job finishes.
    try:
        while job.status == "running":
            await asyncio.sleep(0.5)
            while job.new_lines:
                line = job.new_lines.popleft()
                await websocket.send_text(json.dumps({"kind": "log", "line": line}))
        # Final drain of anything queued in the last half-second.
        while job.new_lines:
            line = job.new_lines.popleft()
            await websocket.send_text(json.dumps({"kind": "log", "line": line}))
        await websocket.send_text(
            json.dumps({"kind": "done", "status": job.status, "exit_code": job.exit_code})
        )
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[ws_install] error: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ---------- websocket: per-scan live events ----------

@app.websocket("/ws/scan/{scan_id}")
async def ws_scan_events(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    # Confirm scan exists
    exists = False
    for s in session_scope():
        exists = s.get(Scan, scan_id) is not None
    if not exists:
        await websocket.send_text(json.dumps({"kind": "error", "message": "scan not found"}))
        await websocket.close()
        return

    channel = f"scan:{scan_id}:events"
    # Use the same broker the agents publish to (Redis if available, else in-memory)
    from .agents.base import _redis as _broker  # type: ignore
    pubsub = _broker.pubsub()
    pubsub.subscribe(channel)

    # Replay prior events from DB so the client gets the full history on connect
    for s in session_scope():
        rows = s.execute(
            select(Event).where(Event.scan_id == scan_id).order_by(Event.id)
        ).scalars()
        for e in rows:
            await websocket.send_text(
                json.dumps(
                    {
                        "kind": "event",
                        "stage": e.stage,
                        "level": e.level,
                        "message": e.message,
                        "ts": e.ts.isoformat() if e.ts else None,
                        "replay": True,
                    },
                    default=str,
                )
            )

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            data = message["data"]
            if isinstance(data, bytes):
                data = data.decode("utf-8", errors="replace")
            await websocket.send_text(data)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[ws_scan_events] error: {e}")
    finally:
        try:
            pubsub.unsubscribe(channel)
        except Exception:
            pass
        try:
            pubsub.close()
        except Exception:
            pass


# ---------- interactive shell (PTY-backed bash) ----------


class ShellCreateRequest(BaseModel):
    cols: int = _shell.DEFAULT_COLS
    rows: int = _shell.DEFAULT_ROWS


@app.post("/api/shell/sessions")
def shell_create(req: ShellCreateRequest):
    """Spawn a new bash process under a fresh PTY.

    Returns the session_id the client uses to open `/ws/shell/{id}`.
    The session outlives the WebSocket connection so an operator can
    disconnect and reconnect without losing the bash process.
    """
    if not _shell.is_supported():
        raise HTTPException(
            501,
            "Interactive shell requires a POSIX host (forkpty). "
            "Run the backend in Docker / WSL / Linux, not native Windows.",
        )
    try:
        sess = _shell.create_session(cols=req.cols, rows=req.rows)
    except _shell.ShellUnsupported as e:
        raise HTTPException(501, str(e))
    except Exception as e:
        raise HTTPException(500, f"failed to spawn shell: {e}")
    return {
        "session_id": sess.session_id,
        "cols": sess.cols,
        "rows": sess.rows,
        "created_at": sess.created_at,
    }


@app.get("/api/shell/sessions")
def shell_list():
    """List live PTY sessions (debug)."""
    return {"sessions": _shell.list_sessions(), "count": len(_shell.list_sessions())}


@app.delete("/api/shell/sessions/{session_id}")
def shell_kill(session_id: str):
    """Kill one session explicitly (e.g. when the user clicks KILL)."""
    if not _shell.kill_session(session_id):
        raise HTTPException(404, "session not found")
    return {"session_id": session_id, "status": "killed"}


@app.websocket("/ws/shell/{session_id}")
async def ws_shell(websocket: WebSocket, session_id: str):
    """Bidirectional PTY bridge.

    Wire protocol (text frames, JSON):
      client → server:
        {kind:"data",   data:"<b64>"}     # keystrokes
        {kind:"resize", cols:N, rows:N}    # xterm fit
        {kind:"ping"}                      # liveness
      server → client:
        {kind:"open",   session_id, cols, rows}
        {kind:"out",    data:"<b64>"}      # PTY stdout (xterm)
        {kind:"exit",   code}
        {kind:"error",  message}
        {kind:"pong"}

    The PTY is NOT killed on WebSocket disconnect — the bash survives
    in case the operator reconnects.  Lifespan reaper collects zombies
    after SESSION_TTL_S (15 min idle).
    """
    await websocket.accept()
    sess = _shell.get_session(session_id)
    if not sess:
        await websocket.send_text(json.dumps({"kind": "error", "message": "session not found"}))
        await websocket.close()
        return

    sess.touch()
    await websocket.send_text(
        json.dumps(
            {"kind": "open", "session_id": sess.session_id, "cols": sess.cols, "rows": sess.rows}
        )
    )

    loop = asyncio.get_event_loop()
    reader_task: Optional[asyncio.Task] = None

    async def _pump_pty_to_ws() -> None:
        """Background task: read PTY → send {kind:"out", data:<b64>}."""
        while True:
            try:
                chunk = await loop.run_in_executor(None, sess.read, 4096)
            except Exception:
                chunk = b""
            if not chunk:
                # Process exited
                code = 0
                try:
                    code = sess.proc.exitstatus or 0
                except Exception:
                    code = 0
                try:
                    await websocket.send_text(json.dumps({"kind": "exit", "code": code}))
                except Exception:
                    pass
                _shell.kill_session(sess.session_id)
                return
            try:
                await websocket.send_text(
                    json.dumps({"kind": "out", "data": _shell.b64e(chunk)})
                )
            except Exception:
                return

    reader_task = asyncio.create_task(_pump_pty_to_ws())

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            kind = msg.get("kind")
            if kind == "ping":
                sess.touch()
                await websocket.send_text(json.dumps({"kind": "pong"}))
            elif kind == "resize":
                sess.touch()
                cols = int(msg.get("cols", sess.cols))
                rows = int(msg.get("rows", sess.rows))
                try:
                    sess.set_winsize(cols, rows)
                except Exception:
                    pass
            elif kind == "data":
                sess.touch()
                try:
                    sess.write(_shell.b64d(msg.get("data", "")))
                except Exception:
                    pass
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[ws_shell] error: {e}")
    finally:
        if reader_task and not reader_task.done():
            reader_task.cancel()
            try:
                await reader_task
            except (asyncio.CancelledError, Exception):
                pass


# ---------- onboarding state machine ----------


class OnboardChoosePath(BaseModel):
    path: str


class OnboardConsent(BaseModel):
    consent_text: str


class OnboardInstall(BaseModel):
    binaries: list[str] = []


@app.get("/api/onboard/state")
def onboard_state():
    """Current step + completed steps + detected capabilities.

    Drives the wizard UI: the frontend reads `current_step` to know
    which panel to show, and `completed_steps` for the progress bar.
    """
    from . import onboard

    return onboard.snapshot()


@app.post("/api/onboard/choose-path")
def onboard_choose_path(req: OnboardChoosePath):
    """Record the user's chosen install path (native / wsl / skip)."""
    from . import onboard

    try:
        return onboard.choose_path(req.path)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/onboard/consent")
def onboard_consent(req: OnboardConsent):
    """Record legal consent. Body must contain 'yes' AND 'consent' (case-insensitive)."""
    from . import onboard

    try:
        return onboard.record_consent(req.consent_text)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/onboard/install")
def onboard_install(req: OnboardInstall):
    """Kick off installs for the requested binaries. Returns one entry per binary."""
    from . import onboard

    return onboard.start_installs(req.binaries)


@app.post("/api/onboard/finish")
def onboard_finish():
    """Mark onboard complete (mirrors the frontend's localStorage flag)."""
    from . import onboard

    return onboard.finish()


@app.post("/api/onboard/reset")
def onboard_reset():
    """Wipe onboard state — useful for testing / re-running the wizard."""
    from . import onboard

    return onboard.reset()


# ---------- threat intel (live CVE + MITRE ATT&CK feed) ----------
#
# Backed by app/threat_intel.py. In-memory + on-disk cache (TTL per resource
# type). Returns stale=True when the live fetch failed but a cached copy was
# served; returns 503 with a clear message if neither live nor cache exists.


@app.get("/api/threat-intel/cve/{cve_id}")
async def threat_intel_cve(cve_id: str):
    """Return a single CVE from NVD (description, CVSS v3/v2, references, dates)."""
    from . import threat_intel

    raw = await threat_intel.fetch_nvd_cve(cve_id)
    if raw is None:
        # Neither live nor cached.
        raise HTTPException(
            503,
            (
                f"CVE intel unavailable for {cve_id}: no cached copy and live "
                "NVD fetch failed. Pre-seed the cache (backend/.cache/) or "
                "check outbound network."
            ),
        )
    # fetch_nvd_cve returns the cached payload even when stale; the caller
    # can't tell them apart from the dict alone. Mark stale=True when the
    # only available copy is older than the per-CVE TTL.
    from time import time as _now

    from .threat_intel import cache_load_with_meta as _clwm

    _, ts, _ = _clwm(f"nvd-{cve_id.strip().upper()}.json")
    stale = ts and (_now() - ts) > threat_intel.TTL_CVE_DETAIL
    normalized = threat_intel.cve_to_threat(raw, stale=stale)
    if normalized is None:
        raise HTTPException(404, f"CVE not found: {cve_id}")
    return normalized


@app.get("/api/threat-intel/recent-cves")
async def threat_intel_recent_cves(
    days: int = Query(7, ge=1, le=30),
    severity: str = Query("high"),
):
    """Return recent CVEs from NVD (last *days* days, filtered to *severity* and up)."""
    from . import threat_intel

    sev = severity.strip().upper()
    if sev not in threat_intel._SEVERITY_RANK:
        raise HTTPException(400, f"severity must be one of low|medium|high|critical (got {severity!r})")

    try:
        items = await threat_intel.fetch_nvd_recent(days=days, severity=sev)
    except threat_intel.ThreatIntelFetchError as e:
        raise HTTPException(503, f"Recent CVE feed unavailable: {e}")
    if not items:
        # Distinguish "live worked but NVD returned nothing matching" vs
        # "live failed AND no cache". We can detect the latter via cache_load.
        cache_key = f"nvd-recent-{days}d-{sev}.json"
        cached, _ts, _ = threat_intel.cache_load_with_meta(cache_key)
        if not cached:
            raise HTTPException(
                503,
                (
                    "Recent CVE feed unavailable: live NVD fetch succeeded but "
                    "returned no CVEs matching the severity filter, and no "
                    "cached copy exists."
                ),
            )

    out = [threat_intel.cve_to_threat(v) for v in items]
    out = [x for x in out if x]
    return {
        "window_days": days,
        "severity": sev,
        "count": len(out),
        "cves": out,
    }


@app.get("/api/threat-intel/mitre/{technique_id}")
async def threat_intel_mitre_technique(technique_id: str):
    """Return one MITRE ATT&CK technique (T1190 etc.) — name, tactics, mitigations, examples."""
    from . import threat_intel

    bundle = await threat_intel.fetch_mitre_bundle()
    if not bundle:
        raise HTTPException(
            503,
            (
                "MITRE ATT&CK bundle unavailable: no cached copy and live "
                "fetch failed. Pre-seed backend/.cache/mitre-enterprise.json or "
                "check outbound network."
            ),
        )
    tech = threat_intel.find_mitre_technique(bundle, technique_id)
    if tech is None:
        raise HTTPException(404, f"MITRE technique not found: {technique_id}")
    normalized = threat_intel.mitre_to_threat(tech, bundle)
    if normalized is None:
        raise HTTPException(404, f"MITRE technique not found: {technique_id}")
    return normalized


@app.get("/api/threat-intel/mitre/search")
async def threat_intel_mitre_search(
    q: str = Query(..., min_length=2),
    limit: int = Query(25, ge=1, le=100),
):
    """Substring search across MITRE technique names + descriptions."""
    from . import threat_intel

    bundle = await threat_intel.fetch_mitre_bundle()
    if not bundle:
        raise HTTPException(
            503,
            (
                "MITRE ATT&CK bundle unavailable: no cached copy and live "
                "fetch failed. Pre-seed backend/.cache/mitre-enterprise.json or "
                "check outbound network."
            ),
        )
    hits = threat_intel.search_mitre(bundle, q, limit=limit)
    normalized = [threat_intel.mitre_to_threat(h, bundle) for h in hits]
    normalized = [n for n in normalized if n]
    return {"query": q, "count": len(normalized), "techniques": normalized}


@app.get("/api/threat-intel/feed")
async def threat_intel_feed(
    refresh: bool = Query(False),
    days: int = Query(7, ge=1, le=30),
    severity: str = Query("high"),
):
    """Combined feed: recent CVEs (last *days* d, severity ≥ *severity*) + top MITRE techniques."""
    from . import threat_intel

    sev = severity.strip().upper()
    if sev not in threat_intel._SEVERITY_RANK:
        raise HTTPException(400, f"severity must be one of low|medium|high|critical (got {severity!r})")

    feed = await threat_intel.threat_intel_feed(refresh=refresh, days=days, severity=sev)
    # If both sections came back empty AND we have no cache, surface 503.
    cache_key = "threat-intel-feed.json"
    cached, _ts, _ = threat_intel.cache_load_with_meta(cache_key)
    if (
        not cached
        and not feed.get("recent_cves")
        and not feed.get("mitre_techniques")
    ):
        raise HTTPException(
            503,
            (
                "Threat-intel feed unavailable: live fetch failed for both "
                "NVD and MITRE, and no cached copy exists. Check outbound "
                "network or pre-seed backend/.cache/."
            ),
        )
    resp = JSONResponse(feed)
    # Spec: 5-minute browser cache for the combined feed.
    resp.headers["Cache-Control"] = "max-age=300"
    return resp
