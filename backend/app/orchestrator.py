"""Recon orchestrator.

The single entry point for a scan. It:
1. opens its own DB session
2. creates the root asset for the target
3. runs each agent sequentially in the same session
4. updates the scan's `current_stage` + `status` + `stats`
5. writes a `scan_completed` event when done

Agents are async; the orchestrator runs them one at a time (most have
internal parallelism — http_probe, portscan — so the pipeline stays
fast enough for one-host scans).

Toolbox v2: the orchestrator picks up extra agents (exploit / network /
cloud / osint) based on the scan's engagement mode. Modes supported:
  - passive        : OSINT only (subfinder, amass-passive, harvester, …)
  - active         : OSINT + web exploits (sqlmap, dalfox, …) [default]
  - web_only       : web exploits + recon only
  - network_only   : smb / ssh / AD agents
  - full_spectrum  : everything that the engagement profile allows
"""
from __future__ import annotations

import asyncio
from datetime import datetime

from sqlalchemy import select

from .agents import CORE_PIPELINE, AgentContext, agents_by_mode
from .db import session_scope
from .models import Asset, Scan


def pipeline_for_mode(mode: str) -> list:
    """Return the list of agent classes to run for a given engagement mode.

    Core recon agents always run first (subdomain → dns → http → port →
    tech → path → vuln). Toolbox agents are appended after.
    """
    core = list(CORE_PIPELINE)
    toolbox = agents_by_mode(mode)
    # dedup + preserve order
    seen: set = set()
    out: list = []
    for cls in core + toolbox:
        key = cls.__name__
        if key in seen:
            continue
        seen.add(key)
        out.append(cls)
    return out


def _is_ip(target: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def run_scan_sync(scan_id: str) -> None:
    """Blocking runner, used by Celery."""
    asyncio.run(run_scan(scan_id))


async def run_scan(scan_id: str) -> None:
    """Async runner. Each agent shares the same session.

    Failure in any single agent logs an error and continues (the
    orchestrator never aborts the whole scan because of one bad stage).
    """
    for s in session_scope():
        scan: Scan | None = s.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.started_at = scan.started_at or datetime.utcnow()
        s.flush()

        # 1. Create root asset for the target (parent=None)
        root_value = scan.target
        existing = s.execute(
            select(Asset).where(Asset.scan_id == scan_id, Asset.parent_id.is_(None))
        ).scalar_one_or_none()
        if not existing:
            root = Asset(
                scan_id=scan_id,
                type="ip" if _is_ip(root_value) else "domain",
                value=root_value,
                parent_id=None,
                meta={"is_root": True},
                discovered_by="orchestrator",
            )
            s.add(root)
            s.flush()

        # Pick the agent pipeline based on engagement mode
        pipeline = pipeline_for_mode(scan.mode)
        ctx = AgentContext(
            scan_id=scan_id,
            target=scan.target,
            mode=scan.mode,
            db=s,
        )

        ctx.info(
            "orchestrator",
            f"Pipeline started for {scan.target} (mode={scan.mode}, agents={len(pipeline)})",
        )

        stats: dict = {"agents": {}, "pipeline": [a.__name__ for a in pipeline]}

        # Ruflo mirror: register a swarm for this scan (topology = hierarchical-mesh).
        try:
            from . import ruflo

            ruflo.swarm_init(
                scan_id=scan_id,
                target=scan.target,
                mode=scan.mode,
                max_agents=len(pipeline),
            )
        except Exception as e:
            ctx.warn("orchestrator", f"ruflo.swarm_init failed: {e}")

        for agent_cls in pipeline:
            agent = agent_cls()
            scan.current_stage = agent.name
            s.flush()
            ctx.info("orchestrator", f"--- stage: {agent.name} ---")

            # Ruflo mirror: hooks_pre-task telemetry.
            try:
                from . import ruflo

                ruflo.hook_pre(agent.name)
            except Exception:
                pass

            t0 = datetime.utcnow()
            try:
                await agent.run(ctx)
                dur = (datetime.utcnow() - t0).total_seconds()
                stats["agents"][agent.name] = {"ok": True, "duration_s": round(dur, 2)}
            except Exception as e:
                dur = (datetime.utcnow() - t0).total_seconds()
                stats["agents"][agent.name] = {"ok": False, "error": str(e)[:300], "duration_s": round(dur, 2)}
                ctx.error(agent.name, f"agent failed: {e}")
            s.flush()

            # Ruflo mirror: hooks_post-task + neural_train trajectory step.
            try:
                from . import ruflo

                ruflo.hook_post(agent.name)
                ruflo.neural_train(
                    agent=agent.name,
                    scan_id=scan_id,
                    target=scan.target,
                    ok=stats["agents"][agent.name].get("ok", False),
                    duration_s=stats["agents"][agent.name].get("duration_s", 0.0),
                )
            except Exception:
                pass

        # Stats summary
        from .models import Asset as A, Finding as F
        a_count = s.execute(select(A).where(A.scan_id == scan_id)).scalars().all()
        f_count = s.execute(select(F).where(F.scan_id == scan_id)).scalars().all()
        stats["assets_total"] = len(a_count)
        stats["findings_total"] = len(f_count)

        # Persist findings + per-agent patterns to the cross-scan intel store.
        try:
            from . import intel

            for f in f_count:
                intel.store_finding(
                    scan_id,
                    {
                        "severity": f.severity,
                        "vuln_class": f.vuln_class,
                        "title": f.title,
                        "evidence": f.evidence,
                    },
                )

            for name, st in stats.get("agents", {}).items():
                conf = 0.95 if st.get("ok") else 0.15
                intel.store_pattern(
                    agent=name,
                    target=scan.target,
                    outcome=("ok" if st.get("ok") else "fail")
                    + f" ({st.get('duration_s', 0)}s)",
                    confidence=conf,
                )
        except Exception as e:
            ctx.warn("orchestrator", f"intel persist failed: {e}")

        scan.stats = stats
        scan.status = "completed"
        scan.finished_at = datetime.utcnow()
        s.flush()
        ctx.success(
            "orchestrator",
            f"Pipeline complete: {stats['assets_total']} assets, {stats['findings_total']} findings",
        )

        # Ruflo mirror: mark the scan's swarm as completed.
        try:
            from . import ruflo

            ruflo.swarm_set_status(f"swarm-{scan_id[:8]}", "completed")
        except Exception:
            pass
