"""Base agent + shared AgentContext.

The context owns all I/O: logging to DB+Redis, asset/finding persistence,
prior-stage asset lookup. Agents stay pure: they call ctx.* and return
whatever raw intel they discovered; ctx is the only thing that talks to
the outside world (besides the tools each agent uses).

Redis is optional — if REDIS_URL is unreachable (local dev / e2e), an
in-process pub/sub broker is used instead. The WebSocket handler reads
from the same broker.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Optional

import redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import session_scope
from ..models import Asset, Event, Finding, Scan


REDIS_URL = os.getenv("REDIS_URL", "")


# ---------- pub/sub broker (Redis with in-process fallback) ----------

class _InMemoryBroker:
    """Drop-in replacement for the redis client used by publish_event.

    Each channel keeps a deque of the last N events. WebSocket clients
    can `subscribe(channel)` to get a queue and `listen()` on it for new
    messages — same surface as redis.client.PubSub.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._channels: dict[str, list] = defaultdict(list)
        self._subscribers: dict[str, list[list[str]]] = defaultdict(list)

    def publish(self, channel: str, message: str) -> int:
        with self._lock:
            self._channels[channel].append(message)
            self._channels[channel] = self._channels[channel][-500:]
            subs = list(self._subscribers.get(channel, []))
        for q in subs:
            try:
                q.append(message)
            except Exception:
                pass
        return len(subs)

    def pubsub(self) -> "_InMemoryPubSub":
        return _InMemoryPubSub(self)


class _InMemoryPubSub:
    def __init__(self, broker: _InMemoryBroker) -> None:
        self._broker = broker
        self._queue: list[str] = []
        self._channel: str | None = None

    def subscribe(self, channel: str) -> None:
        self._channel = channel
        with self._broker._lock:
            self._broker._subscribers[channel].append(self._queue)
            # Replay buffered messages
            for msg in self._broker._channels.get(channel, []):
                self._queue.append(msg)

    def unsubscribe(self, channel: str) -> None:
        with self._broker._lock:
            subs = self._broker._subscribers.get(channel, [])
            if self._queue in subs:
                subs.remove(self._queue)

    async def listen(self):
        import asyncio
        last = 0
        while True:
            if self._queue:
                msg = self._queue[-1]
                self._queue.clear()
                yield {"type": "message", "data": msg}
            await asyncio.sleep(0.1)
            last += 1

    def close(self) -> None:
        if self._channel:
            with self._broker._lock:
                subs = self._broker._subscribers.get(self._channel, [])
                if self._queue in subs:
                    subs.remove(self._queue)


_redis: Any
if REDIS_URL:
    try:
        _redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        _redis_client.ping()
        _redis = _redis_client
        print(f"[base] redis connected: {REDIS_URL}")
    except Exception as e:
        print(f"[base] redis unreachable ({e}); falling back to in-memory broker")
        _redis = _InMemoryBroker()
else:
    print("[base] REDIS_URL not set; using in-memory broker")
    _redis = _InMemoryBroker()


def channel_for(scan_id: str) -> str:
    return f"scan:{scan_id}:events"


def publish_event(scan_id: str, payload: dict[str, Any]) -> None:
    """Publish a JSON event line to Redis for the per-scan WebSocket subscribers."""
    try:
        _redis.publish(channel_for(scan_id), json.dumps(payload, default=str))
    except Exception as e:  # pragma: no cover - best-effort
        print(f"[publish_event] redis failed: {e}")


@dataclass
class AgentContext:
    """Shared context for one scan run. All agents see the same instance."""
    scan_id: str
    target: str
    mode: str  # "passive" or "active"
    db: Session

    # ---------- logging ----------
    def log(self, stage: str, level: str, message: str) -> None:
        e = Event(scan_id=self.scan_id, stage=stage, level=level, message=message)
        self.db.add(e)
        self.db.flush()
        publish_event(
            self.scan_id,
            {
                "kind": "event",
                "stage": stage,
                "level": level,
                "message": message,
                "ts": e.ts.isoformat() if e.ts else None,
            },
        )

    def info(self, stage: str, msg: str) -> None:
        self.log(stage, "info", msg)

    def success(self, stage: str, msg: str) -> None:
        self.log(stage, "success", msg)

    def warn(self, stage: str, msg: str) -> None:
        self.log(stage, "warn", msg)

    def error(self, stage: str, msg: str) -> None:
        self.log(stage, "error", msg)

    # ---------- asset / finding storage ----------
    def store_asset(
        self,
        type_: str,
        value: str,
        discovered_by: str,
        parent_id: Optional[str] = None,
        meta: Optional[dict[str, Any]] = None,
    ) -> str:
        # de-dupe within a scan: same (type, value) is reused
        stmt = (
            select(Asset)
            .where(Asset.scan_id == self.scan_id)
            .where(Asset.type == type_)
            .where(Asset.value == value)
        )
        existing = self.db.execute(stmt).scalar_one_or_none()
        if existing:
            # merge meta
            if meta:
                existing.meta = {**existing.meta, **meta}
            self.db.flush()
            return existing.id

        a = Asset(
            scan_id=self.scan_id,
            type=type_,
            value=value,
            parent_id=parent_id,
            meta=meta or {},
            discovered_by=discovered_by,
        )
        self.db.add(a)
        self.db.flush()
        return a.id

    def store_finding(
        self,
        severity: str,
        vuln_class: str,
        title: str,
        asset_id: Optional[str] = None,
        evidence: Optional[dict[str, Any]] = None,
    ) -> str:
        f = Finding(
            scan_id=self.scan_id,
            asset_id=asset_id,
            severity=severity,
            vuln_class=vuln_class,
            title=title,
            evidence=evidence or {},
        )
        self.db.add(f)
        self.db.flush()
        return f.id

    # ---------- reads ----------
    def get_target_asset(self) -> Asset:
        """The root asset representing the scan target itself (created by orchestrator)."""
        stmt = (
            select(Asset)
            .where(Asset.scan_id == self.scan_id)
            .where(Asset.parent_id.is_(None))
        )
        return self.db.execute(stmt).scalar_one()

    def assets_by_type(self, type_: str) -> list[Asset]:
        stmt = (
            select(Asset)
            .where(Asset.scan_id == self.scan_id)
            .where(Asset.type == type_)
        )
        return list(self.db.execute(stmt).scalars())

    def all_assets(self) -> list[Asset]:
        stmt = select(Asset).where(Asset.scan_id == self.scan_id)
        return list(self.db.execute(stmt).scalars())


class BaseAgent:
    """Override `name` and `run`."""
    name: str = "base"

    async def run(self, ctx: AgentContext) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    # ---------- shared tool execution (toolbox v2) ----------

    async def run_tool(self, ctx: AgentContext, tool: str, params: dict | None = None,
                       target: str = "", timeout: int | None = None,
                       mode: str | None = None) -> dict[str, Any]:
        """Run a single tool through ToolExecutor and adapt the result.

        Returns a dict with: ok, returncode, duration_s, raw_count, assets,
        findings, error. Agent decides whether to call ctx.store_asset /
        ctx.store_finding for each entry.
        """
        from ..services.executor import ToolExecutor
        from ..services.adapters import adapt

        executor = ToolExecutor(engagement_mode=mode or ctx.mode)
        params = params or {}
        target = target or ctx.target
        result = await executor.run(
            tool_name=tool,
            params=params,
            scan_id=ctx.scan_id,
            target=target,
            timeout=timeout,
            engagement_mode=mode,
        )
        adapter_result = adapt(tool, result.parsed, result.stdout_excerpt, target)

        # Persist discovered assets/findings via ctx
        asset_ids_by_value: dict[str, str] = {}
        for a in adapter_result.assets:
            asset_id = ctx.store_asset(
                type_=a.get("type", "endpoint"),
                value=a.get("value", ""),
                discovered_by=adapter_result.agent_name or tool,
                meta=a.get("meta") or {},
            )
            if a.get("parent_value"):
                parent_id = ctx.store_asset(
                    type_="host",
                    value=a["parent_value"],
                    discovered_by=adapter_result.agent_name or tool,
                )
                ctx.store_asset(
                    type_=a.get("type", "endpoint"),
                    value=a.get("value", ""),
                    discovered_by=adapter_result.agent_name or tool,
                    parent_id=parent_id,
                    meta=a.get("meta") or {},
                )
            asset_ids_by_value[a.get("value", "")] = asset_id

        for f in adapter_result.findings:
            ctx.store_finding(
                severity=f.get("severity", "info"),
                vuln_class=f.get("vuln_class", "toolbox"),
                title=f.get("title", "toolbox finding"),
                asset_id=asset_ids_by_value.get(target),
                evidence=f.get("evidence") or {},
            )

        # Ruflo event sinks for red-team-relevant signals
        self._emit_ruflo_events(ctx, tool, target, adapter_result.findings, params)

        return {
            "ok": result.ok,
            "returncode": result.returncode,
            "duration_s": result.duration_s,
            "raw_count": result.raw_count,
            "assets": adapter_result.assets,
            "findings": adapter_result.findings,
            "agent_name": adapter_result.agent_name,
            "error": result.error,
            "timed_out": result.timed_out,
            "scope_violation": result.scope_violation,
        }

    def _emit_ruflo_events(self, ctx: AgentContext, tool: str, target: str,
                            findings: list[dict[str, Any]],
                            params: dict[str, Any]) -> None:
        """Push exploit / credential events into Ruflo so the dashboard reflects them."""
        from .. import ruflo

        exploit_classes = {"sqli", "xss", "cmdi", "lfi", "rce"}
        for f in findings:
            vc = (f.get("vuln_class") or "").lower()
            if vc in exploit_classes:
                ruflo.exploit_attempt(
                    scan_id=ctx.scan_id,
                    target=target,
                    technique=vc,
                    payload_id=(f.get("evidence") or {}).get("payload_id"),
                    success=True,
                    severity=f.get("severity", "info"),
                    evidence=f.get("evidence") or {},
                    mitre_technique=_mitre_for(vc),
                )

        if any((f.get("vuln_class") or "") == "credential-leak" for f in findings):
            import hashlib as _h
            for f in findings:
                if (f.get("vuln_class") or "") != "credential-leak":
                    continue
                ev = f.get("evidence") or {}
                plain = params.get("_plaintext_secret") or ev.get("password")
                secret_hash = _h.sha256(plain.encode("utf-8")).hexdigest() if plain else "n/a"
                ruflo.credential_discovered(
                    scan_id=ctx.scan_id,
                    target=target,
                    service=ev.get("service", "unknown"),
                    username=ev.get("username", "unknown"),
                    secret_hash=secret_hash,
                    source=tool,
                )


def _mitre_for(vuln_class: str) -> str | None:
    """Tiny ATT&CK mapper for the most common toolbox findings."""
    mapping = {
        "sqli": "T1190",
        "xss": "T1189",
        "cmdi": "T1059",
        "lfi": "T1083",
        "rce": "T1059",
        "credential-leak": "T1110",
        "secret-leak": "T1552",
        "cloud-misconfig": "T1078",
    }
    return mapping.get(vuln_class)
