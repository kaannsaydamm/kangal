"""Cross-scan intel store and pattern persistence.

Provides:
- intel_search(query): text search across all historical findings & assets
- store_pattern(...): persist a successful-recon pattern (agent, target profile, outcome)
- list_patterns(): return stored patterns (in confidence order)

The "memory" is a tiny JSON-on-disk store under $KANGAL_DATA/memory.json
(controlled via env var, default /tmp/kangal-memory.json). This is the
local equivalent of what ruflo's memory_store / agentdb_pattern-store
do in the Claude Flow world: cross-session, cross-scan queryable.

In the orchestrated setup, hooks_post-task signals from the agent that
wrote the entry would feed this; we wire that in as a fire-and-forget
hook in orchestrator.run_scan (no blocking call, no MCP dep).
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Iterable

_LOCK = threading.Lock()
_PATH = Path(os.environ.get("KANGAL_MEMORY", "/tmp/kangal-memory.json"))


def _load() -> dict[str, Any]:
    if not _PATH.exists():
        return {"findings": [], "patterns": []}
    try:
        return json.loads(_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"findings": [], "patterns": []}


def _save(data: dict[str, Any]) -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    _PATH.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")


def _tokens(s: str) -> list[str]:
    return [t for t in (s or "").lower().split() if len(t) >= 2]


def _score(query_tokens: Iterable[str], haystack: str) -> float:
    """Tiny BM25-ish score: fraction of query tokens that appear in haystack."""
    if not query_tokens:
        return 0.0
    h = (haystack or "").lower()
    matches = sum(1 for t in query_tokens if t in h)
    return matches / max(1, len(list(query_tokens)))


def store_finding(scan_id: str, finding: dict[str, Any]) -> None:
    """Index a finding for cross-scan intel queries."""
    with _LOCK:
        d = _load()
        d["findings"].append(
            {
                "scan_id": scan_id,
                "ts": time.time(),
                "severity": finding.get("severity"),
                "vuln_class": finding.get("vuln_class"),
                "title": finding.get("title"),
                "evidence": finding.get("evidence") or {},
            }
        )
        # cap to last 5000 to keep file bounded
        d["findings"] = d["findings"][-5000:]
        _save(d)


def store_pattern(agent: str, target: str, outcome: str, confidence: float) -> None:
    """Persist a successful recon pattern for future routing/learning."""
    with _LOCK:
        d = _load()
        d["patterns"].append(
            {
                "ts": time.time(),
                "agent": agent,
                "target": target,
                "outcome": outcome,
                "confidence": float(confidence),
            }
        )
        d["patterns"] = d["patterns"][-1000:]
        _save(d)


def list_patterns(limit: int = 50) -> list[dict[str, Any]]:
    with _LOCK:
        d = _load()
    return sorted(d.get("patterns", []), key=lambda p: p.get("confidence", 0.0), reverse=True)[
        :limit
    ]


def search(query: str, limit: int = 20) -> list[dict[str, Any]]:
    """Search across all indexed findings. Returns matches with score + reason."""
    q_tokens = _tokens(query)
    if not q_tokens:
        return []
    out: list[dict[str, Any]] = []
    with _LOCK:
        d = _load()
    for f in d.get("findings", []):
        haystack = " ".join(
            [
                str(f.get("title") or ""),
                str(f.get("vuln_class") or ""),
                str(f.get("severity") or ""),
                json.dumps(f.get("evidence") or {}, default=str),
            ]
        )
        s = _score(q_tokens, haystack)
        if s <= 0:
            continue
        out.append(
            {
                "id": f"intel-{f.get('ts')}-{f.get('scan_id')[:8]}",
                "scan_id": f.get("scan_id"),
                "severity": f.get("severity"),
                "vuln_class": f.get("vuln_class"),
                "title": f.get("title"),
                "evidence": f.get("evidence") or {},
                "score": round(s, 3),
                "source": "local-intel",
            }
        )
    out.sort(key=lambda r: r["score"], reverse=True)
    return out[:limit]
