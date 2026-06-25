"""Kangal tool registry and discovery.

Loads `tools-registry.json` (mounted into the container at
`$KANGAL_TOOLBOX_REGISTRY` or `/opt/kangal-toolbox/bin/tools-registry.json`)
and exposes a typed view for the rest of the system.

A tool entry looks like:
  {
    "name": "nuclei",
    "tier": 1,
    "category": "vuln_scan",
    "binary": "nuclei",
    "args_template": ["-json", "-silent"],
    "output_format": "jsonl",
    "timeout_default_s": 600,
    "rate_limit_per_min": 30,
    "requires_root": false,
    "engagement_modes": ["active", "web_only", "full_spectrum"],
    "produces": ["finding"]
  }
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional


REGISTRY_PATHS = [
    os.environ.get("KANGAL_TOOLBOX_REGISTRY"),
    "/opt/kangal-toolbox/bin/tools-registry.json",
    "./tools-registry.json",
    "../tools-registry.json",
]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    tier: int
    category: str
    binary: str
    args_template: list[str]
    output_format: str  # json|jsonl|xml|text
    timeout_default_s: int
    rate_limit_per_min: int
    requires_root: bool
    engagement_modes: list[str]
    produces: list[str] = field(default_factory=list)

    def is_allowed_in(self, mode: str) -> bool:
        return mode in self.engagement_modes


def _load_raw() -> dict[str, Any]:
    for p in REGISTRY_PATHS:
        if p and Path(p).exists():
            with Path(p).open(encoding="utf-8") as f:
                return json.load(f)
    return {"tools": []}


@lru_cache(maxsize=1)
def all_tools() -> tuple[ToolSpec, ...]:
    raw = _load_raw()
    out: list[ToolSpec] = []
    for entry in raw.get("tools", []):
        try:
            out.append(
                ToolSpec(
                    name=entry["name"],
                    tier=int(entry.get("tier", 2)),
                    category=entry.get("category", "uncategorized"),
                    binary=entry.get("binary", entry["name"]),
                    args_template=list(entry.get("args_template", [])),
                    output_format=entry.get("output_format", "text"),
                    timeout_default_s=int(entry.get("timeout_default_s", 300)),
                    rate_limit_per_min=int(entry.get("rate_limit_per_min", 0)),
                    requires_root=bool(entry.get("requires_root", False)),
                    engagement_modes=list(entry.get("engagement_modes", [])),
                    produces=list(entry.get("produces", [])),
                )
            )
        except Exception:
            # Skip malformed entries; registry is data, not code.
            continue
    return tuple(out)


def get(name: str) -> Optional[ToolSpec]:
    for t in all_tools():
        if t.name == name:
            return t
    return None


def by_tier(tier: int) -> list[ToolSpec]:
    return [t for t in all_tools() if t.tier == tier]


def by_category(category: str) -> list[ToolSpec]:
    return [t for t in all_tools() if t.category == category]


def for_engagement(mode: str) -> list[ToolSpec]:
    return [t for t in all_tools() if t.is_allowed_in(mode)]


def summary() -> dict[str, Any]:
    tools = all_tools()
    by_t: dict[int, int] = {}
    by_c: dict[str, int] = {}
    for t in tools:
        by_t[t.tier] = by_t.get(t.tier, 0) + 1
        by_c[t.category] = by_c.get(t.category, 0) + 1
    return {
        "total": len(tools),
        "by_tier": by_t,
        "by_category": by_c,
        "registry_path": next((p for p in REGISTRY_PATHS if p and Path(p).exists()), None),
    }
