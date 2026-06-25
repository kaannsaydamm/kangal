"""Tech fingerprint from HTTP headers + body.

We don't run whatweb/nuclei — we just walk the `meta` dicts of url assets
and apply the patterns in `patterns.py`. Same outcome, zero extra deps.
"""
from __future__ import annotations

import re
from typing import Optional

from ..patterns import TECH_PATTERNS, find_version
from .base import AgentContext, BaseAgent


HEADER_SOURCES = ["server", "x_powered_by", "x_aspnet_version", "x_aspnetmvc_version", "generator"]


class TechDetectAgent(BaseAgent):
    name = "tech"

    async def run(self, ctx: AgentContext) -> None:
        url_assets = ctx.assets_by_type("url")
        if not url_assets:
            ctx.warn(self.name, "No URL assets to fingerprint")
            return

        ctx.info(self.name, f"Fingerprinting {len(url_assets)} URLs")
        findings_emitted: set[str] = set()
        per_url: dict[str, list[str]] = {}

        for url_asset in url_assets:
            meta = url_asset.meta or {}
            blob = " ".join(str(meta.get(k) or "") for k in HEADER_SOURCES)

            detected: list[str] = []
            for pat in TECH_PATTERNS:
                m = re.search(pat.name_regex, blob, re.IGNORECASE)
                if m:
                    version = find_version(m.group(0))
                    label = f"{pat.title}{f' v{version}' if version else ''}"
                    if label not in detected:
                        detected.append(label)
            if detected:
                per_url[url_asset.value] = detected

        # Persist as a single `tech` asset per unique combo? Simpler: one tech asset per url.
        for url_asset in url_assets:
            techs = per_url.get(url_asset.value) or []
            if not techs:
                continue
            tech_id = ctx.store_asset(
                type_="tech",
                value=", ".join(techs)[:1000],
                parent_id=url_asset.id,
                discovered_by=self.name,
                meta={"url": url_asset.value, "tech": techs},
            )

        ctx.success(self.name, f"Detected tech on {len(per_url)} URLs")
