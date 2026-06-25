"""Path scan: probe a curated list of sensitive paths on every URL.

Each finding becomes an `endpoint` asset + (later) a Finding via VulnCorrelator.
We dedupe across the scan: same path on same host.
"""
from __future__ import annotations

import asyncio

import httpx

from ..patterns import PATH_PATTERNS
from .base import AgentContext, BaseAgent

DEFAULT_TIMEOUT = 6.0


class PathScanAgent(BaseAgent):
    name = "pathscan"

    async def run(self, ctx: AgentContext) -> None:
        url_assets = ctx.assets_by_type("url")
        if not url_assets:
            ctx.warn(self.name, "No URLs to path-scan")
            return

        ctx.info(self.name, f"Path-scanning {len(url_assets)} URLs x {len(PATH_PATTERNS)} paths")

        sem = asyncio.Semaphore(20)

        async def _probe(base_url: str, path: str) -> tuple[str, str, int, int, str]:
            url = base_url.rstrip("/") + path
            async with sem:
                try:
                    async with httpx.AsyncClient(
                        timeout=DEFAULT_TIMEOUT,
                        follow_redirects=False,
                        verify=False,
                        headers={"User-Agent": "Kangal/1.0 (recon)"},
                    ) as client:
                        r = await client.get(url)
                        body = r.text[:512] if r.text else ""
                        return base_url, path, r.status_code, len(body), body
                except Exception:
                    return base_url, path, 0, 0, ""

        tasks = []
        for url_asset in url_assets:
            for p in PATH_PATTERNS:
                tasks.append(_probe(url_asset.value, p.path))

        results = await asyncio.gather(*tasks, return_exceptions=False)
        found = 0
        for base_url, path, status, body_len, body in results:
            if status in (200, 206) and body_len > 0:
                # Store the endpoint as an asset, parented to the URL asset
                url_asset_id = None
                for u in url_assets:
                    if u.value == base_url:
                        url_asset_id = u.id
                        break
                if url_asset_id:
                    ctx.store_asset(
                        type_="endpoint",
                        value=base_url.rstrip("/") + path,
                        parent_id=url_asset_id,
                        discovered_by=self.name,
                        meta={
                            "status": status,
                            "body_len": body_len,
                            "body_excerpt": body,
                        },
                    )
                    found += 1
        ctx.success(self.name, f"Discovered {found} reachable sensitive endpoints")
