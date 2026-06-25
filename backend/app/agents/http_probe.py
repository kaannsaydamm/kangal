"""HTTP probe: HEAD then GET, capture status/title/headers/redirect chain.

Stores one `url` asset per reachable web target. In active mode we also
follow up to 3 redirects so we see the final landing page's headers.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

import httpx

from .base import AgentContext, BaseAgent

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(body: str) -> Optional[str]:
    m = TITLE_RE.search(body[:50000])
    if not m:
        return None
    t = m.group(1).strip()
    return t[:200] if t else None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _candidate_urls(host: str) -> list[str]:
    """For a hostname, try https then http. For an IP, same."""
    return [f"https://{host}", f"http://{host}"]


class HTTPProbeAgent(BaseAgent):
    name = "http_probe"

    async def run(self, ctx: AgentContext) -> None:
        # candidates: root + every subdomain + every IP
        hosts: list[tuple[str, Optional[str]]] = []  # (host, parent_asset_id)
        root = ctx.get_target_asset()
        hosts.append((root.value, root.id))
        for sub in ctx.assets_by_type("subdomain"):
            hosts.append((sub.value, sub.id))
        for ip_asset in ctx.assets_by_type("ip"):
            hosts.append((ip_asset.value, ip_asset.id))

        ctx.info(self.name, f"Probing HTTP for {len(hosts)} hosts")

        sem = asyncio.Semaphore(10)

        async def _probe(host: str, parent_id: Optional[str]) -> Optional[dict]:
            async with sem:
                for base in _candidate_urls(host):
                    try:
                        async with httpx.AsyncClient(
                            timeout=12.0,
                            follow_redirects=True,
                            max_redirects=3,
                            verify=False,  # noisy scan against self-signed ok
                            headers={"User-Agent": "Kangal/1.0 (recon)"},
                        ) as client:
                            r = await client.get(base)
                            # Body: cap to 256KB
                            body = r.text[:262144] if r.text else ""
                            title = _extract_title(body)
                            chain = [str(h.url) for h in r.history] + [str(r.url)]
                            return {
                                "url": str(r.url),
                                "status": r.status_code,
                                "title": title,
                                "server": r.headers.get("server"),
                                "content_type": r.headers.get("content-type"),
                                "x_powered_by": r.headers.get("x-powered-by"),
                                "x_aspnet_version": r.headers.get("x-aspnet-version"),
                                "x_aspnetmvc_version": r.headers.get("x-aspnetmvc-version"),
                                "generator": r.headers.get("x-generator"),
                                "csp": r.headers.get("content-security-policy"),
                                "hsts": r.headers.get("strict-transport-security"),
                                "x_frame_options": r.headers.get("x-frame-options"),
                                "x_content_type_options": r.headers.get("x-content-type-options"),
                                "referrer_policy": r.headers.get("referrer-policy"),
                                "redirect_chain": chain,
                                "body_excerpt": body[:2048],
                                "scheme": urlparse(str(r.url)).scheme,
                            }
                    except Exception:
                        continue
                return None

        results = await asyncio.gather(*[_probe(h, p) for h, p in hosts], return_exceptions=False)
        ok = 0
        for (host, parent_id), data in zip(hosts, results):
            if not data:
                continue
            url = data["url"]
            asset_id = ctx.store_asset(
                type_="url",
                value=url,
                parent_id=parent_id,
                discovered_by=self.name,
                meta=data,
            )
            ok += 1
        ctx.success(self.name, f"Got HTTP responses for {ok}/{len(hosts)} hosts")
