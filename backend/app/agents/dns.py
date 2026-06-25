"""DNS resolution via Cloudflare DoH (1.1.1.1), with system-resolver fallback.

We resolve every subdomain (and the root target) and store one `ip` asset
per resolved address. Each ip asset's parent is the subdomain/root.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Optional

import httpx

from .base import AgentContext, BaseAgent

DOH_URL = "https://1.1.1.1/dns-query"
DOH_HEADERS = {"accept": "application/dns-json"}


async def _resolve_via_doh(name: str) -> list[str]:
    """Return A/AAAA records via Cloudflare DoH JSON API."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            out: list[str] = []
            for rtype in ("A", "AAAA"):
                r = await client.get(
                    DOH_URL,
                    params={"name": name, "type": rtype},
                    headers=DOH_HEADERS,
                )
                if r.status_code != 200:
                    continue
                data = r.json()
                for ans in data.get("Answer", []):
                    val = ans.get("data", "")
                    try:
                        ipaddress.ip_address(val)
                        out.append(val)
                    except ValueError:
                        continue
            return out
    except Exception:
        return []


async def _resolve_via_system(name: str) -> list[str]:
    """Fallback: use the OS resolver in a thread."""
    def _do() -> list[str]:
        out: list[str] = []
        try:
            infos = socket.getaddrinfo(name, None)
            for fam, *_rest, sockaddr in infos:
                ip = sockaddr[0]
                try:
                    ipaddress.ip_address(ip)
                    out.append(ip)
                except ValueError:
                    continue
        except Exception:
            return []
        # de-dupe, preserve order
        seen = set()
        return [x for x in out if not (x in seen or seen.add(x))]

    return await asyncio.to_thread(_do)


class DNSAgent(BaseAgent):
    name = "dns"

    async def _resolve_one(self, name: str) -> list[str]:
        ips = await _resolve_via_doh(name)
        if not ips:
            ips = await _resolve_via_system(name)
        return ips

    async def run(self, ctx: AgentContext) -> None:
        # Resolve the root target
        targets: list[tuple[str, str]] = []  # (hostname, kind)
        root = ctx.get_target_asset()
        targets.append((root.value, "root"))

        for sub in ctx.assets_by_type("subdomain"):
            targets.append((sub.value, "subdomain"))

        ctx.info(self.name, f"Resolving {len(targets)} hostnames")

        async def _one(name: str, kind: str) -> tuple[str, list[str]]:
            return name, await self._resolve_one(name)

        results = await asyncio.gather(*[_one(n, k) for n, k in targets], return_exceptions=False)

        # Map hostname -> asset id (parent)
        host_to_asset: dict[str, str] = {root.value: root.id}
        for sub in ctx.assets_by_type("subdomain"):
            host_to_asset[sub.value] = sub.id

        total_ips = 0
        for name, ips in results:
            if not ips:
                ctx.warn(self.name, f"{name}: no DNS records")
                continue
            parent_id = host_to_asset.get(name)
            for ip in ips:
                ctx.store_asset(
                    type_="ip",
                    value=ip,
                    parent_id=parent_id,
                    discovered_by=self.name,
                    meta={"hostname": name},
                )
                total_ips += 1
        ctx.success(self.name, f"Discovered {total_ips} IP records")
