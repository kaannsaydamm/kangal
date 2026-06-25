"""Subdomain discovery via crt.sh + small DNS brute wordlist.

crt.sh is the passive Certificate Transparency log search — almost every
public subdomain that has ever been issued a cert shows up there. It's
unauthenticated, JSON-API, and reliable.

For hosts not in CT logs (very fresh, internal, or wildcard) we fall back
to a tiny DNS brute against 50 common prefixes.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Iterable

import httpx

from .base import AgentContext, BaseAgent

CRT_SH_URL = "https://crt.sh/?q={target}&output=json"

# Cheap but effective: the prefixes that historically catch the most subdomains.
COMMON_PREFIXES = [
    "www", "mail", "api", "cdn", "cloud", "app", "blog", "dev", "staging",
    "test", "admin", "portal", "shop", "store", "m", "mobile", "static",
    "media", "images", "img", "docs", "wiki", "support", "status", "auth",
    "sso", "login", "dashboard", "panel", "mx", "smtp", "pop", "imap",
    "vpn", "remote", "git", "gitlab", "github", "jira", "jenkins", "ci",
    "stg", "stage", "prod", "beta", "alpha", "demo", "sandbox", "lab",
    "internal", "intranet", "db", "mysql", "postgres", "redis", "mongo",
    "elastic", "kibana", "grafana", "prom", "prometheus", "minio", "s3",
]


def _is_subdomain(value: str, root: str) -> bool:
    value = value.lower().strip().rstrip(".")
    root = root.lower().strip().rstrip(".")
    if not value or value == root:
        return False
    # crt.sh sometimes returns the root itself as well as wildcards
    if "*" in value:
        return False
    return value.endswith("." + root) or value == root


class SubdomainAgent(BaseAgent):
    name = "subdomain"

    async def run(self, ctx: AgentContext) -> None:
        root = ctx.target.strip().lower().rstrip(".")
        # If the target is an IP, skip subdomain discovery.
        try:
            ipaddress.ip_address(root)
            ctx.info(self.name, f"Target is an IP ({root}); skipping subdomain discovery")
            return
        except ValueError:
            pass

        ctx.info(self.name, f"Querying crt.sh for subdomains of {root}")
        found: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                r = await client.get(CRT_SH_URL.format(target=f"%.{root}"))
                r.raise_for_status()
                rows = r.json()
            for row in rows:
                for name in (row.get("name_value") or "").split("\n"):
                    name = name.strip().lower().rstrip(".")
                    if _is_subdomain(name, root):
                        found.add(name)
            ctx.success(self.name, f"crt.sh returned {len(found)} unique subdomains")
        except Exception as e:
            ctx.warn(self.name, f"crt.sh query failed: {e}")

        # DNS brute in parallel for the 50 common prefixes
        ctx.info(self.name, f"Brute-forcing {len(COMMON_PREFIXES)} common prefixes")
        brute_targets = [f"{p}.{root}" for p in COMMON_PREFIXES]

        async def _try_one(host: str) -> str | None:
            try:
                await asyncio.get_running_loop().getaddrinfo(host, None)
                return host
            except Exception:
                return None

        results = await asyncio.gather(*[_try_one(h) for h in brute_targets], return_exceptions=False)
        for h in results:
            if h:
                found.add(h)
        ctx.success(self.name, f"Total subdomains after brute: {len(found)}")

        # Persist them as assets, parent = root domain asset
        root_asset_id = ctx.get_target_asset().id
        for sub in sorted(found):
            ctx.store_asset(
                type_="subdomain",
                value=sub,
                parent_id=root_asset_id,
                discovered_by=self.name,
                meta={"source": "crt.sh+brute"},
            )
