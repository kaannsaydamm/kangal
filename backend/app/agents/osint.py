"""OSINT / secret-discovery agents — passive & mostly read-only.

These run only in passive mode and respect the engagement scope
enforced by ToolExecutor._in_scope.
"""
from __future__ import annotations

from .base import AgentContext, BaseAgent


class TheHarvesterAgent(BaseAgent):
    name = "osint_harvester"

    async def run(self, ctx: AgentContext) -> None:
        ctx.info(self.name, "theHarvester passive OSINT")
        await self.run_tool(
            ctx,
            tool="theHarvester",
            params={"d": ctx.target, "b": "all", "l": 500},
            target=ctx.target,
            timeout=600,
            mode="passive",
        )


class SubfinderAgent(BaseAgent):
    name = "subdomain_subfinder"

    async def run(self, ctx: AgentContext) -> None:
        ctx.info(self.name, "subfinder passive sources")
        await self.run_tool(
            ctx,
            tool="subfinder",
            params={"d": ctx.target, "all": True, "silent": True, "json": True},
            target=ctx.target,
            timeout=600,
            mode="passive",
        )


class AmassAgent(BaseAgent):
    name = "subdomain_amass"

    async def run(self, ctx: AgentContext) -> None:
        # amass enum with passive first; brute if engagement mode allows.
        mode_args = "passive" if ctx.mode == "passive" else "active"
        await self.run_tool(
            ctx,
            tool="amass",
            params={"enum": "-d", "domain": ctx.target, "json": True, "passive": "passive" in mode_args},
            target=ctx.target,
            timeout=1800,
            mode=ctx.mode,
        )


class DnsxAgent(BaseAgent):
    name = "dns_dnsx"

    async def run(self, ctx: AgentContext) -> None:
        # Get all known subdomain assets and bulk-resolve them.
        sub_targets = [ctx.target]
        for a in ctx.assets_by_type("subdomain"):
            if a.value and a.value not in sub_targets:
                sub_targets.append(a.value)
        for sub in sub_targets[:100]:
            await self.run_tool(
                ctx,
                tool="dnsx",
                params={"d": sub, "a": "", "aaaa": "", "cname": "", "json": True},
                target=sub,
                timeout=120,
                mode=ctx.mode,
            )


class HttpxAgent(BaseAgent):
    name = "probe_httpx"

    async def run(self, ctx: AgentContext) -> None:
        sub_targets = [ctx.target]
        for a in ctx.assets_by_type("subdomain"):
            if a.value and a.value not in sub_targets:
                sub_targets.append(a.value)
        for sub in sub_targets[:100]:
            await self.run_tool(
                ctx,
                tool="httpx",
                params={
                    "u": sub,
                    "title": True,
                    "tech-detect": True,
                    "status-code": True,
                    "json": True,
                    "silent": True,
                },
                target=sub,
                timeout=120,
                mode=ctx.mode,
            )


class TruffleHogAgent(BaseAgent):
    name = "secret_trufflehog"

    async def run(self, ctx: AgentContext) -> None:
        if not ctx.target.startswith("repo://") and not ctx.target.startswith("git://"):
            ctx.info(self.name, "target is not a git repo — skipping trufflehog")
            return
        repo = ctx.target.split("://", 1)[1]
        await self.run_tool(
            ctx,
            tool="trufflehog",
            params={"git": repo, "json": True},
            target=ctx.target,
            timeout=1800,
            mode="passive",
        )


class GitLeaksAgent(BaseAgent):
    name = "secret_gitleaks"

    async def run(self, ctx: AgentContext) -> None:
        if not ctx.target.startswith("repo://"):
            ctx.info(self.name, "target is not a local repo path — skipping gitleaks")
            return
        repo_path = ctx.target[len("repo://"):]
        await self.run_tool(
            ctx,
            tool="gitleaks",
            params={"dir": repo_path, "report-format": "json"},
            target=ctx.target,
            timeout=900,
            mode="passive",
        )


class WafW00fAgent(BaseAgent):
    name = "waf_wafw00f"

    async def run(self, ctx: AgentContext) -> None:
        for a in ctx.assets_by_type("url"):
            url = a.value
            if not (url.startswith("http://") or url.startswith("https://")):
                continue
            await self.run_tool(
                ctx,
                tool="wafw00f",
                params={"u": url, "json": True},
                target=url,
                timeout=120,
                mode="passive",
            )


def all_agents() -> list[BaseAgent]:
    return [
        TheHarvesterAgent(),
        SubfinderAgent(),
        AmassAgent(),
        DnsxAgent(),
        HttpxAgent(),
        TruffleHogAgent(),
        GitLeaksAgent(),
        WafW00fAgent(),
    ]
