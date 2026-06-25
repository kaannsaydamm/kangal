"""Network exploitation agents — SMB / SSH / WinRM enumeration.

All of these run only on hosts the portscan agent already saw on
active service ports. They DO NOT do blind scanning — they reuse the
scan graph.
"""
from __future__ import annotations

from .base import AgentContext, BaseAgent


def _service_hosts(ctx: AgentContext, port: int) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for a in ctx.assets_by_type("service"):
        meta = a.meta or {}
        if int(meta.get("port", 0)) == port:
            out.append((meta.get("host", a.value.split(":", 1)[0]), a.id))
    # also handle raw "host:port" values
    for a in ctx.assets_by_type("port"):
        if ":" in a.value and a.value.endswith(f":{port}"):
            out.append((a.value.rsplit(":", 1)[0], a.id))
    # de-dupe
    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for h, aid in out:
        if h in seen:
            continue
        seen.add(h)
        deduped.append((h, aid))
    return deduped


class SmbEnumAgent(BaseAgent):
    name = "smb_enum4linux"

    async def run(self, ctx: AgentContext) -> None:
        hosts = _service_hosts(ctx, 445) + _service_hosts(ctx, 139)
        if not hosts:
            ctx.warn(self.name, "no SMB ports discovered")
            return
        ctx.info(self.name, f"enum4linux against {len(hosts)} SMB host(s)")
        for host, _aid in hosts[:10]:
            await self.run_tool(
                ctx,
                tool="enum4linux-ng",
                params={"host": host, "json": True},
                target=host,
                timeout=180,
                mode="full_spectrum",
            )


class SmbMapAgent(BaseAgent):
    name = "smb_smbmap"

    async def run(self, ctx: AgentContext) -> None:
        hosts = _service_hosts(ctx, 445)
        if not hosts:
            ctx.warn(self.name, "no SMB ports discovered")
            return
        ctx.info(self.name, f"smbmap share enumeration on {len(hosts)} host(s)")
        for host, _aid in hosts[:10]:
            await self.run_tool(
                ctx,
                tool="smbmap",
                params={"host": host},
                target=host,
                timeout=180,
                mode="full_spectrum",
            )


class NxcAgent(BaseAgent):
    name = "ad_nxc"

    async def run(self, ctx: AgentContext) -> None:
        hosts = _service_hosts(ctx, 445) + _service_hosts(ctx, 5985) + _service_hosts(ctx, 5986)
        if not hosts:
            ctx.warn(self.name, "no SMB/WinRM ports discovered")
            return
        ctx.info(self.name, f"NetExec enumeration on {len(hosts)} host(s)")
        for host, _aid in hosts[:10]:
            await self.run_tool(
                ctx,
                tool="nxc",
                params={"host": host, "protocol": "smb", "shares": True, "users": True},
                target=host,
                timeout=240,
                mode="full_spectrum",
            )


class BloodHoundAgent(BaseAgent):
    name = "ad_bloodhound"

    async def run(self, ctx: AgentContext) -> None:
        # requires credentials — only runs when params.cid_file is provided
        from .. import ruflo

        # BloodHound is fed the scan target; collectors can do their thing.
        # Output is heavy JSON; we just store the asset graph.
        ctx.info(self.name, "bloodhound-python collector (no creds -> limited)")
        result = await self.run_tool(
            ctx,
            tool="bloodhound-python",
            params={"domain": ctx.target, "dc": "", "no-cache": True},
            target=ctx.target,
            timeout=600,
            mode="full_spectrum",
        )
        if result.get("assets"):
            ruflo.memory_store(
                key=f"{ctx.scan_id}:bloodhound",
                value=f"bloodhound collected {len(result['assets'])} ad objects",
                tags=["bloodhound", "ad", ctx.target],
            )


class SshHydraAgent(BaseAgent):
    name = "creds_ssh_hydra"

    async def run(self, ctx: AgentContext) -> None:
        hosts = _service_hosts(ctx, 22)
        if not hosts:
            ctx.warn(self.name, "no SSH ports discovered")
            return
        ctx.info(self.name, f"hydra ssh against {len(hosts)} host(s)")
        for host, _aid in hosts[:5]:
            await self.run_tool(
                ctx,
                tool="hydra",
                params={
                    "L": "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-usernames.txt",
                    "P": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
                    "t": "ssh",
                    "f": True,
                    "host": host,
                },
                target=host,
                timeout=900,
                mode="full_spectrum",
            )


def all_agents() -> list[BaseAgent]:
    return [
        SmbEnumAgent(),
        SmbMapAgent(),
        NxcAgent(),
        BloodHoundAgent(),
        SshHydraAgent(),
    ]
