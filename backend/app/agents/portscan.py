"""Port scan via nmap. Sync subprocess — runs in a Celery worker thread.

We use `-sT` (TCP connect, no raw socket needed) and `--top-ports 100` to
keep the scan under ~30s. We also ask for light service detection (`-sV`)
on the open ports.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import xml.etree.ElementTree as ET
from typing import Optional

from .base import AgentContext, BaseAgent

# Pre-built top-100 TCP ports (Nmap's "top 100" list).
NMAP_ARGS = ["-sT", "-sV", "--top-ports", "100", "-Pn", "-T4", "--open", "-oX", "-"]

PORT_LINE_RE = re.compile(r"^(\d+)/tcp\s+(\w+)\s+(\S+)(?:\s+(.*))?$")


def _parse_nmap_xml(xml_bytes: bytes, host: str) -> list[dict]:
    """Parse the nmap -oX stdout into a list of port dicts."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return []
    ports: list[dict] = []
    for h in root.findall("host"):
        addr_el = h.find("address")
        if addr_el is None:
            continue
        if addr_el.get("addrtype") != "ipv4" and addr_el.get("addrtype") != "ipv6":
            continue
        h_addr = addr_el.get("addr")
        ports_el = h.find("ports")
        if ports_el is None:
            continue
        for p in ports_el.findall("port"):
            portnum = int(p.get("portid", "0"))
            proto = p.get("protocol", "tcp")
            state_el = p.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            svc_el = p.find("service")
            svc = {
                "name": svc_el.get("name") if svc_el is not None else None,
                "product": svc_el.get("product") if svc_el is not None else None,
                "version": svc_el.get("version") if svc_el is not None else None,
                "extrainfo": svc_el.get("extrainfo") if svc_el is not None else None,
            } if svc_el is not None else {}
            ports.append(
                {
                    "host": h_addr,
                    "port": portnum,
                    "proto": proto,
                    "state": state,
                    "service": svc,
                }
            )
    return ports


async def _run_nmap(target: str) -> list[dict]:
    """Async-subprocess nmap. Returns list of port dicts."""
    cmd = ["nmap", *NMAP_ARGS, target]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0 and not stdout:
        raise RuntimeError(f"nmap failed (rc={proc.returncode}): {stderr.decode(errors='ignore')[:300]}")
    return _parse_nmap_xml(stdout, target)


class PortScanAgent(BaseAgent):
    name = "portscan"

    async def run(self, ctx: AgentContext) -> None:
        # Gather IP assets + the root target (in case it's an IP literal)
        targets: list[tuple[str, str]] = []  # (ip, parent_asset_id)
        root = ctx.get_target_asset()
        try:
            ipaddress.ip_address(root.value)
            targets.append((root.value, root.id))
        except ValueError:
            pass
        for ip_asset in ctx.assets_by_type("ip"):
            targets.append((ip_asset.value, ip_asset.id))

        if not targets:
            ctx.warn(self.name, "No IPs to scan")
            return

        ctx.info(self.name, f"Port-scanning {len(targets)} hosts (top-100)")

        sem = asyncio.Semaphore(3)  # nmap is loud; don't blow the NIC

        async def _one(ip: str, parent_id: str) -> tuple[str, list[dict]]:
            async with sem:
                try:
                    ports = await _run_nmap(ip)
                    return ip, ports
                except Exception as e:
                    ctx.warn(self.name, f"nmap failed for {ip}: {e}")
                    return ip, []

        results = await asyncio.gather(*[_one(ip, pid) for ip, pid in targets])
        total_open = 0
        for ip, ports in results:
            for p in ports:
                svc = p.get("service") or {}
                meta = {
                    "host": ip,
                    "port": p["port"],
                    "proto": p["proto"],
                    "state": p["state"],
                    "service_name": svc.get("name"),
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "extrainfo": svc.get("extrainfo"),
                }
                ctx.store_asset(
                    type_="port",
                    value=f"{ip}:{p['port']}",
                    parent_id=parent_id,
                    discovered_by=self.name,
                    meta=meta,
                )
                ctx.store_asset(
                    type_="service",
                    value=f"{ip}:{p['port']}/{svc.get('name') or 'unknown'}",
                    parent_id=parent_id,
                    discovered_by=self.name,
                    meta=meta,
                )
                total_open += 1
        ctx.success(self.name, f"Discovered {total_open} open ports across {len(targets)} hosts")
