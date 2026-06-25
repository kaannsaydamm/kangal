"""Vuln correlator: walks all assets and emits Findings using patterns.py.

This is the *last* stage. It reads the accumulated assets and produces
severity-ranked Findings. No outbound I/O.
"""
from __future__ import annotations

from ..patterns import (
    PORT_PATTERNS,
    REQUIRED_SECURITY_HEADERS,
    VERSION_DISCLOSURE,
    PATH_PATTERNS,
    TECH_PATTERNS,
    find_version,
)
from .base import AgentContext, BaseAgent


class VulnCorrelator(BaseAgent):
    name = "vuln"

    async def run(self, ctx: AgentContext) -> None:
        ctx.info(self.name, "Correlating findings from discovered assets")
        emitted = 0

        # ---- port-based ----
        for port_asset in ctx.assets_by_type("port"):
            try:
                portnum = int(port_asset.value.rsplit(":", 1)[-1])
            except (ValueError, IndexError):
                continue
            for pat in PORT_PATTERNS:
                if pat.port == portnum:
                    ctx.store_finding(
                        severity=pat.severity,
                        vuln_class=pat.vuln_class,
                        title=pat.title,
                        asset_id=port_asset.id,
                        evidence={"port": portnum, "value": port_asset.value},
                    )
                    emitted += 1
                    break

        # ---- header + tech (per URL) ----
        for url_asset in ctx.assets_by_type("url"):
            meta = url_asset.meta or {}

            for h in REQUIRED_SECURITY_HEADERS:
                # meta keys are normalized to snake_case (server, x_powered_by, ...)
                key = h.header.lower().replace("-", "_")
                if not meta.get(key) and not meta.get(h.header):
                    ctx.store_finding(
                        severity=h.severity,
                        vuln_class=h.vuln_class,
                        title=h.title,
                        asset_id=url_asset.id,
                        evidence={"url": url_asset.value, "header": h.header},
                    )
                    emitted += 1

            for h in VERSION_DISCLOSURE:
                key = h.header.lower().replace("-", "_")
                val = meta.get(key) or meta.get(h.header)
                if not val:
                    continue
                v = find_version(str(val))
                if v or h.version_disclosure:
                    sev = h.severity if v else "info"
                    title = f"{h.title}" + (f" (v{v})" if v else "")
                    ctx.store_finding(
                        severity=sev,
                        vuln_class=h.vuln_class,
                        title=title,
                        asset_id=url_asset.id,
                        evidence={"url": url_asset.value, "header": h.header, "value": str(val)[:200]},
                    )
                    emitted += 1

        # ---- path-based ----
        for endpoint_asset in ctx.assets_by_type("endpoint"):
            for p in PATH_PATTERNS:
                if endpoint_asset.value.endswith(p.path):
                    ctx.store_finding(
                        severity=p.severity,
                        vuln_class=p.vuln_class,
                        title=p.title,
                        asset_id=endpoint_asset.id,
                        evidence={"url": endpoint_asset.value, "status": endpoint_asset.meta.get("status")},
                    )
                    emitted += 1
                    break

        # ---- tech-based (informational fingerprints) ----
        for tech_asset in ctx.assets_by_type("tech"):
            tech_list = (tech_asset.meta or {}).get("tech") or []
            for t in tech_list:
                for pat in TECH_PATTERNS:
                    if pat.title in t or pat.title.replace(" detected", "") in t:
                        ctx.store_finding(
                            severity=pat.severity,
                            vuln_class=pat.vuln_class,
                            title=t,
                            asset_id=tech_asset.id,
                            evidence={"url": (tech_asset.meta or {}).get("url")},
                        )
                        emitted += 1
                        break

        ctx.success(self.name, f"Emitted {emitted} findings")
