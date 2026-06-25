"""Kangal recon agents.

Each agent owns one stage of the pipeline. Agents are plain Python classes
with a `run(scan_id, target, ctx)` async method. They communicate back to
the orchestrator via the shared `AgentContext`:

- ctx.log(stage, level, message)        — write to events table + Redis pub/sub
- ctx.store_asset(type, value, parent, meta, by)  — persist discovered asset
- ctx.store_finding(asset_id, severity, vuln_class, title, evidence) — vuln
- ctx.assets(...)                        — read prior stage assets

Toolbox v2 agents (exploit / network / cloud / osint) live in submodules
and use BaseAgent.run_tool() to delegate the actual subprocess to the
Ruflo-instrumented ToolExecutor. New agents = subclass + call run_tool.
"""
from .base import AgentContext, BaseAgent
from .subdomain import SubdomainAgent
from .dns import DNSAgent
from .http_probe import HTTPProbeAgent
from .portscan import PortScanAgent
from .tech import TechDetectAgent
from .pathscan import PathScanAgent
from .vuln import VulnCorrelator

# Toolbox v2
from . import exploit
from . import network
from . import cloud
from . import osint

CORE_PIPELINE = [
    SubdomainAgent,
    DNSAgent,
    HTTPProbeAgent,
    PortScanAgent,
    TechDetectAgent,
    PathScanAgent,
    VulnCorrelator,
]

# Built on top of core. Run only when their engagement-mode gate opens.
TOOLBOX_AGENTS = (
    exploit.all_agents()
    + network.all_agents()
    + cloud.all_agents()
    + osint.all_agents()
)

ALL_AGENTS = CORE_PIPELINE + TOOLBOX_AGENTS


def agents_by_mode(mode: str) -> list[type[BaseAgent]]:
    """Filter toolbox agents by engagement mode string.

    Modes supported: passive, active, web_only, network_only, full_spectrum.
    """
    m = (mode or "active").lower()
    if m == "passive":
        return [a for a in TOOLBOX_AGENTS if getattr(a, "name", "").startswith("osint_")]
    if m == "web_only":
        return [a for a in TOOLBOX_AGENTS if a in exploit.all_agents()]
    if m == "network_only":
        return [a for a in TOOLBOX_AGENTS if a in network.all_agents()]
    if m == "full_spectrum":
        return list(TOOLBOX_AGENTS)
    # default: active web + osint
    return (
        [a for a in TOOLBOX_AGENTS if a in exploit.all_agents() or a in osint.all_agents()]
    )


__all__ = [
    "AgentContext",
    "BaseAgent",
    "SubdomainAgent",
    "DNSAgent",
    "HTTPProbeAgent",
    "PortScanAgent",
    "TechDetectAgent",
    "PathScanAgent",
    "VulnCorrelator",
    "exploit",
    "network",
    "cloud",
    "osint",
    "CORE_PIPELINE",
    "TOOLBOX_AGENTS",
    "ALL_AGENTS",
    "agents_by_mode",
]
