"""Cloud + container + IaC auditing agents.

These are read-only: prowler / scout-suite / trivy / kube-hunter.
They target environment endpoints discovered by the recon pipeline
or the scan target itself if it looks like a cloud / k8s endpoint.
"""
from __future__ import annotations

from .base import AgentContext, BaseAgent


def _looks_like_aws(target: str) -> bool:
    t = target.lower()
    return any(x in t for x in ("amazonaws", "aws.", "cloudfront", "rds.amazonaws"))


def _looks_like_k8s(target: str) -> bool:
    return any(p in target for p in (":6443", ":8443", ":10250"))


class ProwlerAgent(BaseAgent):
    name = "cloud_prowler"

    async def run(self, ctx: AgentContext) -> None:
        if not (_looks_like_aws(ctx.target) or "aws" in ctx.target.lower()):
            ctx.warn(self.name, "target does not look like AWS — skipping prowler")
            return
        ctx.info(self.name, "prowler AWS CIS scan (read-only)")
        await self.run_tool(
            ctx,
            tool="prowler",
            params={"provider": "aws", "output": "json", "output_directory": "/tmp/prowler"},
            target=ctx.target,
            timeout=1800,
            mode="full_spectrum",
        )


class ScoutSuiteAgent(BaseAgent):
    name = "cloud_scoutsuite"

    async def run(self, ctx: AgentContext) -> None:
        if "aws" not in ctx.target.lower() and "azure" not in ctx.target.lower() and "gcp" not in ctx.target.lower():
            ctx.warn(self.name, "target does not look like a cloud account — skipping scout-suite")
            return
        await self.run_tool(
            ctx,
            tool="scout",
            params={"provider": "aws"},
            target=ctx.target,
            timeout=1800,
            mode="full_spectrum",
        )


class TrivyAgent(BaseAgent):
    name = "vuln_trivy"

    async def run(self, ctx: AgentContext) -> None:
        # Trivy on a remote image — only if target is an image reference.
        if "/" not in ctx.target or ":" not in ctx.target:
            ctx.info(self.name, "target not an image ref — skipping trivy image scan")
            return
        await self.run_tool(
            ctx,
            tool="trivy",
            params={"image": ctx.target, "format": "json"},
            target=ctx.target,
            timeout=900,
            mode="full_spectrum",
        )


class KubeHunterAgent(BaseAgent):
    name = "k8s_hunter"

    async def run(self, ctx: AgentContext) -> None:
        if not _looks_like_k8s(ctx.target):
            ctx.warn(self.name, "target does not look like a k8s endpoint")
            return
        await self.run_tool(
            ctx,
            tool="kube-hunter",
            params={"remote": ctx.target.split(":")[0]},
            target=ctx.target,
            timeout=600,
            mode="full_spectrum",
        )


class SemgrepAgent(BaseAgent):
    name = "sast_semgrep"

    async def run(self, ctx: AgentContext) -> None:
        # Semgrep on a local repo path; agent runs in celery worker.
        # Triggered by scan target starting with repo://
        if not ctx.target.startswith("repo://"):
            ctx.info(self.name, "target is not a local repo — skipping semgrep")
            return
        repo_path = ctx.target[len("repo://"):]
        await self.run_tool(
            ctx,
            tool="semgrep",
            params={"config": "auto", "json": True, "target": repo_path},
            target=ctx.target,
            timeout=1200,
            mode="full_spectrum",
        )


def all_agents() -> list[BaseAgent]:
    return [
        ProwlerAgent(),
        ScoutSuiteAgent(),
        TrivyAgent(),
        KubeHunterAgent(),
        SemgrepAgent(),
    ]
