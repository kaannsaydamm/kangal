"""Tool executor: subprocess runner with Ruflo telemetry hooks.

`ToolExecutor.run(spec, args, ctx)` is the single entry point every new
agent should call to invoke a tool. It:

  1. Resolves the binary path (toolbox bin or PATH)
  2. Enforces rate limit (per tool name, in-memory)
  3. Validates engagement mode + scope (target must be in scope)
  4. Calls Ruflo hooks_pre-task (mirrors mcp__claude-flow__hooks_pre_task)
  5. Subprocess with timeout, output capture
  6. Parses output (json|jsonl|xml|text)
  7. Calls Ruflo hooks_post_task + neural_train (mirrors mcp__claude-flow__neural_train)
  8. Stores pattern via Ruflo (mirrors mcp__agentic-flow__agentdb_pattern_store)
  9. Returns a ToolResult dataclass

The executor never raises on tool failure — it returns a result with `ok=False`
and the stderr. Agents decide how to react.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
import uuid
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .. import ruflo
from ..tools import ToolSpec, get as get_tool_spec


TOOLBOX_BIN = os.environ.get("KANGAL_TOOLBOX_BIN", "/opt/kangal-toolbox/bin")
ENGAGEMENT_MODE = os.environ.get("KANGAL_ENGAGEMENT_MODE", "full_spectrum")
SCOPE_CIDRS: list[str] = [s for s in os.environ.get("KANGAL_SCOPE_CIDRS", "").split(",") if s]
SCOPE_DOMAINS: list[str] = [s for s in os.environ.get("KANGAL_SCOPE_DOMAINS", "").split(",") if s]


# ---------- rate limiting (per-tool, per-process, sliding window) ----------
_call_history: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=1000))


def _allow_rate(spec: ToolSpec) -> bool:
    if spec.rate_limit_per_min <= 0:
        return True
    now = time.time()
    window = 60.0
    history = _call_history[spec.name]
    while history and now - history[0] > window:
        history.popleft()
    if len(history) >= spec.rate_limit_per_min:
        return False
    history.append(now)
    return True


# ---------- scope validation ----------
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)


def _in_scope(target: str) -> bool:
    """Best-effort scope check. Empty scope = allow all (dev)."""
    if not SCOPE_CIDRS and not SCOPE_DOMAINS:
        return True
    t = (target or "").strip().lower()
    if not t:
        return False
    if _IPV4_RE.match(t):
        # naive CIDR check; production should use ipaddress module
        return any(t.startswith(c.rsplit("/", 1)[0].rsplit(".", 1)[0]) for c in SCOPE_CIDRS)
    if _DOMAIN_RE.match(t):
        return any(t.endswith("." + d) or t == d for d in SCOPE_DOMAINS)
    return False


# ---------- result type ----------
@dataclass
class ToolResult:
    tool: str
    target: str
    scan_id: str
    started_at: float
    finished_at: float
    duration_s: float
    returncode: int
    ok: bool
    timed_out: bool
    scope_violation: bool
    rate_limited: bool
    stdout_excerpt: str  # cap to 16KB
    stderr_excerpt: str
    parsed: list[dict[str, Any]] = field(default_factory=list)  # parsed records
    raw_count: int = 0
    ruflo_pattern_id: str | None = None
    error: str | None = None


# ---------- output parsing ----------
def _parse_jsonl(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _parse_xml(text: str) -> list[dict[str, Any]]:
    """Coarse XML -> list of dicts. Good enough for nmap/sqlmap style outputs."""
    try:
        root = ET.fromstring(text)
    except Exception:
        return [{"_raw": text[:2000]}]
    return [{"_xml_tag": root.tag, "_xml_text": (root.text or "")[:500]}]


def _parse_output(spec: ToolSpec, stdout: str) -> list[dict[str, Any]]:
    if spec.output_format == "jsonl":
        return _parse_jsonl(stdout)
    if spec.output_format == "json":
        # nuclei/dalfox sometimes wrap multiple JSON objects in a single
        # response — split heuristically.
        try:
            v = json.loads(stdout)
            if isinstance(v, list):
                return v
            return [v]
        except Exception:
            return _parse_jsonl(stdout)
    if spec.output_format == "xml":
        return _parse_xml(stdout)
    # text — agent-specific parsing is up to the agent
    return [{"_text": stdout[:8192]}]


# ---------- argument substitution ----------
_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _render_args(template: list[str], params: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for a in template:
        for _ in range(64):  # bounded repeat to defeat {{}} attacks
            new = _PLACEHOLDER_RE.sub(lambda m: str(params.get(m.group(1), m.group(0))), a)
            if new == a:
                break
            a = new
        out.append(a)
    # append extra kwargs
    for k, v in params.items():
        if k.startswith("-"):
            out.extend([k, str(v)])
    return out


# ---------- main entry ----------
class ToolExecutor:
    def __init__(self, *, engagement_mode: str | None = None) -> None:
        self.engagement_mode = engagement_mode or ENGAGEMENT_MODE
        # bind Ruflo functions locally to avoid circular import surprises
        self._hook_pre = ruflo.hook_pre
        self._hook_post = ruflo.hook_post
        self._pattern_store = ruflo.pattern_store
        self._neural_train = ruflo.neural_train
        self._memory_store = ruflo.memory_store
        self._agent_spawn = ruflo.agent_spawn

    def _resolve_binary(self, spec: ToolSpec) -> str | None:
        # 1. toolbox bin
        cand = Path(TOOLBOX_BIN) / spec.binary
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
        # 2. PATH
        which = shutil.which(spec.binary)
        return which

    async def run(
        self,
        tool_name: str,
        params: dict[str, Any] | None = None,
        *,
        scan_id: str = "",
        target: str = "",
        timeout: int | None = None,
        engagement_mode: str | None = None,
        agent: str = "tool-executor",
    ) -> ToolResult:
        params = params or {}
        mode = engagement_mode or self.engagement_mode
        spec = get_tool_spec(tool_name)
        if not spec:
            return ToolResult(
                tool=tool_name, target=target, scan_id=scan_id,
                started_at=time.time(), finished_at=time.time(),
                duration_s=0.0, returncode=-1, ok=False, timed_out=False,
                scope_violation=False, rate_limited=False,
                stdout_excerpt="", stderr_excerpt=f"unknown tool: {tool_name}",
                error="unknown tool",
            )
        if not spec.is_allowed_in(mode):
            return ToolResult(
                tool=tool_name, target=target, scan_id=scan_id,
                started_at=time.time(), finished_at=time.time(),
                duration_s=0.0, returncode=-2, ok=False, timed_out=False,
                scope_violation=False, rate_limited=False,
                stdout_excerpt="", stderr_excerpt=f"disallowed in mode={mode}",
                error="engagement mode violation",
            )

        # Scope check
        if target and not _in_scope(target):
            return ToolResult(
                tool=tool_name, target=target, scan_id=scan_id,
                started_at=time.time(), finished_at=time.time(),
                duration_s=0.0, returncode=-3, ok=False, timed_out=False,
                scope_violation=True, rate_limited=False,
                stdout_excerpt="", stderr_excerpt="target not in engagement scope",
                error="scope violation",
            )

        # Rate limit
        if not _allow_rate(spec):
            return ToolResult(
                tool=tool_name, target=target, scan_id=scan_id,
                started_at=time.time(), finished_at=time.time(),
                duration_s=0.0, returncode=-4, ok=False, timed_out=False,
                scope_violation=False, rate_limited=True,
                stdout_excerpt="", stderr_excerpt="rate limited (per-minute cap)",
                error="rate limited",
            )

        bin_path = self._resolve_binary(spec)
        if not bin_path:
            return ToolResult(
                tool=tool_name, target=target, scan_id=scan_id,
                started_at=time.time(), finished_at=time.time(),
                duration_s=0.0, returncode=-5, ok=False, timed_out=False,
                scope_violation=False, rate_limited=False,
                stdout_excerpt="", stderr_excerpt=f"binary not found: {spec.binary}",
                error="binary missing",
            )

        args = _render_args(spec.args_template, params)
        timeout = int(timeout or spec.timeout_default_s)

        # Ruflo hook_pre
        try:
            self._hook_pre(f"{spec.category}:{spec.name}")
        except Exception:
            pass

        started = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                bin_path, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await proc.wait()
                except Exception:
                    pass
                return self._finalize(
                    spec, scan_id, target, started, time.time(),
                    returncode=-6, ok=False, timed_out=True, scope_violation=False, rate_limited=False,
                    stdout=b"", stderr=f"timeout after {timeout}s".encode(),
                    error="timeout",
                )
            stdout = stdout_b.decode("utf-8", errors="replace") if stdout_b else ""
            stderr = stderr_b.decode("utf-8", errors="replace") if stderr_b else ""
            ok = proc.returncode == 0 or _looks_like_findings(spec, stdout)
            parsed = _parse_output(spec, stdout)
            result = ToolResult(
                tool=spec.name, target=target, scan_id=scan_id,
                started_at=started, finished_at=time.time(),
                duration_s=round(time.time() - started, 3),
                returncode=proc.returncode or 0, ok=ok, timed_out=False,
                scope_violation=False, rate_limited=False,
                stdout_excerpt=stdout[:16384], stderr_excerpt=stderr[:4096],
                parsed=parsed, raw_count=len(parsed),
            )
        except FileNotFoundError as e:
            result = ToolResult(
                tool=spec.name, target=target, scan_id=scan_id,
                started_at=started, finished_at=time.time(),
                duration_s=round(time.time() - started, 3),
                returncode=-7, ok=False, timed_out=False,
                scope_violation=False, rate_limited=False,
                stdout_excerpt="", stderr_excerpt=str(e), error="executable not found",
            )
        except Exception as e:
            result = ToolResult(
                tool=spec.name, target=target, scan_id=scan_id,
                started_at=started, finished_at=time.time(),
                duration_s=round(time.time() - started, 3),
                returncode=-8, ok=False, timed_out=False,
                scope_violation=False, rate_limited=False,
                stdout_excerpt="", stderr_excerpt=str(e)[:1000], error=str(e)[:200],
            )

        return self._finalize(
            spec, scan_id, target, started, result.finished_at,
            result.returncode, result.ok, result.timed_out,
            result.scope_violation, result.rate_limited,
            result.stdout_excerpt.encode("utf-8", "replace"),
            result.stderr_excerpt.encode("utf-8", "replace"),
            parsed=result.parsed, error=result.error,
        )

    def _finalize(
        self, spec, scan_id, target, started, finished,
        returncode, ok, timed_out, scope_violation, rate_limited,
        stdout_b, stderr_b, *, parsed=None, error=None,
    ) -> ToolResult:
        parsed = parsed or []
        stdout_text = stdout_b.decode("utf-8", errors="replace") if isinstance(stdout_b, (bytes, bytearray)) else stdout_b
        stderr_text = stderr_b.decode("utf-8", errors="replace") if isinstance(stderr_b, (bytes, bytearray)) else stderr_b
        duration = round(finished - started, 3)

        # Ruflo hook_post
        try:
            self._hook_post(f"{spec.category}:{spec.name}")
        except Exception:
            pass

        # Ruflo neural_train
        try:
            self._neural_train(
                agent=f"{spec.category}:{spec.name}",
                scan_id=scan_id or "(no-scan)",
                target=target or "(no-target)",
                ok=ok and not timed_out and not scope_violation,
                duration_s=duration,
            )
        except Exception:
            pass

        # Ruflo pattern_store
        ruflo_pattern_id = None
        try:
            self._pattern_store(
                agent=spec.name,
                pattern=f"{spec.category} on {target}"[:200],
                confidence=0.95 if (ok and parsed) else (0.4 if ok else 0.1),
            )
            ruflo_pattern_id = str(uuid.uuid4())[:12]
        except Exception:
            pass

        # Ruflo memory_store for high-signal results
        if ok and parsed and len(parsed) > 0 and scan_id:
            try:
                self._memory_store(
                    key=f"{scan_id}:{spec.name}",
                    value=f"{spec.name} found {len(parsed)} records on {target}"[:200],
                    tags=[spec.category, target, scan_id[:8]],
                )
            except Exception:
                pass

        return ToolResult(
            tool=spec.name, target=target, scan_id=scan_id,
            started_at=started, finished_at=finished,
            duration_s=duration, returncode=returncode,
            ok=ok and not timed_out and not scope_violation and not rate_limited,
            timed_out=timed_out, scope_violation=scope_violation,
            rate_limited=rate_limited,
            stdout_excerpt=stdout_text[:16384] if stdout_text else "",
            stderr_excerpt=stderr_text[:4096] if stderr_text else "",
            parsed=parsed, raw_count=len(parsed),
            ruflo_pattern_id=ruflo_pattern_id, error=error,
        )


def _looks_like_findings(spec: ToolSpec, stdout: str) -> bool:
    """Some tools (nuclei, sqlmap) exit non-zero but produce useful output."""
    if not stdout:
        return False
    if spec.output_format == "jsonl":
        for line in stdout.splitlines()[:5]:
            if line.strip().startswith("{"):
                return True
    return False
