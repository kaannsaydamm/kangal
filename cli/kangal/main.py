"""Kangal Dashboard CLI — Click entry point.

Layout:
  kangal scan (list | get | start | events)
  kangal intel (search | patterns | memory list | memory search)
  kangal engagement (list | get | create | scope-check | panic)
  kangal tool (list | run | install | info)
  kangal shell (sessions | open | close)
  kangal system (diag | onboard | install)
  kangal toolbox (summary)

Global flags:
  --json   emit raw JSON to stdout instead of tables

Exit codes:
  0   success
  1   backend returned an error (4xx/5xx)
  2   backend unreachable / network failure
  3   invalid user input
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import Any, Optional

import click

from . import api as api_mod
from .api import Backend, BackendError, BackendUnreachable
from .format import (
    print_err,
    print_json,
    print_kv,
    print_table,
    truncate,
    yesno,
)


# ----------------------------------------------------------------------------
# Shared: a process-wide Backend singleton for the duration of a Click run.
# Click guarantees the `@click.pass_context` is the same `ctx` for the whole
# invocation, so we stash the client on `ctx.obj` and reuse it.
# ----------------------------------------------------------------------------


def _get_backend(ctx: click.Context) -> Backend:
    obj = ctx.obj or {}
    if "backend" not in obj:
        obj["backend"] = Backend()
        ctx.obj = obj
    return obj["backend"]  # type: ignore[return-value]


def _as_json(ctx: click.Context) -> bool:
    obj = ctx.obj or {}
    return bool(obj.get("json"))


def _emit(ctx: click.Context, data: Any, *, render) -> None:
    """Either dump JSON (--json) or call the human formatter."""
    if _as_json(ctx):
        print_json(data)
        return
    render(data)


def _err_exit(msg: str, code: int = 1) -> None:
    print_err(msg)
    sys.exit(code)


# ----------------------------------------------------------------------------
# Top-level group
# ----------------------------------------------------------------------------


@click.group(help="Kangal Dashboard CLI — drive the Kangal backend from your terminal.")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Emit raw JSON to stdout (machine-friendly).")
@click.option("--backend-url", default=None,
              help="Override KANGAL_BACKEND_URL for this invocation.")
@click.pass_context
def cli(ctx: click.Context, as_json: bool, backend_url: Optional[str]) -> None:
    ctx.ensure_object(dict)
    ctx.obj["json"] = as_json
    if backend_url:
        os.environ["KANGAL_BACKEND_URL"] = backend_url


# Wrap every subcommand so Backend* exceptions get translated into
# friendly stderr messages + correct exit codes.
class _BackendAwareGroup(click.Group):
    """Click Group that catches BackendError / BackendUnreachable globally."""

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except BackendUnreachable as e:
            _err_exit(str(e), 2)
        except BackendError as e:
            _err_exit(str(e), 1)
        except SystemExit:
            # Click uses SystemExit to signal --help and clean exits.
            raise
        except click.exceptions.Exit:
            raise
        except (UnicodeEncodeError, OSError) as e:
            # Last-resort: rendering with non-UTF-8 terminal surfaces
            # UnicodeEncodeError out of rich. Print a hint instead of dumping
            # a 5 KB stack trace.
            _err_exit(f"output encoding error: {e}", 1)
        except Exception as e:  # noqa: BLE001 — final guard
            _err_exit(f"unexpected error: {e}", 1)


# Replace the auto-generated `cli` class with our error-aware one.
cli.__class__ = _BackendAwareGroup
cli.result_callback = None  # silence any default callback plumbing


# ----------------------------------------------------------------------------
# scan
# ----------------------------------------------------------------------------


@cli.group()
def scan() -> None:
    """Scan lifecycle: list / get / start / events."""


@scan.command("list")
@click.option("--limit", default=50, show_default=True)
@click.pass_context
def scan_list(ctx: click.Context, limit: int) -> None:
    """List recent scans."""
    rows = _get_backend(ctx).get("/api/scans", params={"limit": limit})

    def render(data):
        if not data:
            click.echo("(no scans yet)")
            return
        rows_view = [
            (
                truncate(r.get("id"), 36),
                truncate(r.get("target"), 32),
                r.get("mode", ""),
                r.get("status", ""),
                truncate(r.get("started_at") or "", 19),
            )
            for r in data
        ]
        print_table(
            ["SCAN ID", "TARGET", "MODE", "STATUS", "STARTED"],
            rows_view,
        )

    _emit(ctx, rows, render=render)


@scan.command("get")
@click.argument("scan_id")
@click.pass_context
def scan_get(ctx: click.Context, scan_id: str) -> None:
    """Get scan details + stats."""
    data = _get_backend(ctx).get(f"/api/scan/{scan_id}")

    def render(d):
        kv = [
            ("ID", d.get("id")),
            ("TARGET", d.get("target")),
            ("MODE", d.get("mode")),
            ("STATUS", d.get("status")),
            ("STAGE", d.get("current_stage")),
            ("STARTED", d.get("started_at")),
            ("FINISHED", d.get("finished_at")),
            ("ERROR", d.get("error") or ""),
        ]
        print_kv(kv)
        stats = d.get("stats") or {}
        if stats:
            click.echo("")
            click.echo("STATS")
            print_kv(sorted(stats.items()))

    _emit(ctx, data, render=render)


@scan.command("start")
@click.argument("target")
@click.option(
    "--mode",
    type=click.Choice(["passive", "active", "web_only", "network_only", "full_spectrum"]),
    default="active",
    show_default=True,
)
@click.option("--engagement", default=None, help="Engagement ID to bind to this scan.")
@click.option("--wait", is_flag=True, default=False, help="Poll until the scan completes.")
@click.pass_context
def scan_start(
    ctx: click.Context,
    target: str,
    mode: str,
    engagement: Optional[str],
    wait: bool,
) -> None:
    """Queue a new scan against <target>."""
    payload: dict[str, Any] = {"target": target, "mode": mode}
    if engagement:
        payload["engagement_id"] = engagement
    res = _get_backend(ctx).post("/api/scan", json=payload)
    scan_id = (res or {}).get("scan_id", "")

    def render(d):
        click.echo(f"queued scan {d.get('scan_id')} ({d.get('mode')}) target={d.get('target')}")
        click.echo(f"status: {d.get('status')}")

    _emit(ctx, res, render=render)

    if wait and scan_id:
        _wait_for_scan(ctx, scan_id)


def _wait_for_scan(ctx: click.Context, scan_id: str, poll_s: float = 2.0) -> None:
    """Poll /api/scan/<id> until status is terminal."""
    backend = _get_backend(ctx)
    terminal = {"completed", "failed", "stopped", "error"}
    while True:
        try:
            data = backend.get(f"/api/scan/{scan_id}")
        except BackendError as e:
            click.echo(f"poll error: {e}", err=True)
            return
        status = (data or {}).get("status", "")
        click.echo(f"… status={status}")
        if status in terminal:
            return
        time.sleep(poll_s)


@scan.command("events")
@click.argument("scan_id")
@click.option("--follow/--no-follow", default=False)
@click.option("--tail", default=0, type=int, help="Show only the last N events.")
@click.pass_context
def scan_events(
    ctx: click.Context,
    scan_id: str,
    follow: bool,
    tail: int,
) -> None:
    """Print scan events. With --follow, stream new events as they arrive."""
    backend = _get_backend(ctx)
    since = 0

    def fetch():
        return backend.get(f"/api/scan/{scan_id}/events", params={"since": since})

    try:
        events = fetch() or []
    except BackendError as e:
        _err_exit(str(e), 1)
        return

    if tail and len(events) > tail:
        events = events[-tail:]

    def render(rows):
        if not rows:
            click.echo("(no events)")
            return
        view = [
            (
                truncate(e.get("ts") or "", 19),
                e.get("stage", ""),
                e.get("level", ""),
                truncate(e.get("message", ""), 200),
            )
            for e in rows
        ]
        print_table(["TS", "STAGE", "LEVEL", "MESSAGE"], view)

    _emit(ctx, events, render=render)
    since += len(events)

    if follow:
        # Cheap polling tail. A WS implementation would replace this.
        click.echo("(streaming — Ctrl-C to exit)")
        try:
            while True:
                time.sleep(2.0)
                try:
                    more = fetch() or []
                except BackendError as e:
                    click.echo(f"follow error: {e}", err=True)
                    return
                if not more:
                    continue
                if _as_json(ctx):
                    print_json(more)
                else:
                    render(more)
                since += len(more)
        except KeyboardInterrupt:
            return


# ----------------------------------------------------------------------------
# intel
# ----------------------------------------------------------------------------


@cli.group()
def intel() -> None:
    """Cross-scan intel store: search, patterns, memory."""


@intel.command("search")
@click.argument("query")
@click.option("--limit", default=25, show_default=True)
@click.pass_context
def intel_search(ctx: click.Context, query: str, limit: int) -> None:
    """Search the cross-scan intel store."""
    res = _get_backend(ctx).get(
        "/api/intel/search", params={"q": query, "limit": limit}
    )

    def render(d):
        results = (d or {}).get("results") or []
        if not results:
            click.echo("(no matches)")
            return
        rows = [
            (
                truncate(r.get("id", ""), 36),
                truncate(r.get("kind", ""), 20),
                truncate(r.get("summary", r.get("title", "")), 80),
            )
            for r in results
        ]
        print_table(["ID", "KIND", "SUMMARY"], rows)

    _emit(ctx, res, render=render)


@intel.command("patterns")
@click.option("--limit", default=50, show_default=True)
@click.pass_context
def intel_patterns(ctx: click.Context, limit: int) -> None:
    """List stored recon patterns."""
    res = _get_backend(ctx).get("/api/intel/patterns", params={"limit": limit})

    def render(d):
        patterns = (d or {}).get("patterns") or []
        if not patterns:
            click.echo("(no patterns yet)")
            return
        rows = [
            (
                truncate(p.get("name", p.get("id", "")), 40),
                truncate(p.get("agent", ""), 16),
                truncate(p.get("target_kind", p.get("target", "")), 24),
                p.get("confidence", ""),
            )
            for p in patterns
        ]
        print_table(["PATTERN", "AGENT", "TARGET", "CONFIDENCE"], rows)

    _emit(ctx, res, render=render)


@intel.group("memory")
def intel_memory() -> None:
    """Ruflo-style memory: list / search."""


@intel_memory.command("list")
@click.pass_context
def intel_memory_list(ctx: click.Context) -> None:
    """Return memory-store summary (counts)."""
    res = _get_backend(ctx).get("/api/ruflo/memory/stats")

    def render(d):
        if not d:
            click.echo("(empty)")
            return
        kv = sorted((d or {}).items())
        print_kv(kv)

    _emit(ctx, res, render=render)


@intel_memory.command("search")
@click.argument("query")
@click.option("--limit", default=20, show_default=True)
@click.pass_context
def intel_memory_search(ctx: click.Context, query: str, limit: int) -> None:
    """Search the ruflo memory store."""
    res = _get_backend(ctx).get(
        "/api/ruflo/memory/search", params={"q": query, "limit": limit}
    )

    def render(d):
        results = (d or {}).get("results") or []
        if not results:
            click.echo("(no matches)")
            return
        rows = [
            (
                truncate(r.get("id", ""), 36),
                truncate(r.get("kind", r.get("type", "")), 16),
                truncate(r.get("content", r.get("summary", "")), 80),
            )
            for r in results
        ]
        print_table(["ID", "KIND", "CONTENT"], rows)

    _emit(ctx, res, render=render)


# ----------------------------------------------------------------------------
# engagement
# ----------------------------------------------------------------------------


@cli.group()
def engagement() -> None:
    """Engagement manager: scope guard, kill switch, panic."""


@engagement.command("list")
@click.pass_context
def engagement_list(ctx: click.Context) -> None:
    """List active engagements."""
    res = _get_backend(ctx).get("/api/engagement")

    def render(d):
        # ruflo.engagement_status() returns either:
        #   {"engagements": [...]}        — when called without an id
        #   {"active": {id: engagement}, "count": N}  — registry dict
        #   a single engagement dict      — when called with an id (unlikely here)
        items: list[dict] = []
        if isinstance(d, dict):
            if isinstance(d.get("engagements"), list):
                items = d["engagements"]
            elif isinstance(d.get("active"), dict):
                items = list(d["active"].values())
            elif d and "id" in d:
                items = [d]
        elif isinstance(d, list):
            items = d
        if not items:
            click.echo("(no engagements)")
            return
        rows = [
            (
                truncate(e.get("id", ""), 36),
                e.get("name", ""),
                e.get("client", ""),
                e.get("operator", ""),
                e.get("status", ""),
                truncate(",".join(e.get("scope_domains", []) or []), 40),
            )
            for e in items
        ]
        print_table(["ID", "NAME", "CLIENT", "OPERATOR", "STATUS", "DOMAINS"], rows)

    _emit(ctx, res, render=render)


@engagement.command("get")
@click.argument("engagement_id")
@click.pass_context
def engagement_get(ctx: click.Context, engagement_id: str) -> None:
    """Get engagement details."""
    res = _get_backend(ctx).get(f"/api/engagement/{engagement_id}")

    def render(d):
        kv = sorted((d or {}).items())
        print_kv(kv)

    _emit(ctx, res, render=render)


@engagement.command("create")
@click.option("--name", required=True)
@click.option("--client", required=True)
@click.option("--operator", "operator", required=True)
@click.option("--scope-domains", default=None, help="Comma-separated domain list.")
@click.option("--scope-cidrs", default=None, help="Comma-separated CIDR list.")
@click.option("--profile", default="full_spectrum", show_default=True)
@click.option("--destructive", is_flag=True, default=False)
@click.pass_context
def engagement_create(
    ctx: click.Context,
    name: str,
    client: str,
    operator: str,
    scope_domains: Optional[str],
    scope_cidrs: Optional[str],
    profile: str,
    destructive: bool,
) -> None:
    """Create a new engagement (scope guard + profile)."""
    payload: dict[str, Any] = {
        "name": name,
        "client": client,
        "operator": operator,
        "profile": profile,
        "destructive_allowed": destructive,
        "scope_domains": [d.strip() for d in (scope_domains or "").split(",") if d.strip()],
        "scope_cidrs": [c.strip() for c in (scope_cidrs or "").split(",") if c.strip()],
    }
    res = _get_backend(ctx).post("/api/engagement", json=payload)

    def render(d):
        click.echo(f"created engagement: {d.get('id')} (status={d.get('status')})")

    _emit(ctx, res, render=render)


@engagement.command("scope-check")
@click.argument("target")
@click.option("--engagement", "engagement_id", default=None)
@click.pass_context
def engagement_scope_check(
    ctx: click.Context, target: str, engagement_id: Optional[str]
) -> None:
    """Check whether a target is in scope for the current engagement."""
    payload = {"target": target, "engagement_id": engagement_id}
    res = _get_backend(ctx).post("/api/engagement/scope-check", json=payload)

    def render(d):
        ok = bool(d.get("in_scope"))
        msg = "IN SCOPE" if ok else "OUT OF SCOPE"
        print_kv(
            [
                ("TARGET", d.get("target")),
                ("RESULT", msg),
                ("REASON", d.get("reason", "")),
            ]
        )

    _emit(ctx, res, render=render)


@engagement.command("panic")
@click.argument("engagement_id")
@click.confirmation_option(prompt="Type 'panic' to confirm kill switch")
@click.pass_context
def engagement_panic(ctx: click.Context, engagement_id: str) -> None:
    """Kill switch — stop the engagement + all its swarms."""
    res = _get_backend(ctx).post(f"/api/engagement/{engagement_id}/panic")

    def render(d):
        click.echo(f"PANIC: {json.dumps(d, default=str)}")

    _emit(ctx, res, render=render)


# ----------------------------------------------------------------------------
# tool (interactive toolbox)
# ----------------------------------------------------------------------------


@cli.group()
def tool() -> None:
    """Toolbox: list, run, install, inspect."""


@tool.command("list")
@click.option("--category", default=None)
@click.option("--tier", type=click.Choice(["1", "2"]), default=None)
@click.option("--search", "q", default=None, help="Substring filter on name.")
@click.pass_context
def tool_list(
    ctx: click.Context,
    category: Optional[str],
    tier: Optional[str],
    q: Optional[str],
) -> None:
    """List tools. Optionally filter by category / tier / substring."""
    params: dict[str, Any] = {}
    if category:
        params["category"] = category
    if tier:
        params["tier"] = int(tier)
    res = _get_backend(ctx).get("/api/toolbox/tools", params=params)

    def render(d):
        items = (d or {}).get("tools") or []
        if q:
            ql = q.lower()
            items = [t for t in items if ql in (t.get("name") or "").lower()]
        if not items:
            click.echo("(no tools)")
            return
        rows = [
            (
                t.get("name", ""),
                t.get("tier", ""),
                t.get("category", ""),
                t.get("binary", ""),
                yesno(t.get("requires_root", False)),
                truncate(",".join(t.get("engagement_modes") or []), 30),
            )
            for t in items
        ]
        print_table(
            ["NAME", "TIER", "CATEGORY", "BINARY", "ROOT", "MODES"],
            rows,
        )

    _emit(ctx, res, render=render)


@tool.command("run")
@click.argument("name")
@click.argument("args", nargs=-1)
@click.option("--target", default="", help="Engagement target (if applicable).")
@click.option("--scan-id", default="")
@click.option("--engagement-mode", default=None)
@click.option("--timeout", default=None, type=int)
@click.pass_context
def tool_run(
    ctx: click.Context,
    name: str,
    args: tuple[str, ...],
    target: str,
    scan_id: str,
    engagement_mode: Optional[str],
    timeout: Optional[int],
) -> None:
    """Run a tool synchronously via /api/toolbox/execute.

    Extra positional ARGS are joined into a `params.args` list.
    """
    params: dict[str, Any] = {"args": list(args)}
    payload: dict[str, Any] = {
        "tool": name,
        "params": params,
        "target": target,
        "scan_id": scan_id,
    }
    if engagement_mode:
        payload["engagement_mode"] = engagement_mode
    if timeout:
        payload["timeout"] = timeout

    res = _get_backend(ctx).post("/api/toolbox/execute", json=payload)

    def render(d):
        kv = [
            ("TOOL", d.get("tool")),
            ("OK", yesno(bool(d.get("ok")))),
            ("RETURNCODE", d.get("returncode")),
            ("DURATION_S", d.get("duration_s")),
            ("TIMED_OUT", yesno(bool(d.get("timed_out")))),
            ("SCOPE_VIOLATION", yesno(bool(d.get("scope_violation")))),
            ("RATE_LIMITED", yesno(bool(d.get("rate_limited")))),
            ("RUFLO_PATTERN_ID", d.get("ruflo_pattern_id") or ""),
            ("ERROR", d.get("error") or ""),
        ]
        print_kv(kv)
        parsed = d.get("parsed") or []
        if parsed:
            click.echo("")
            click.echo("PARSED (first 50):")
            print_json(parsed[:50])
        stdout = d.get("stdout_excerpt") or ""
        if stdout:
            click.echo("")
            click.echo("STDOUT (excerpt):")
            click.echo(stdout)
        stderr = d.get("stderr_excerpt") or ""
        if stderr:
            click.echo("")
            click.echo("STDERR (excerpt):")
            click.echo(stderr)

    _emit(ctx, res, render=render)


@tool.command("install")
@click.argument("name")
@click.pass_context
def tool_install(ctx: click.Context, name: str) -> None:
    """Trigger a background install for a single binary."""
    res = _get_backend(ctx).post(f"/api/system/install/{name}")

    def render(d):
        click.echo(f"install_id={d.get('install_id')} status={d.get('status')}")
        if d.get("command"):
            click.echo(f"command: {' '.join(d.get('command') or [])}")

    _emit(ctx, res, render=render)


@tool.command("info")
@click.argument("name")
@click.pass_context
def tool_info(ctx: click.Context, name: str) -> None:
    """Show full detail for one tool."""
    res = _get_backend(ctx).get("/api/toolbox/tools")
    match = None
    if isinstance(res, dict):
        for t in res.get("tools") or []:
            if t.get("name") == name:
                match = t
                break

    def render(d):
        if not d:
            click.echo(f"(tool not found: {name})")
            return
        kv = sorted(d.items())
        print_kv(kv)

    _emit(ctx, match or {"error": "not found"}, render=render)


# ----------------------------------------------------------------------------
# shell
# ----------------------------------------------------------------------------


@cli.group()
def shell() -> None:
    """Interactive PTY-backed bash sessions."""


@shell.command("sessions")
@click.pass_context
def shell_sessions(ctx: click.Context) -> None:
    """List live shell sessions."""
    res = _get_backend(ctx).get("/api/shell/sessions")

    def render(d):
        items = (d or {}).get("sessions") or []
        if not items:
            click.echo("(no sessions)")
            return
        rows = [
            (
                s.get("session_id", ""),
                s.get("cols", ""),
                s.get("rows", ""),
                s.get("created_at", ""),
                "yes" if s.get("alive", True) else "no",
            )
            for s in items
        ]
        print_table(["SESSION_ID", "COLS", "ROWS", "CREATED", "ALIVE"], rows)

    _emit(ctx, res, render=render)


@shell.command("open")
@click.option("--cols", default=120, show_default=True)
@click.option("--rows", default=32, show_default=True)
@click.pass_context
def shell_open(ctx: click.Context, cols: int, rows: int) -> None:
    """Create a new shell session and stream PTY output to the local terminal."""
    backend = _get_backend(ctx)
    try:
        info = backend.post(
            "/api/shell/sessions", json={"cols": cols, "rows": rows}
        )
    except BackendError as e:
        # 501 = backend on unsupported host (e.g. native Windows). Friendly msg.
        if e.status_code == 501:
            _err_exit(
                "Backend host does not support PTY shells. "
                "Run the backend inside Docker / WSL / Linux.",
                1,
            )
            return
        raise
    session_id = (info or {}).get("session_id", "")
    click.echo(f"session_id: {session_id}")
    if not session_id:
        return

    if _as_json(ctx):
        # Non-interactive mode: just print the handshake payload and exit.
        print_json(info)
        return

    # Interactive PTY pump: connect WS, stream base64-decoded bytes to stdout.
    _stream_shell_ws(backend, session_id)


def _stream_shell_ws(backend: Backend, session_id: str) -> None:
    """Bridge a Kangal PTY shell session into this terminal's stdout.

    Uses the `websocket-client` lib if available; otherwise falls back
    to a minimal hand-rolled frame parser (only what we need: text frames).
    """
    import base64
    import socket
    import ssl
    from urllib.parse import urlparse

    url = backend.ws_url(f"/ws/shell/{session_id}")
    click.echo(f"(connected to {url}; Ctrl-C to detach)")
    click.echo("")

    try:
        from websocket import create_connection  # type: ignore
        _run_ws_with_lib(session_id, create_connection, url)
        return
    except ImportError:
        pass

    # Fallback: hand-rolled WS client (text frames only).
    _run_ws_handrolled(session_id, url, base64)


def _run_ws_with_lib(session_id, create_connection, url: str) -> None:
    """Use `websocket-client` if installed. Most pleasant experience."""
    import base64

    ws = create_connection(url, timeout=None)
    try:
        while True:
            raw = ws.recv()
            if not raw:
                break
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            kind = msg.get("kind")
            if kind == "out":
                sys.stdout.buffer.write(base64.b64decode(msg.get("data", "")))
                sys.stdout.buffer.flush()
            elif kind == "open":
                pass
            elif kind == "exit":
                click.echo("")
                click.echo(f"(shell exited: code={msg.get('code')})")
                return
            elif kind == "error":
                click.echo(f"(server error: {msg.get('message')})", err=True)
                return
            elif kind == "pong":
                pass
    except KeyboardInterrupt:
        click.echo("")
        click.echo("(detached; bash still running on backend)")
    finally:
        try:
            ws.close()
        except Exception:
            pass


def _run_ws_handrolled(session_id: str, url: str, base64_mod) -> None:
    """Minimal WS client for when `websocket-client` isn't installed.

    Supports text frames only (the shell WS uses text JSON frames with
    base64 payload inside `data`).  We don't bother with fragmentation
    or pings — bash sessions are short-lived enough that simple blocking
    recv() calls work in practice.
    """
    import base64 as _b64
    import os as _os
    import socket as _socket
    import struct as _struct

    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    use_ssl = parsed.scheme == "wss"

    sock = _socket.create_connection((host, port), timeout=None)
    if use_ssl:
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)

    key = _b64.b64encode(_os.urandom(16)).decode("ascii")
    req = (
        f"GET {parsed.path or '/'} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    sock.sendall(req.encode("ascii"))

    # Read handshake response (until \r\n\r\n).
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("WS handshake failed")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")

    try:
        while True:
            data = rest
            rest = b""
            while len(data) < 2:
                chunk = sock.recv(4096)
                if not chunk:
                    return
                data += chunk
            b1, b2 = data[0], data[1]
            opcode = b1 & 0x0F
            masked = (b2 & 0x80) != 0
            length = b2 & 0x7F
            idx = 2
            if length == 126:
                while len(data) < idx + 2:
                    data += sock.recv(4096)
                length = _struct.unpack(">H", data[idx:idx + 2])[0]
                idx += 2
            elif length == 127:
                while len(data) < idx + 8:
                    data += sock.recv(4096)
                length = _struct.unpack(">Q", data[idx:idx + 8])[0]
                idx += 8
            if masked:
                while len(data) < idx + 4:
                    data += sock.recv(4096)
                mask = data[idx:idx + 4]
                idx += 4
            while len(data) < idx + length:
                data += sock.recv(4096)
            payload = data[idx:idx + length]
            if masked:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:  # close
                return
            if opcode == 0x1:  # text
                try:
                    msg = json.loads(payload.decode("utf-8", errors="replace"))
                except Exception:
                    continue
                kind = msg.get("kind")
                if kind == "out":
                    sys.stdout.buffer.write(_b64.b64decode(msg.get("data", "")))
                    sys.stdout.buffer.flush()
                elif kind == "exit":
                    click.echo("")
                    click.echo(f"(shell exited: code={msg.get('code')})")
                    return
                elif kind == "error":
                    click.echo(f"(server error: {msg.get('message')})", err=True)
                    return
            # else: ignore ping/pong/binary
    except KeyboardInterrupt:
        click.echo("")
        click.echo("(detached; bash still running on backend)")


@shell.command("close")
@click.argument("session_id")
@click.pass_context
def shell_close(ctx: click.Context, session_id: str) -> None:
    """Kill a shell session on the backend."""
    res = _get_backend(ctx).delete(f"/api/shell/sessions/{session_id}")

    def render(d):
        click.echo(f"killed session: {d.get('session_id')} status={d.get('status')}")

    _emit(ctx, res, render=render)


# ----------------------------------------------------------------------------
# system
# ----------------------------------------------------------------------------


@cli.group()
def system() -> None:
    """Host capabilities, onboard wizard, install."""


@system.command("diag")
@click.option("--binary", default=None, help="Show one binary only.")
@click.pass_context
def system_diag(ctx: click.Context, binary: Optional[str]) -> None:
    """Print host capability matrix (host info + tool presence)."""
    backend = _get_backend(ctx)
    path = f"/api/system/diag/{binary}" if binary else "/api/system/diag"
    res = backend.get(path)

    def render(d):
        host = (d or {}).get("host") or {}
        if host:
            click.echo("PLATFORM       " + " ".join(
                [host.get("system", ""), host.get("release", "")]
            ).strip())
            print_kv(
                [
                    ("PLATFORM", f"{host.get('system', '')} {host.get('release', '')}".strip()),
                    ("WSL", "yes" if host.get("is_wsl") else "no"),
                    ("POSIX", "yes" if host.get("system") != "Windows" else "no"),
                    ("ADMIN/ROOT", "yes" if host.get("is_admin") else "no"),
                    ("PYTHON", host.get("python_version", "")),
                    ("NODE", ""),  # backend does not probe node currently
                    ("MACHINE", host.get("machine", "")),
                ]
            )
            click.echo("")

        bins = (d or {}).get("binaries") or {}
        if not bins:
            click.echo("(no binary information)")
            return
        rows = []
        for name in sorted(bins.keys()):
            info = bins.get(name) or {}
            rows.append(
                (
                    name,
                    yesno(bool(info.get("present"))),
                    info.get("version") or "",
                    info.get("install_cmd") or "",
                )
            )
        print_table(["BINARY", "PRESENT", "VERSION", "INSTALL CMD"], rows)

    _emit(ctx, res, render=render)


@system.command("onboard")
@click.pass_context
def system_onboard(ctx: click.Context) -> None:
    """Interactive onboard wizard — drives /api/onboard/* state machine."""
    backend = _get_backend(ctx)
    if _as_json(ctx):
        # Non-interactive: just dump the current snapshot.
        state = backend.get("/api/onboard/state")
        print_json(state)
        return

    click.echo("Welcome. Press enter to start detection, or 'skip' to skip onboarding.")
    first = click.prompt("(enter / skip)", default="", show_default=False)
    if first.strip().lower() == "skip":
        backend.post("/api/onboard/choose-path", json={"path": "skip"})
        click.echo("Onboard skipped.")
        return

    # Refresh state — auto-welcome + detect are already populated.
    state = backend.get("/api/onboard/state") or {}
    detected = (state or {}).get("detected") or {}
    bins = (detected or {}).get("binaries") or {}
    if bins:
        click.echo("")
        click.echo("Detected capabilities:")
        rows = [
            (name, yesno(bool(info.get("present"))), info.get("version") or "")
            for name, info in sorted(bins.items())
        ]
        print_table(["BINARY", "PRESENT", "VERSION"], rows)

    click.echo("")
    click.echo("Choose install path: [1] native (apt/brew) [2] wsl [3] skip")
    choice = click.prompt("> ", default="1", show_default=False)
    path_map = {"1": "native", "2": "wsl", "3": "skip"}
    chosen = path_map.get(choice.strip(), "native")
    backend.post("/api/onboard/choose-path", json={"path": chosen})
    if chosen == "skip":
        click.echo("Onboard skipped.")
        return

    click.echo("")
    consent = click.prompt("Type 'yes i consent' to confirm", default="")
    try:
        backend.post("/api/onboard/consent", json={"consent_text": consent})
    except BackendError as e:
        _err_exit(f"consent rejected: {e}", 1)
        return

    # Recommendations.
    recs = (detected or {}).get("recommendations") or []
    if not recs:
        click.echo("No missing tools detected — nothing to install.")
    else:
        click.echo("")
        click.echo(f"Recommended tools to install: {', '.join(recs)}")
        if click.confirm("Install missing tools?", default=True):
            install_res = backend.post(
                "/api/onboard/install", json={"binaries": recs}
            ) or {}
            entries = install_res.get("installs") or []
            started = [
                e for e in entries
                if (e or {}).get("status") == "started" and e.get("install_id")
            ]
            if started:
                _poll_installs(backend, [e["install_id"] for e in started])

    backend.post("/api/onboard/finish")
    click.echo("Onboard complete.")


def _poll_installs(backend: Backend, install_ids: list[str], poll_s: float = 2.0) -> None:
    """Poll each install_id until it terminates. Prints incremental progress."""
    pending = list(install_ids)
    while pending:
        time.sleep(poll_s)
        still = []
        for iid in pending:
            try:
                s = backend.get(f"/api/system/install/{iid}/status")
            except BackendError:
                still.append(iid)
                continue
            status = (s or {}).get("status", "")
            completed = (s or {}).get("completed_count")
            total = (s or {}).get("total_count", "?")
            click.echo(f"  install {iid[:8]}…  status={status}  {completed}/{total}")
            if status in ("ok", "failed", "cancelled"):
                continue
            still.append(iid)
        pending = still


@system.command("install")
@click.argument("binary_name")
@click.pass_context
def system_install(ctx: click.Context, binary_name: str) -> None:
    """Install a single binary."""
    res = _get_backend(ctx).post(f"/api/system/install/{binary_name}")

    def render(d):
        click.echo(f"install_id={d.get('install_id')} status={d.get('status')}")

    _emit(ctx, res, render=render)


# ----------------------------------------------------------------------------
# toolbox summary
# ----------------------------------------------------------------------------


@cli.group()
def toolbox() -> None:
    """Toolbox aggregate views."""


@toolbox.command("summary")
@click.pass_context
def toolbox_summary(ctx: click.Context) -> None:
    """Show tier/category tool counts."""
    res = _get_backend(ctx).get("/api/toolbox/summary")

    def render(d):
        if not d:
            click.echo("(empty)")
            return
        click.echo(f"total: {d.get('total')}")
        bt = d.get("by_tier") or {}
        if bt:
            print_kv([(f"tier {k}", v) for k, v in sorted(bt.items())])
        bc = d.get("by_category") or {}
        if bc:
            click.echo("")
            print_kv([(k, v) for k, v in sorted(bc.items())])
        rp = d.get("registry_path")
        if rp:
            click.echo("")
            click.echo(f"registry: {rp}")

    _emit(ctx, res, render=render)


# ----------------------------------------------------------------------------
# Error routing
# ----------------------------------------------------------------------------


def _main() -> None:
    """Wrapper so we can translate Backend* exceptions into nice stderr."""
    try:
        cli(obj={}, standalone_mode=False)
    except BackendUnreachable as e:
        _err_exit(str(e), 2)
    except BackendError as e:
        _err_exit(str(e), 1)
    except click.ClickException as e:
        e.show()
        sys.exit(e.exit_code)
    except KeyboardInterrupt:
        click.echo("(interrupted)", err=True)
        sys.exit(130)


if __name__ == "__main__":
    _main()