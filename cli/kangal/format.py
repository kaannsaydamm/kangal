"""Output formatting helpers — tables, kv, raw JSON.

Single source of truth for human-readable output so all subcommands look
the same. Keeps the formatting intentionally simple (column-aligned
spaces, no fancy unicode box drawing) so it survives less-capable
terminals and copy-paste into chat / tickets.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Iterable, Sequence


# Use rich if available (nicer colored tables), else fall back to plain text.
try:
    from rich.console import Console
    from rich.table import Table

    # Force UTF-8 on stdout/stderr so the unicode glyphs (✓/✗) we render
    # in yesno() don't blow up on legacy Windows consoles (cp1252/cp1254).
    import io as _io
    import sys as _sys

    try:
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        _sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        _RICH = Console(force_terminal=False, soft_wrap=True, file=_sys.stdout)
    except Exception:
        _RICH = Console(soft_wrap=True)
except Exception:  # pragma: no cover
    _RICH = None


def _err_console():
    """Return a stderr sink for errors."""
    if _RICH is not None:
        return _RICH
    return None


def print_json(data: Any) -> None:
    """Emit `data` as JSON to stdout (one-line, no trailing newline spam)."""
    json.dump(data, sys.stdout, default=str, indent=2, sort_keys=False)
    sys.stdout.write("\n")


def print_err(message: str) -> None:
    """Print a red error message to stderr (best-effort)."""
    if _RICH is not None:
        # Use a dedicated stderr Console so output doesn't bleed into stdout.
        try:
            err_console = Console(stderr=True)
            err_console.print(f"[red]{message}[/red]")
            return
        except Exception:
            pass
    sys.stderr.write(message + "\n")


def print_kv(rows: Iterable[tuple[str, Any]]) -> None:
    """Print KEY (left-padded) → value pairs.

    Used by `kangal system diag` for the host section.
    """
    items = [(str(k), "" if v is None else str(v)) for k, v in rows]
    if not items:
        return
    width = max(len(k) for k, _ in items)
    for k, v in items:
        sys.stdout.write(f"{k.ljust(width)}   {v}\n")


def _plain_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> None:
    """Column-aligned plain-text table.

    Each cell is stringified; columns are padded to the widest value.
    Long values are not truncated — we let them overflow on purpose.
    """
    if not headers:
        return
    str_rows = [["" if v is None else str(v) for v in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("-" * w for w in widths)
    sys.stdout.write(line + "\n")
    sys.stdout.write(sep + "\n")
    for row in str_rows:
        sys.stdout.write(
            "  ".join(
                cell.ljust(widths[i]) if i < len(widths) else cell
                for i, cell in enumerate(row)
            )
            + "\n"
        )


def print_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    title: str | None = None,
) -> None:
    """Print a tabular block of rows.

    `headers` is the column name list. `rows` is the data rows. When
    `rich` is available, render a colored table — otherwise fall back
    to a column-aligned plain-text rendering.
    """
    if _RICH is not None:
        t = Table(title=title, show_lines=False, header_style="bold")
        for h in headers:
            t.add_column(h, overflow="fold")
        for row in rows:
            t.add_row(*[("" if v is None else str(v)) for v in row])
        _RICH.print(t)
        return
    if title:
        sys.stdout.write(title + "\n")
    _plain_table(headers, rows)


def truncate(s: Any, n: int) -> str:
    """Trim a string for display. None becomes empty."""
    text = "" if s is None else str(s)
    if len(text) <= n:
        return text
    return text[: max(0, n - 1)] + "…"


def yesno(flag: bool) -> str:
    """Render a boolean as a check / cross."""
    if _RICH is not None:
        return "[green]✓[/green]" if flag else "[red]✗[/red]"
    return "✓" if flag else "✗"