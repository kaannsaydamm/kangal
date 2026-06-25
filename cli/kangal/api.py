"""HTTP client wrapper around the Kangal backend.

Re-uses a single `httpx.Client` per process (Click invocation) so that
the underlying connection pool is amortized across many subcommands.

Behavior contract:
  - GET/POST/DELETE/PUT  → return parsed JSON (dict/list) on 2xx
  - non-2xx               → raise `BackendError(message, status_code)`
  - network failure       → raise `BackendUnreachable(base_url)`

The `BackendError` and `BackendUnreachable` types are caught by the
top-level CLI entry point and turned into a friendly stderr message
with exit code 1 / 2.
"""
from __future__ import annotations

import os
from typing import Any

import httpx


DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT_S = 30.0


class BackendError(RuntimeError):
    """Raised when the backend returns a non-2xx response."""

    def __init__(self, message: str, status_code: int = 0, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class BackendUnreachable(RuntimeError):
    """Raised when the backend host is unreachable / connection refused."""

    def __init__(self, base_url: str) -> None:
        super().__init__(f"Backend not reachable at {base_url}")
        self.base_url = base_url


def base_url() -> str:
    """Resolve the backend base URL from the KANGAL_BACKEND_URL env var."""
    return os.getenv("KANGAL_BACKEND_URL", DEFAULT_BASE_URL).rstrip("/")


class Backend:
    """Thin façade over `httpx.Client` with explicit error semantics."""

    def __init__(self, url: str | None = None, timeout: float = DEFAULT_TIMEOUT_S) -> None:
        self.url = (url or base_url()).rstrip("/")
        self._client = httpx.Client(base_url=self.url, timeout=timeout)

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass

    def __enter__(self) -> "Backend":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ HTTP

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            r = self._client.request(method, path, **kwargs)
        except httpx.RequestError as e:
            # ConnectError, ReadTimeout, ConnectTimeout, RemoteProtocolError, …
            raise BackendUnreachable(self.url) from e

        if r.status_code >= 400:
            # Try to surface the backend's structured error if any.
            try:
                payload = r.json()
            except Exception:
                payload = r.text
            msg = f"{method} {path} → HTTP {r.status_code}"
            if isinstance(payload, dict) and "detail" in payload:
                msg = f"{msg}: {payload['detail']}"
            raise BackendError(msg, status_code=r.status_code, payload=payload)

        if r.status_code == 204 or not r.content:
            return None
        try:
            return r.json()
        except Exception:
            return r.text

    def get(self, path: str, **kwargs: Any) -> Any:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self._request("POST", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self._request("DELETE", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Any:
        return self._request("PUT", path, **kwargs)

    # ------------------------------------------------------------------ WS URL

    def ws_url(self, path: str) -> str:
        """Convert an HTTP base URL to a WebSocket URL.

        `path` is appended verbatim (e.g. "/ws/shell/abc" → "ws://…/ws/shell/abc").
        """
        base = self.url
        if base.startswith("https://"):
            base = "wss://" + base[len("https://"):]
        elif base.startswith("http://"):
            base = "ws://" + base[len("http://"):]
        return base.rstrip("/") + path