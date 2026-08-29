"""Thin wrapper around :class:`fastmcp.FastMCP`.

Purpose: centralize server lifecycle (name, version, transport, startup/
shutdown hooks) and expose a single ``@wrapper.tool()`` decorator so the
actual ``app.py`` stays a flat list of tool declarations.

Not a leaky abstraction — ``wrapper.mcp`` is still the underlying FastMCP
instance for anything the wrapper doesn't cover.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.auth import require_scopes
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from ..common.security import require_loopback_host
from ..config import settings


class MCPServerWrapper:
    """Wraps a FastMCP instance with project-local conveniences."""

    def __init__(
        self,
        name: str = "mcpstrike",
        version: str = "3.0.0",
        session_dir: Path | None = None,
        backend_url: str | None = None,
        auth_token: str | None = None,
        auth_scopes: tuple[str, ...] | None = None,
    ) -> None:
        self.name = name
        self.version = version
        self.backend_url: str = backend_url or settings.backend_url

        self.session_dir: Path = session_dir or settings.resolve_session_dir()
        self.session_dir.mkdir(parents=True, exist_ok=True)

        token = auth_token or settings.resolve_auth_token(create=True)
        if token is None:  # defensive: create=True must always produce a token
            raise RuntimeError("Could not initialize MCP authentication token")
        scopes = auth_scopes or settings.auth_scope_list()
        verifier = StaticTokenVerifier(
            tokens={
                token: {
                    "client_id": "mcpstrike-client",
                    "scopes": list(scopes),
                }
            },
            required_scopes=["mcpstrike:read"],
        )
        self.mcp = FastMCP(name=name, version=version, auth=verifier)

        # Sync-only hooks. FastMCP doesn't currently expose a lifespan API
        # that we can cleanly plug async coroutines into, so we keep these
        # synchronous on purpose — anything async should be driven by the
        # tool implementations themselves.
        self._startup_hooks: list[Callable[[], None]] = []
        self._shutdown_hooks: list[Callable[[], None]] = []

    # ── Decorators ──────────────────────────────────────────────────────

    def tool(
        self,
        *args: Any,
        required_scopes: tuple[str, ...] = ("mcpstrike:read",),
        **kwargs: Any,
    ) -> Callable[..., Any]:
        """Register a tool with explicit scope-based authorization."""
        if "auth" in kwargs:
            raise TypeError("Use required_scopes instead of passing auth directly")
        kwargs["auth"] = require_scopes(*required_scopes)
        return self.mcp.tool(*args, **kwargs)

    def on_startup(self, fn: Callable[[], None]) -> Callable[[], None]:
        self._startup_hooks.append(fn)
        return fn

    def on_shutdown(self, fn: Callable[[], None]) -> Callable[[], None]:
        self._shutdown_hooks.append(fn)
        return fn

    # ── Session directory ───────────────────────────────────────────────

    def set_session_dir(self, new_dir: Path, create: bool = True) -> Path:
        if create:
            new_dir.mkdir(parents=True, exist_ok=True)
        if not new_dir.exists():
            raise FileNotFoundError(f"Session directory does not exist: {new_dir}")
        self.session_dir = new_dir
        return self.session_dir

    # ── Run ─────────────────────────────────────────────────────────────

    def run(
        self,
        transport: str = "http",
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        """Start the MCP server.

        For ``transport="http"``, ``host`` and ``port`` default to
        ``settings.server_host`` / ``settings.server_port``.
        """
        effective_host = host or settings.server_host
        if transport == "http":
            require_loopback_host(effective_host, "mcpstrike MCP server")
        self._print_banner(transport, host, port)

        for hook in self._startup_hooks:
            hook()

        if transport == "http":
            tls_identity = settings.resolve_mcp_tls_identity(create=True)
            if tls_identity is None:  # defensive: create=True must return a pair
                raise RuntimeError("Could not initialize the local MCP TLS identity")
            cert_path, key_path = tls_identity
            self.mcp.run(
                transport="http",
                host=effective_host,
                port=port or settings.server_port,
                uvicorn_config={
                    "ssl_certfile": str(cert_path),
                    "ssl_keyfile": str(key_path),
                },
            )
        elif transport == "stdio":
            self.mcp.run(transport="stdio")
        else:
            raise ValueError(f"Unsupported transport: {transport}")

    def _print_banner(self, transport: str, host: str | None, port: int | None) -> None:
        bar = "=" * 60
        print(bar)
        print(f"🚀 {self.name} v{self.version}")
        print(bar)
        print(f"\n📡 Backend URL:       {self.backend_url}")
        print(f"💾 Session Directory: {self.session_dir}")
        print(f"   (absolute:         {self.session_dir.absolute()})")
        print(f"   (exists:           {self.session_dir.exists()})")
        if transport == "http":
            h = host or settings.server_host
            p = port or settings.server_port
            print(f"\n🌐 Transport: https://{h}:{p}/mcp (pinned local TLS)")
        else:
            print(f"\n🌐 Transport: {transport}")
        print(f"\n{bar}\n")
