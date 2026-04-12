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

from ..config import settings


class MCPServerWrapper:
    """Wraps a FastMCP instance with project-local conveniences."""

    def __init__(
        self,
        name: str = "mcpstrike",
        version: str = "3.0.0",
        session_dir: Path | None = None,
        backend_url: str | None = None,
    ) -> None:
        self.name = name
        self.version = version
        self.backend_url: str = backend_url or settings.backend_url

        self.session_dir: Path = session_dir or settings.resolve_session_dir()
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self.mcp = FastMCP(name=name, version=version)

        # Sync-only hooks. FastMCP doesn't currently expose a lifespan API
        # that we can cleanly plug async coroutines into, so we keep these
        # synchronous on purpose — anything async should be driven by the
        # tool implementations themselves.
        self._startup_hooks: list[Callable[[], None]] = []
        self._shutdown_hooks: list[Callable[[], None]] = []

    # ── Decorators ──────────────────────────────────────────────────────

    def tool(self, *args: Any, **kwargs: Any) -> Callable[..., Any]:
        """Pass-through to ``FastMCP.tool`` (so callers never import fastmcp)."""
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
        self._print_banner(transport, host, port)

        for hook in self._startup_hooks:
            hook()

        if transport == "http":
            self.mcp.run(
                transport="http",
                host=host or settings.server_host,
                port=port or settings.server_port,
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
            print(f"\n🌐 Transport: http://{h}:{p}/mcp")
        else:
            print(f"\n🌐 Transport: {transport}")
        print(f"\n{bar}\n")
