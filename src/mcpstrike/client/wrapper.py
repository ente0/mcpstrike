"""Async MCP client wrapper.

Responsibilities:
    • JSON-RPC request/response over HTTP with SSE parsing
    • ``mcp-session-id`` header management
    • ``initialize`` handshake and tool discovery cache
    • ``tools/call`` with typed results

This is the single MCP client used by the mcpstrike TUI and any future
frontends. All JSON-RPC and session management logic lives here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings


class MCPProtocolError(RuntimeError):
    """Raised when the MCP server returns an error or a malformed response."""


@dataclass
class MCPTool:
    """A lightweight view over the MCP tool descriptor."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "MCPTool":
        return cls(
            name=raw.get("name", "unknown"),
            description=raw.get("description", ""),
            input_schema=raw.get("inputSchema", {}),
        )

    def parameter_names(self) -> list[str]:
        return list(self.input_schema.get("properties", {}).keys())


class MCPClientWrapper:
    """Single async MCP client used by every frontend in this project.

    Typical lifecycle::

        async with MCPClientWrapper() as client:
            await client.initialize()
            tools = await client.list_tools()
            result = await client.call_tool("health_check", {})
    """

    def __init__(
        self,
        mcp_url: str | None = None,
        client_name: str = "mcpstrike-client",
        client_version: str = "3.0.0",
        timeout: float = 60.0,
    ) -> None:
        self.mcp_url = mcp_url or settings.mcp_url
        self.client_name = client_name
        self.client_version = client_version
        self.timeout = timeout

        self._session_id: str | None = None
        self._request_id = 1
        self._tools: list[MCPTool] = []
        self._http: httpx.AsyncClient | None = None
        self._initialized = False

    # ── Context manager ────────────────────────────────────────────────

    async def __aenter__(self) -> "MCPClientWrapper":
        self._http = httpx.AsyncClient(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ── Properties ─────────────────────────────────────────────────────

    @property
    def session_id(self) -> str | None:
        return self._session_id

    @property
    def tools(self) -> list[MCPTool]:
        """Cached tool descriptors (empty until ``list_tools`` is called)."""
        return self._tools

    def tool_names(self) -> list[str]:
        return [t.name for t in self._tools]

    def has_tool(self, name: str) -> bool:
        return any(t.name == name for t in self._tools)

    # ── Low-level JSON-RPC ─────────────────────────────────────────────

    async def _send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._http is None:
            # Lazy-open outside of `async with` for convenience.
            self._http = httpx.AsyncClient(timeout=self.timeout)

        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params or {},
        }
        self._request_id += 1

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id and method != "initialize":
            headers["mcp-session-id"] = self._session_id

        response = await self._http.post(self.mcp_url, json=payload, headers=headers)

        # FastMCP returns the session id on the response of `initialize`.
        if "mcp-session-id" in response.headers:
            self._session_id = response.headers["mcp-session-id"]

        if response.status_code != 200:
            raise MCPProtocolError(
                f"MCP server returned HTTP {response.status_code}: {response.text[:200]}"
            )

        # SSE: look for `data: <json>` lines.
        for line in response.text.splitlines():
            if line.startswith("data: "):
                try:
                    return json.loads(line[6:])
                except json.JSONDecodeError:
                    continue

        # Plain JSON fallback.
        try:
            return response.json()
        except json.JSONDecodeError as e:
            raise MCPProtocolError(f"Malformed MCP response: {e}") from e

    # ── High-level operations ──────────────────────────────────────────

    async def initialize(self) -> dict[str, Any]:
        """Perform the MCP handshake; returns the server's ``serverInfo``."""
        raw = await self._send(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "roots": {"listChanged": True},
                    "sampling": {},
                },
                "clientInfo": {"name": self.client_name, "version": self.client_version},
            },
        )
        self._initialized = True
        return raw.get("result", {}).get("serverInfo", {})

    async def list_tools(self, force_refresh: bool = False) -> list[MCPTool]:
        """Fetch and cache the server's tool list."""
        if self._tools and not force_refresh:
            return self._tools
        raw = await self._send("tools/list")
        tools_raw = raw.get("result", {}).get("tools", [])
        self._tools = [MCPTool.from_raw(t) for t in tools_raw]
        return self._tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
        """Invoke a tool by name. Returns the ``result`` object, or None on error."""
        if not self._initialized:
            await self.initialize()

        if self._tools and not self.has_tool(name):
            raise MCPProtocolError(
                f"Unknown tool '{name}' — available: {', '.join(self.tool_names()[:10])}"
            )

        raw = await self._send("tools/call", {"name": name, "arguments": arguments})
        if "error" in raw:
            raise MCPProtocolError(str(raw["error"]))
        return raw.get("result")

    # ── Tool schema export (for Ollama native tool-calling) ────────────

    def tools_as_ollama_schema(self) -> list[dict[str, Any]]:
        """Return tool descriptors shaped for Ollama's native ``tools=[...]`` param.

        Ollama 0.3+ accepts OpenAI-style function definitions::

            {"type": "function",
             "function": {"name": "...", "description": "...", "parameters": {...}}}
        """
        out: list[dict[str, Any]] = []
        for t in self._tools:
            out.append(
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description or f"MCP tool {t.name}",
                        "parameters": t.input_schema
                        or {"type": "object", "properties": {}, "required": []},
                    },
                }
            )
        return out
