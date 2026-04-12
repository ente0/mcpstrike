"""Ollama ↔ MCP bridge.

Handles the chat loop: send messages to Ollama, detect tool-calls, dispatch
them via :class:`MCPClientWrapper`, feed results back.

Two tool-call strategies:
    1. **Native** — Ollama 0.3+ supports a ``tools`` parameter on ``/api/chat``
       that returns structured ``tool_calls`` in the response message.
    2. **Fallback** — for older models or when native tool-calling isn't
       selected in the model, we parse JSON out of the text response
       (``{"tool": "...", "arguments": {...}}``).

The bridge tries native first; if the response has no ``tool_calls`` but the
text *looks* like a JSON tool call, the fallback parser kicks in.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings
from .wrapper import MCPClientWrapper


@dataclass
class ToolCall:
    """Normalized representation of a tool request from the model."""

    name: str
    arguments: dict[str, Any]
    source: str  # "native" | "fallback"


@dataclass
class ChatChunk:
    """One streamed delta from Ollama."""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    done: bool = False


class OllamaBridge:
    """High-level chat orchestrator."""

    def __init__(
        self,
        mcp: MCPClientWrapper,
        ollama_url: str | None = None,
        model: str | None = None,
        use_native_tools: bool = True,
        num_ctx: int = 32768,
    ) -> None:
        self.mcp = mcp
        self.ollama_url = ollama_url or settings.ollama_url
        self.model = model or settings.ollama_model
        self.use_native_tools = use_native_tools
        self.num_ctx = num_ctx

    # ── Public API ──────────────────────────────────────────────────────

    async def stream_chat(
        self,
        messages: list[dict[str, Any]],
    ) -> AsyncIterator[ChatChunk]:
        """Stream a chat completion. Yields :class:`ChatChunk` objects.

        The final chunk always has ``done=True`` and may carry aggregated
        ``tool_calls`` (either native or fallback-parsed).

        If ``use_native_tools`` is on but the current model rejects the
        ``tools`` parameter (Ollama returns HTTP 400 for unsupported models),
        we automatically retry once without it and permanently disable native
        tool-calling on this bridge instance.
        """
        try:
            async for chunk in self._stream_once(messages, with_tools=self.use_native_tools):
                yield chunk
        except httpx.HTTPStatusError as e:
            if (
                self.use_native_tools
                and e.response is not None
                and e.response.status_code == 400
            ):
                # Retry once without native tools, then fall back permanently.
                self.use_native_tools = False
                async for chunk in self._stream_once(messages, with_tools=False):
                    yield chunk
            else:
                raise

    async def _stream_once(
        self,
        messages: list[dict[str, Any]],
        with_tools: bool,
    ) -> AsyncIterator[ChatChunk]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {"num_ctx": self.num_ctx},
        }
        if with_tools and self.mcp.tools:
            payload["tools"] = self.mcp.tools_as_ollama_schema()

        accumulated = ""
        native_tool_calls: list[ToolCall] = []

        async with httpx.AsyncClient(timeout=300.0) as client:
            async with client.stream(
                "POST", f"{self.ollama_url}/api/chat", json=payload
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    msg = chunk.get("message", {}) or {}
                    content = msg.get("content", "") or ""
                    if content:
                        accumulated += content

                    # Native tool calls (Ollama 0.3+) — may appear on any chunk
                    # but Ollama typically emits them on the final one.
                    for rtc in msg.get("tool_calls") or []:
                        fn = rtc.get("function") or {}
                        name = fn.get("name")
                        raw_args = fn.get("arguments", {})
                        if isinstance(raw_args, str):
                            try:
                                raw_args = json.loads(raw_args)
                            except json.JSONDecodeError:
                                raw_args = {}
                        if isinstance(name, str) and isinstance(raw_args, dict):
                            native_tool_calls.append(
                                ToolCall(name=name, arguments=raw_args, source="native")
                            )

                    yield ChatChunk(content=content, tool_calls=[], done=False)

                    if chunk.get("done", False):
                        break

        # Final chunk: consolidate tool calls.
        final_calls = native_tool_calls
        if not final_calls:
            parsed = self._parse_fallback_tool_call(accumulated)
            if parsed is not None:
                final_calls = [parsed]

        yield ChatChunk(content="", tool_calls=final_calls, done=True)

    async def dispatch(self, tool_call: ToolCall) -> dict[str, Any] | None:
        """Execute a tool on the MCP server and return its raw result."""
        return await self.mcp.call_tool(tool_call.name, tool_call.arguments)

    # ── Fallback parsing ────────────────────────────────────────────────

    @staticmethod
    def _parse_fallback_tool_call(text: str) -> ToolCall | None:
        """Try to extract a ``{"tool": ..., "arguments": ...}`` JSON blob.

        This is the historical contract in the legacy clients. We keep it so
        mcpstrike still works with models that don't honor ``tools=[...]``.
        """
        if not text:
            return None

        text = text.strip()
        # Strip markdown fencing if present.
        if text.startswith("```"):
            text = text.strip("`").strip()
            if text.startswith("json"):
                text = text[4:].strip()

        # Whole string is JSON?
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to find the last balanced {...}.
            start = text.find("{")
            end = text.rfind("}") + 1
            if start == -1 or end <= start:
                return None
            try:
                data = json.loads(text[start:end])
            except json.JSONDecodeError:
                return None

        if not isinstance(data, dict):
            return None
        name = data.get("tool")
        arguments = data.get("arguments")
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return None
        return ToolCall(name=name, arguments=arguments, source="fallback")
