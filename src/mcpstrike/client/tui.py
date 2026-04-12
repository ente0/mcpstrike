"""mcpstrike client — interactive TUI frontend.

Built on top of :class:`MCPClientWrapper` + :class:`OllamaBridge`. All the
MCP/Ollama/parsing logic lives in those modules — this file only deals with
the terminal UI: banner, status panel, slash commands, prompt loop, auto-save
of command output, and Ctrl+C abort.

Entry point::

    mcpstrike-client --model llama3.2 --mcp-url http://localhost:8889/mcp
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.styles import Style as PTStyle
from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.theme import Theme

from ..common.filenames import FilenameAllocator
from ..common.formatters import format_command_report
from ..config import settings
from .ollama_bridge import ChatChunk, OllamaBridge, ToolCall
from .prompts.generator import PromptContext, TemplateManager, generate_prompt
from .wrapper import MCPClientWrapper, MCPProtocolError

# ════════════════════════════════════════════════════════════════════════════
# Rich theme / console
# ════════════════════════════════════════════════════════════════════════════

console = Console(
    theme=Theme(
        {
            "info": "cyan",
            "success": "green",
            "warning": "yellow",
            "error": "red bold",
            "tool": "blue",
            "dim": "dim",
            "prompt": "magenta bold",
            "section": "cyan bold",
            "header": "bold cyan",
        }
    )
)

ICONS = {
    "check": "✅",
    "cross": "❌",
    "warn": "⚠️",
    "info": "ℹ️",
    "tool": "🔧",
    "save": "💾",
    "robot": "🤖",
    "brain": "🧠",
    "loop": "🔄",
    "rocket": "🚀",
}

COMMANDS = {
    "/help": "Show this help panel",
    "/tools": "List available MCP tools",
    "/agent": "Toggle autonomous agent mode",
    "/prompt": "Generate and load a pentest prompt template",
    "/prompts": "List available prompt templates",
    "/status": "Show session status (connection, model, session info)",
    "/clear": "Clear conversation history",
    "/native": "Toggle native Ollama tool-calling (vs JSON fallback)",
    "/model": "Show or change the active Ollama model",
    "/quit": "Exit mcpstrike",
    "/exit": "Exit mcpstrike",
}

# ════════════════════════════════════════════════════════════════════════════
# Session stats
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class SessionStats:
    start_time: float = field(default_factory=time.monotonic)
    tools_called: int = 0
    commands_executed: int = 0
    files_saved: int = 0
    generations_aborted: int = 0

    @property
    def duration(self) -> float:
        return time.monotonic() - self.start_time


# ════════════════════════════════════════════════════════════════════════════
# Slash command completer
# ════════════════════════════════════════════════════════════════════════════


class SlashCompleter(Completer):
    def __init__(self, commands: dict[str, str]) -> None:
        self._commands = commands

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text.startswith("/"):
            return
        for cmd, desc in self._commands.items():
            if cmd.startswith(text):
                yield Completion(cmd, start_position=-len(text), display_meta=desc)


# ════════════════════════════════════════════════════════════════════════════
# Agent controller
# ════════════════════════════════════════════════════════════════════════════


class AbortError(Exception):
    """Raised by the signal handler to unwind the chat loop."""


@dataclass
class GenerationController:
    is_generating: bool = False
    is_cancelled: bool = False

    def start(self) -> None:
        self.is_generating = True
        self.is_cancelled = False

    def stop(self) -> None:
        self.is_generating = False

    def cancel(self) -> bool:
        if self.is_generating:
            self.is_cancelled = True
            return True
        return False


# ════════════════════════════════════════════════════════════════════════════
# TUI application
# ════════════════════════════════════════════════════════════════════════════


class TUIApp:
    def __init__(
        self,
        mcp_url: str | None = None,
        ollama_url: str | None = None,
        model: str | None = None,
        sessions_dir: str | None = None,
        use_native_tools: bool = True,
        auto_parse: bool = True,
        debug: bool = False,
    ) -> None:
        self.mcp_url = mcp_url or settings.mcp_url
        self.ollama_url = ollama_url or settings.ollama_url
        self.model = model or settings.ollama_model
        self.sessions_dir = os.path.expanduser(
            sessions_dir or str(settings.resolve_session_dir())
        )
        self.use_native_tools = use_native_tools
        self.auto_parse = auto_parse
        self.debug = debug

        self.mcp = MCPClientWrapper(mcp_url=self.mcp_url)
        self.bridge = OllamaBridge(
            mcp=self.mcp,
            ollama_url=self.ollama_url,
            model=self.model,
            use_native_tools=self.use_native_tools,
        )

        self.conversation: list[dict[str, Any]] = []
        self.agent_mode: bool = True
        self.running: bool = True
        self.current_session_id: str | None = None
        self.allocator = FilenameAllocator()
        self.stats = SessionStats()
        self.gen = GenerationController()

        self.completer = SlashCompleter(COMMANDS)
        self.history = InMemoryHistory()
        self.prompt_style = PTStyle.from_dict({"prompt": "#00ff00 bold"})
        self.template_mgr = TemplateManager()

    # ── Logging helpers ────────────────────────────────────────────────

    def ok(self, msg: str, indent: int = 0) -> None:
        console.print(f"{'  ' * indent}[success]{ICONS['check']} {msg}[/]")

    def err(self, msg: str, indent: int = 0) -> None:
        console.print(f"{'  ' * indent}[error]{ICONS['cross']} {msg}[/]")

    def warn(self, msg: str, indent: int = 0) -> None:
        console.print(f"{'  ' * indent}[warning]{ICONS['warn']} {msg}[/]")

    def info(self, msg: str, indent: int = 0) -> None:
        console.print(f"{'  ' * indent}[info]{ICONS['info']} {msg}[/]")

    # ── Banner / status ────────────────────────────────────────────────

    def banner(self) -> Panel:
        return Panel(
            "[header]mcpstrike TUI[/]\n"
            "[dim]MCP + Ollama autonomous pentest client[/]",
            box=ROUNDED,
            border_style="cyan",
            title="[bold]v3.0.0[/]",
            title_align="left",
        )

    def status_panel(self) -> Panel:
        t = Table.grid(padding=(0, 2))
        t.add_column(style="dim")
        t.add_column()
        t.add_row("MCP URL:", f"[cyan]{self.mcp_url}[/]")
        t.add_row("Ollama URL:", f"[cyan]{self.ollama_url}[/]")
        t.add_row("Model:", f"[bold]{self.model}[/]")
        t.add_row("Sessions:", f"[cyan]{self.sessions_dir}[/]")
        t.add_row("Current session:", self.current_session_id or "[dim]none[/]")
        t.add_row("Agent mode:", "[success]ON[/]" if self.agent_mode else "[dim]OFF[/]")
        t.add_row(
            "Native tools:",
            "[success]ON[/]" if self.use_native_tools else "[dim]fallback[/]",
        )
        return Panel(t, title="[bold]Status[/]", border_style="cyan", box=ROUNDED)

    def help_panel(self) -> Panel:
        t = Table.grid(padding=(0, 2))
        t.add_column(style="cyan", no_wrap=True)
        t.add_column(style="dim")
        for cmd, desc in COMMANDS.items():
            t.add_row(cmd, desc)
        t.add_row("", "")
        t.add_row("[bold]Input modes[/]", "")
        t.add_row("<<<", "Begin multi-line input (end with '>>>')")
        t.add_row("@file.txt", "Load raw text from a file as input")
        t.add_row("Ctrl+C", "Abort in-flight generation")
        t.add_row("", "")
        t.add_row("[bold]Prompt workflow[/]", "")
        t.add_row("/prompts", "Show available templates with index numbers")
        t.add_row("/prompt <n> <target>", "Generate prompt #n for <target> and load it")
        t.add_row("/prompt <n> <target> -d <domain>", "Same, with domain")
        return Panel(t, title="[bold]Commands[/]", border_style="cyan", box=ROUNDED)

    def welcome(self) -> None:
        console.print()
        console.print(self.banner())
        console.print(self.status_panel())
        console.print(self.help_panel())
        console.print()

    # ── Signal / abort ─────────────────────────────────────────────────

    def install_sigint_handler(self):
        prev = signal.getsignal(signal.SIGINT)

        def handler(signum, frame):
            if self.gen.cancel():
                console.print(f"\n[warning]{ICONS['warn']} Abort requested...[/]")
            else:
                raise KeyboardInterrupt

        signal.signal(signal.SIGINT, handler)
        return prev

    # ── MCP init ───────────────────────────────────────────────────────

    async def init_mcp(self) -> bool:
        try:
            with console.status("[cyan]Connecting to MCP server...", spinner="dots"):
                server_info = await self.mcp.initialize()
                tools = await self.mcp.list_tools()
            self.ok(
                f"Connected to [bold]{server_info.get('name', 'unknown')}"
                f"[/] v{server_info.get('version', '?')}"
            )
            self.ok(f"Discovered [bold]{len(tools)}[/] tools")
            return True
        except Exception as e:
            self.err(f"Failed to connect to {self.mcp_url}: {e}")
            return False

    # ── System prompt ──────────────────────────────────────────────────

    def build_system_prompt(self) -> str:
        tools_desc = "\n".join(
            f"- {t.name}: {t.description}" for t in self.mcp.tools
        )
        if self.agent_mode:
            return (
                "You are an AUTONOMOUS PENETRATION TESTING AGENT with full decision-making "
                "authority. Use MCP tools to run reconnaissance, enumeration, and exploitation "
                "tasks on authorized targets only. Chain vulnerabilities and adapt based on "
                "actual findings — do not invent results.\n\n"
                "MANDATORY FIRST STEPS: create_session(), then health_check(), then "
                "execute_command('nmap', ...). Afterwards adapt based on what you find.\n\n"
                "NEVER specify base_path in create_session. Use execute_command for running "
                "tools (nmap, nikto, nuclei, etc.) — do not try to call them directly.\n\n"
                f"AVAILABLE MCP TOOLS:\n{tools_desc}\n\n"
                'If your model does not support native tool calling, respond with a single '
                'JSON object: {"tool": "<name>", "arguments": {"...": "..."}}.'
            )
        return (
            "You are an assistant with access to MCP tools.\n\n"
            f"AVAILABLE TOOLS:\n{tools_desc}\n\n"
            'Use native tool calling if supported, or reply with '
            '{"tool": "...", "arguments": {...}} if not.'
        )

    # ── Main loop ──────────────────────────────────────────────────────

    async def run(self) -> None:
        prev_sigint = self.install_sigint_handler()
        try:
            if not await self.init_mcp():
                return

            self.welcome()

            session = PromptSession(
                completer=self.completer,
                history=self.history,
                style=self.prompt_style,
                complete_while_typing=True,
            )

            while self.running:
                try:
                    self.gen = GenerationController()
                    user_input = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: session.prompt(HTML("<b><ansigreen>▶ You &gt;</ansigreen></b> ")),
                    )
                    user_input = user_input.strip()
                    if not user_input:
                        continue

                    if user_input == "<<<":
                        user_input = await self._read_multiline(session)
                        if not user_input:
                            continue

                    if user_input.startswith("@"):
                        loaded = self._load_file(user_input[1:].strip())
                        if loaded is None:
                            continue
                        user_input = loaded

                    if user_input.startswith("/"):
                        await self.handle_slash(user_input)
                    else:
                        await self.process_message(user_input)

                except KeyboardInterrupt:
                    console.print(f"\n[warning]{ICONS['warn']} Use /quit to exit[/]")
                    continue
                except EOFError:
                    break

            self.goodbye()
        finally:
            signal.signal(signal.SIGINT, prev_sigint)
            await self.mcp.close()

    async def _read_multiline(self, session: PromptSession) -> str:
        console.print("[dim]Multi-line mode — end with '>>>' on its own line[/]")
        lines: list[str] = []
        while True:
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: session.prompt("")
                )
                if line.strip() == ">>>":
                    break
                lines.append(line)
            except (EOFError, KeyboardInterrupt):
                self.warn("Multi-line input interrupted")
                break
        return "\n".join(lines).strip()

    def _load_file(self, path: str) -> str | None:
        try:
            with open(os.path.expanduser(path), encoding="utf-8") as f:
                content = f.read()
            self.ok(f"Loaded {path} ({len(content)} chars)")
            return content
        except Exception as e:
            self.err(f"Cannot read {path}: {e}")
            return None

    # ── Slash commands ─────────────────────────────────────────────────

    async def handle_slash(self, cmd: str) -> None:
        parts = cmd.split()
        head = parts[0].lower()

        if head in ("/exit", "/quit"):
            self.running = False
        elif head == "/help":
            console.print(self.help_panel())
        elif head == "/status":
            console.print(self.status_panel())
        elif head == "/tools":
            self._print_tools()
        elif head == "/agent":
            self.agent_mode = not self.agent_mode
            self.ok(f"Agent mode: {'ON' if self.agent_mode else 'OFF'}")
        elif head == "/native":
            self.use_native_tools = not self.use_native_tools
            self.bridge.use_native_tools = self.use_native_tools
            self.ok(
                f"Native tool-calling: {'ON' if self.use_native_tools else 'OFF (fallback mode)'}"
            )
        elif head == "/clear":
            self.conversation.clear()
            self.ok("Conversation cleared")
        elif head == "/prompts":
            self._list_prompts()
        elif head == "/prompt":
            self._handle_prompt_command(parts[1:])
        elif head == "/model":
            if len(parts) > 1:
                self.model = parts[1]
                self.bridge.model = parts[1]
                self.ok(f"Model changed to [bold]{parts[1]}[/]")
            else:
                self.info(f"Current model: [bold]{self.model}[/]")
        else:
            self.err(f"Unknown command: {head} — type /help for available commands")

    def _print_tools(self) -> None:
        table = Table(title="MCP Tools", box=ROUNDED, border_style="cyan")
        table.add_column("Name", style="bold cyan")
        table.add_column("Description", style="dim")
        for t in self.mcp.tools:
            table.add_row(t.name, (t.description or "")[:80])
        console.print(table)

    # ── Prompt template commands ───────────────────────────────────────

    def _list_prompts(self) -> None:
        templates = self.template_mgr.list_templates()
        if not templates:
            self.err("No prompt templates found")
            return
        table = Table(
            title="Prompt Templates",
            box=ROUNDED,
            border_style="cyan",
        )
        table.add_column("#", style="bold yellow", justify="right")
        table.add_column("Name", style="bold cyan")
        table.add_column("Description", style="dim")
        table.add_column("Size", style="dim", justify="right")
        for i, t in enumerate(templates, 1):
            table.add_row(str(i), t.name, t.description[:60], f"{t.size:,}B")
        console.print(table)
        console.print(
            "\n[dim]Usage: /prompt <#> <target> [-d domain] [-tt test_type][/]\n"
            "[dim]Example: /prompt 1 192.168.1.100 -d example.com[/]"
        )

    def _handle_prompt_command(self, args: list[str]) -> None:
        """Parse ``/prompt <index> <target> [options]`` and load into conversation."""
        if len(args) < 2:
            self.err("Usage: /prompt <#> <target> [-d domain] [-tt test_type]")
            self._list_prompts()
            return

        # Parse index
        try:
            idx = int(args[0])
        except ValueError:
            self.err(f"Invalid template number: {args[0]}")
            return

        tpl = self.template_mgr.get_by_index(idx)
        if tpl is None:
            self.err(f"Template #{idx} not found — use /prompts to see available")
            return

        target = args[1]
        domain = "N/A"
        test_type = "full"

        # Simple flag parsing
        i = 2
        while i < len(args):
            if args[i] == "-d" and i + 1 < len(args):
                domain = args[i + 1]
                i += 2
            elif args[i] == "-tt" and i + 1 < len(args):
                test_type = args[i + 1]
                i += 2
            else:
                i += 1

        ctx = PromptContext(target=target, domain=domain, test_type=test_type)
        text, _ = generate_prompt(tpl, ctx)

        # Set session id from context
        self.current_session_id = ctx.session_id()
        self.allocator.reset()

        # Inject into conversation as user message
        self.conversation.clear()
        self.conversation.append({"role": "user", "content": text})

        self.ok(
            f"Loaded template [bold]{tpl.name}[/] for target [bold]{target}[/] "
            f"(session: {ctx.session_id()})"
        )
        self.info(f"Prompt injected ({len(text)} chars). The model will respond on next turn.")
        self.info("Send any message (e.g. 'go') to start, or /clear to reset.")

    # ── Chat loop ──────────────────────────────────────────────────────

    # Maximum agent loop iterations before forcing a pause
    MAX_AGENT_ITERATIONS = 20
    # Keep the system message + the last N conversation entries to prevent
    # Ollama context overflow. Each tool call + result pair counts as ~2 entries.
    CONTEXT_WINDOW = 40

    async def process_message(self, user_input: str) -> None:
        self.conversation.append({"role": "user", "content": user_input})
        await self._chat_loop()

    async def _chat_loop(self) -> None:
        """Iterative agent loop — replaces the old recursive _chat_turn."""
        iteration = 0

        while True:
            iteration += 1

            # Context pruning: keep system prompt lean by only sending the
            # last CONTEXT_WINDOW messages. The system message is always
            # prepended fresh so it never gets pruned.
            self._prune_context()

            system = {"role": "system", "content": self.build_system_prompt()}
            messages = [system] + self.conversation

            self.gen.start()
            assistant_buf = ""
            pending_tool_calls: list[ToolCall] = []

            try:
                spinner = Spinner("dots", text="[dim]Thinking... (Ctrl+C to abort)[/]", style="cyan")
                first_content = True

                from rich.live import Live
                with Live(spinner, console=console, refresh_per_second=10, transient=True) as live:
                    async for chunk in self.bridge.stream_chat(messages):
                        if self.gen.is_cancelled:
                            raise AbortError()

                        if chunk.done:
                            pending_tool_calls = chunk.tool_calls
                            break

                        if chunk.content:
                            if first_content:
                                live.stop()
                                console.print(f"[header]{ICONS['robot']} Assistant:[/] ", end="")
                                first_content = False
                            assistant_buf += chunk.content
                            print(chunk.content, end="", flush=True)

                if not first_content:
                    print()
            except AbortError:
                self.stats.generations_aborted += 1
                self.warn("Generation aborted")
                if assistant_buf:
                    self.conversation.append(
                        {"role": "assistant", "content": assistant_buf + " [ABORTED]"}
                    )
                return
            except httpx.HTTPError as e:
                self.err(f"Ollama HTTP error: {e}")
                return
            except Exception as e:
                self.err(f"Chat error: {e}")
                if self.debug:
                    import traceback as _tb
                    console.print(f"[dim]{_tb.format_exc()}[/]")
                return
            finally:
                self.gen.stop()

            # Record assistant turn.
            if assistant_buf:
                self.conversation.append({"role": "assistant", "content": assistant_buf})

            # No tool calls → conversation turn complete, return to prompt.
            if not pending_tool_calls:
                return

            # Dispatch tool calls.
            for tc in pending_tool_calls:
                await self._execute_tool_call(tc)

            # In non-agent mode, return to prompt after tool execution.
            if not self.agent_mode or not self.running or self.gen.is_cancelled:
                return

            # Safety: stop after MAX_AGENT_ITERATIONS to prevent runaway loops.
            if iteration >= self.MAX_AGENT_ITERATIONS:
                self.warn(
                    f"Agent reached {self.MAX_AGENT_ITERATIONS} iterations — "
                    "pausing. Send a message to continue."
                )
                return

            # Continue autonomously.
            console.print(
                f"\n[dim]{ICONS['loop']} Continuing autonomously "
                f"(iteration {iteration}/{self.MAX_AGENT_ITERATIONS})...[/]\n"
            )
            self.conversation.append(
                {
                    "role": "user",
                    "content": "Tool executed. Proceed with the next step.",
                }
            )

    def _prune_context(self) -> None:
        """Sliding window: drop old messages beyond CONTEXT_WINDOW."""
        if len(self.conversation) <= self.CONTEXT_WINDOW:
            return
        excess = len(self.conversation) - self.CONTEXT_WINDOW
        self.conversation = self.conversation[excess:]
        if self.debug:
            self.info(f"Context pruned: dropped {excess} oldest messages", indent=1)

    async def _execute_tool_call(self, tc: ToolCall) -> None:
        console.print(
            f"\n[tool]{ICONS['tool']} Calling [bold]{tc.name}[/] "
            f"[dim]({tc.source})[/]"
        )
        if self.debug or tc.name != "write_session_file":
            args_json = json.dumps(tc.arguments, indent=2)
            console.print(f"[dim]{args_json}[/]")

        # Track session id.
        if tc.name == "create_session":
            sid = tc.arguments.get("session_id")
            if isinstance(sid, str):
                self.current_session_id = sid
                self.allocator.reset()
                self.ok(f"Tracking session: [bold]{sid}[/]", indent=1)

        try:
            with console.status(f"[cyan]Executing {tc.name}...", spinner="dots"):
                result = await self.bridge.dispatch(tc)
            self.stats.tools_called += 1
        except MCPProtocolError as e:
            self.err(f"MCP error: {e}", indent=1)
            self.conversation.append(
                {
                    "role": "user",
                    "content": f"[TOOL ERROR for {tc.name}]: {e}",
                }
            )
            return
        except Exception as e:
            self.err(f"Dispatch failed: {e}", indent=1)
            return

        if result is None:
            self.err("Tool returned no result", indent=1)
            return

        self.ok("Tool executed", indent=1)

        # Auto-save for execute_command.
        if tc.name == "execute_command" and self.agent_mode and self.current_session_id:
            self.stats.commands_executed += 1
            await self._auto_save(tc.arguments, result)

        # Feed the result back into the conversation so the LLM sees it.
        result_json = json.dumps(result, indent=2)
        if len(result_json) > 2000:
            result_json = result_json[:2000] + "\n... (truncated)"
        self.conversation.append(
            {
                "role": "assistant",
                "content": f'{{"tool": "{tc.name}", "arguments": {json.dumps(tc.arguments)}}}',
            }
        )
        self.conversation.append(
            {
                "role": "user",
                "content": f"[TOOL RESULT for {tc.name}]:\n{result_json}\n[END]",
            }
        )

    async def _auto_save(self, arguments: dict[str, Any], result: dict[str, Any]) -> None:
        cmd = arguments.get("command", "unknown")
        args = arguments.get("args", []) or []
        filename = self.allocator.next(cmd, args)
        content = format_command_report(cmd, args, result)

        console.print(f"\n  [bold]{ICONS['save']} Auto-saving[/] [cyan]{filename}[/]")
        try:
            save_result = await self.mcp.call_tool(
                "write_session_file",
                {
                    "filename": filename,
                    "content": content,
                    "session_id": self.current_session_id,
                },
            )
        except MCPProtocolError as e:
            self.err(f"Save failed: {e}", indent=1)
            return

        if save_result:
            self.stats.files_saved += 1
            self.ok(f"Saved to {self.sessions_dir}/{self.current_session_id}/{filename}", indent=1)

        # Auto-parse on success — fire-and-forget.
        if self.auto_parse:
            await self._auto_parse(cmd, result)

    async def _auto_parse(self, command: str, result: dict[str, Any]) -> None:
        """Send raw output to the server's parser tool and log a summary."""
        if not self.current_session_id:
            return
        if not self.mcp.has_tool("auto_parse_output"):
            return

        from ..common.formatters import extract_output_and_error
        output_text, _ = extract_output_and_error(result)
        if not output_text.strip():
            return

        try:
            parsed = await self.mcp.call_tool(
                "auto_parse_output",
                {"command": command, "content": output_text},
            )
        except MCPProtocolError:
            return

        payload = self._extract_mcp_payload(parsed)
        if not payload or payload.get("status") != "success":
            return

        parser_name = payload.get("parser") or "?"
        findings = payload.get("findings")
        count = self._count_findings(findings)
        if count > 0:
            self.info(f"Parsed with '{parser_name}': {count} findings", indent=1)
            # Persist findings into session_metadata.json
            if self.mcp.has_tool("update_session_findings") and findings:
                try:
                    await self.mcp.call_tool(
                        "update_session_findings",
                        {
                            "session_id": self.current_session_id,
                            "parser": parser_name,
                            "findings": findings,
                            "command": command,
                        },
                    )
                except MCPProtocolError:
                    pass  # non-critical, don't break the flow

    @staticmethod
    def _extract_mcp_payload(raw: dict[str, Any] | None) -> dict[str, Any] | None:
        """Pull the first JSON text block out of an MCP ``result`` envelope."""
        if not isinstance(raw, dict):
            return None
        for block in raw.get("content") or []:
            if not (isinstance(block, dict) and block.get("type") == "text"):
                continue
            try:
                data = json.loads(block["text"])
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(data, dict):
                return data
        return None

    @staticmethod
    def _count_findings(findings: Any) -> int:
        if isinstance(findings, list):
            return len(findings)
        if isinstance(findings, dict):
            ports = findings.get("ports") or []
            vulns = findings.get("vulnerabilities") or []
            return len(ports) + len(vulns)
        return 0

    # ── Goodbye ────────────────────────────────────────────────────────

    def goodbye(self) -> None:
        console.print()
        console.print(
            Panel(
                f"[header]{ICONS['check']} Session ended[/]\n\n"
                f"[dim]Duration:[/] {self.stats.duration:.1f}s\n"
                f"[dim]Tools called:[/] {self.stats.tools_called}\n"
                f"[dim]Commands executed:[/] {self.stats.commands_executed}\n"
                f"[dim]Files saved:[/] {self.stats.files_saved}\n"
                f"[dim]Aborted:[/] {self.stats.generations_aborted}",
                title="[bold cyan]Goodbye[/]",
                border_style="cyan",
                box=ROUNDED,
            )
        )


# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcpstrike-client",
        description=(
            "mcpstrike client — interactive MCP + Ollama autonomous pentest TUI.\n\n"
            "Connects to an mcpstrike MCP server and uses an Ollama LLM to drive\n"
            "penetration testing tools autonomously. Supports both native Ollama\n"
            "tool-calling and JSON fallback for older models."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Interactive commands (inside the TUI):
  /help                 Show all available commands
  /tools                List MCP tools discovered on the server
  /agent                Toggle autonomous agent mode (ON by default)
  /prompt <n> <target>  Generate and load a pentest prompt template
  /prompts              List available prompt templates
  /status               Show connection, model, and session info
  /model <name>         Switch Ollama model at runtime
  /native               Toggle native tool-calling vs JSON fallback
  /clear                Clear conversation history
  /quit, /exit          Exit the client

Examples:
  mcpstrike-client
  mcpstrike-client --model qwen2.5:7b
  mcpstrike-client --no-native-tools
  mcpstrike-client --mcp-url http://remote:8889/mcp
  mcpstrike-client --ollama-url http://gpu-box:11434
        """,
    )
    parser.add_argument(
        "--mcp-url", default=None, metavar="URL",
        help="MCP server URL (default: http://localhost:8889/mcp)",
    )
    parser.add_argument(
        "--ollama-url", default=None, metavar="URL",
        help="Ollama API URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--model", "-m", default=None, metavar="NAME",
        help="Ollama model to use (default: llama3.2)",
    )
    parser.add_argument(
        "--sessions-dir", default=None, metavar="PATH",
        help="Directory for session files (default: ~/hexstrike_sessions)",
    )
    parser.add_argument(
        "--no-native-tools",
        action="store_true",
        help="Disable Ollama native tools=[...] param, use JSON fallback only",
    )
    parser.add_argument(
        "--no-auto-parse",
        action="store_true",
        help="Disable automatic parser dispatch after execute_command",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug tracebacks on errors",
    )
    args = parser.parse_args()

    app = TUIApp(
        mcp_url=args.mcp_url,
        ollama_url=args.ollama_url,
        model=args.model,
        sessions_dir=args.sessions_dir,
        use_native_tools=not args.no_native_tools,
        auto_parse=not args.no_auto_parse,
        debug=args.debug,
    )

    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
