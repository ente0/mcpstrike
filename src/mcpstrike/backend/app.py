"""HexStrike-compatible FastAPI backend.

Provides the HTTP endpoints that :func:`mcpstrike.server.app.execute_command`
and :func:`mcpstrike.server.app.health_check` call:

    GET  /health          → {"status": "ok", ...}
    POST /api/command     → run a subprocess and return stdout/stderr/exit_code

This is the missing piece that closes the end-to-end loop:

    mcpstrike-client  →  mcpstrike-server (MCP)  →  mcpstrike-backend (subprocess)

Usage::

    mcpstrike-backend                       # default 0.0.0.0:8888
    mcpstrike-backend --port 9999
    mcpstrike-backend --host 127.0.0.1

Environment::

    HEXSTRIKE_BACKEND_HOST  (default 0.0.0.0)
    HEXSTRIKE_BACKEND_PORT  (default 8888)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import time
from datetime import datetime
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="mcpstrike backend",
    version="3.0.0",
    description="Local subprocess execution backend for mcpstrike",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_START_TIME = time.monotonic()


# ── Models ─────────────────────────────────────────────────────────────────


class CommandRequest(BaseModel):
    command: str = Field(..., description="Full command string to execute")
    timeout: int = Field(default=300, ge=1, le=3600, description="Timeout in seconds")


class CommandResponse(BaseModel):
    status: str
    command: str
    output: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int | str = "unknown"
    duration: float = 0.0
    timestamp: str = ""


# ── Health ─────────────────────────────────────────────────────────────────


@app.get("/health")
async def health_check() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "mcpstrike-backend",
        "version": "3.0.0",
        "uptime_seconds": round(time.monotonic() - _START_TIME, 1),
        "timestamp": datetime.now().isoformat(),
    }


# ── Command execution ─────────────────────────────────────────────────────


def _resolve_binary(cmd_parts: list[str]) -> list[str]:
    """Resolve the binary to its full path if possible."""
    if not cmd_parts:
        return cmd_parts
    binary = shutil.which(cmd_parts[0])
    if binary:
        cmd_parts[0] = binary
    return cmd_parts


@app.post("/api/command")
async def execute_command(req: CommandRequest) -> CommandResponse:
    """Execute a shell command as a subprocess and return its output."""
    start = time.monotonic()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        proc = await asyncio.create_subprocess_shell(
            req.command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=req.timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            duration = time.monotonic() - start
            return CommandResponse(
                status="timeout",
                command=req.command,
                output=f"Command timed out after {req.timeout}s",
                stdout="",
                stderr="",
                exit_code=-1,
                duration=round(duration, 2),
                timestamp=timestamp,
            )

        stdout_str = stdout_bytes.decode("utf-8", errors="replace")
        stderr_str = stderr_bytes.decode("utf-8", errors="replace")
        exit_code = proc.returncode or 0
        duration = time.monotonic() - start

        return CommandResponse(
            status="success" if exit_code == 0 else "error",
            command=req.command,
            output=stdout_str,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=exit_code,
            duration=round(duration, 2),
            timestamp=timestamp,
        )

    except Exception as e:
        duration = time.monotonic() - start
        return CommandResponse(
            status="failed",
            command=req.command,
            output=f"Error: {e}",
            stderr=str(e),
            exit_code=-1,
            duration=round(duration, 2),
            timestamp=timestamp,
        )


# ── Entry point ────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcpstrike-backend",
        description=(
            "mcpstrike backend — local subprocess execution server.\n\n"
            "Listens for command execution requests from the mcpstrike MCP server\n"
            "and runs them as subprocesses, returning stdout/stderr/exit_code.\n"
            "This is the component that actually runs nmap, nikto, sqlmap, etc."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Architecture:
  mcpstrike-client  -->  mcpstrike-server (MCP, port 8889)
                              |
                              v
                         mcpstrike-backend (this, port 8888)
                              |
                              v
                         subprocess (nmap, nikto, ...)

Examples:
  mcpstrike-backend
  mcpstrike-backend --port 9999
  mcpstrike-backend --host 127.0.0.1 --port 8888
        """,
    )
    parser.add_argument(
        "--host", default=os.getenv("HEXSTRIKE_BACKEND_HOST", "0.0.0.0"),
        help="Bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port", type=int, default=int(os.getenv("HEXSTRIKE_BACKEND_PORT", "8888")),
        help="Bind port (default: 8888)",
    )
    args = parser.parse_args()

    import uvicorn

    print("=" * 60)
    print("  mcpstrike-backend v3.0.0")
    print("=" * 60)
    print(f"  Listening on http://{args.host}:{args.port}")
    print(f"  Health:  GET  http://{args.host}:{args.port}/health")
    print(f"  Execute: POST http://{args.host}:{args.port}/api/command")
    print("=" * 60)

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
