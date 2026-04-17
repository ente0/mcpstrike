"""Optional standalone backend — lightweight alternative to HexStrike.

Provides the same HTTP API that the MCP server's ``execute_command`` and
``health_check`` tools expect:

    GET  /health          -> {"status": "ok", ...}
    POST /api/command     -> run a subprocess and return stdout/stderr/exit_code

Use this when you don't have a full HexStrike server running and want to
execute security tools locally.

Usage::

    mcpstrike-backend                       # default 0.0.0.0:8888
    mcpstrike-backend --port 9999
    mcpstrike-backend --host 127.0.0.1

Requires the ``backend`` extra::

    pipx install ".[backend]"
"""

from __future__ import annotations

import argparse
import asyncio
import os
import time
from datetime import datetime
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="mcpstrike backend",
    version="3.0.0",
    description="Optional local subprocess execution backend for mcpstrike",
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
            "mcpstrike backend — optional local subprocess execution server.\n\n"
            "Lightweight alternative to HexStrike for running security tools\n"
            "locally. Listens for command execution requests from the MCP server\n"
            "and runs them as subprocesses."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This is OPTIONAL. By default mcpstrike uses an external HexStrike server
as the backend. Use this only when you want to run tools locally without
a full HexStrike deployment.

Architecture:
  mcpstrike-client  -->  mcpstrike-server (MCP, port 8889)
                              |
                              v
                    hexstrike-server (default, port 8888)
                         — OR —
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
        "--host", default=os.getenv("MCPSTRIKE_BACKEND_HOST", "0.0.0.0"),
        help="Bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port", type=int, default=int(os.getenv("MCPSTRIKE_BACKEND_PORT", "8890")),
        help="Bind port (default: 8890)",
    )
    args = parser.parse_args()

    import uvicorn

    print("=" * 60)
    print("  mcpstrike-backend v3.0.0 (standalone mode)")
    print("=" * 60)
    print(f"  Listening on  http://{args.host}:{args.port}")
    print(f"  Health:  GET  http://{args.host}:{args.port}/health")
    print(f"  Execute: POST http://{args.host}:{args.port}/api/command")
    print(f"  Note: hexstrike_server uses port 8888 — no conflict")
    print("=" * 60)

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
