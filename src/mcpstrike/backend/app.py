"""Optional standalone backend — lightweight alternative to HexStrike.

Provides the same HTTP API that the MCP server's ``execute_command`` and
``health_check`` tools expect:

    GET  /health          -> {"status": "ok", ...}
    POST /api/command     -> run a subprocess and return stdout/stderr/exit_code

Use this when you don't have a full HexStrike server running and want to
execute security tools locally.

Usage::

    mcpstrike-backend                       # default 127.0.0.1:8890
    mcpstrike-backend --port 9999
    mcpstrike-backend --host 127.0.0.1

Requires the ``backend`` extra::

    pipx install ".[backend]"
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hmac
import json
import os
import secrets
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field, ValidationError

from ..common.security import (
    BACKEND_AUTH_WINDOW_SECONDS,
    backend_challenge_proof,
    backend_request_signature,
    decrypt_backend_message,
    encrypt_backend_message,
    is_loopback_host,
    require_loopback_host,
    validate_backend_nonce,
)
from ..config import settings

_AUTH_CHALLENGES: dict[str, tuple[int, str]] = {}
_MAX_PENDING_CHALLENGES = 1024


@dataclass(frozen=True)
class AuthenticatedBackendRequest:
    """Authenticated and decrypted request context for one backend exchange."""

    body: bytes
    client_nonce: str
    server_nonce: str
    method: str
    path: str


async def _require_signed_request(
    request: Request,
    timestamp_header: Annotated[
        str | None,
        Header(alias="X-MCPStrike-Timestamp"),
    ] = None,
    server_nonce: Annotated[str | None, Header(alias="X-MCPStrike-Nonce")] = None,
    client_nonce: Annotated[
        str | None,
        Header(alias="X-MCPStrike-Client-Nonce"),
    ] = None,
    encryption_nonce: Annotated[
        str | None,
        Header(alias="X-MCPStrike-Encryption-Nonce"),
    ] = None,
    signature: Annotated[
        str | None,
        Header(alias="X-MCPStrike-Signature"),
    ] = None,
) -> AuthenticatedBackendRequest:
    """Authenticate and decrypt one request with a fresh challenge-bound key."""
    token = settings.resolve_backend_auth_token(create=True)
    if (
        token is None
        or not timestamp_header
        or not server_nonce
        or not client_nonce
        or not encryption_nonce
        or not signature
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing backend request signature",
        )
    try:
        request_timestamp = int(timestamp_header)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid request timestamp") from exc
    now = int(time.time())
    ciphertext = await request.body()
    challenge = _AUTH_CHALLENGES.pop(server_nonce, None)
    try:
        validate_backend_nonce(client_nonce)
        validate_backend_nonce(server_nonce)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid backend nonce") from exc
    issued_at, expected_client_nonce = challenge or (None, None)
    if (
        issued_at is None
        or expected_client_nonce != client_nonce
        or abs(now - issued_at) > BACKEND_AUTH_WINDOW_SECONDS
        or abs(now - request_timestamp) > BACKEND_AUTH_WINDOW_SECONDS
    ):
        raise HTTPException(status_code=401, detail="Expired or replayed backend challenge")
    expected = backend_request_signature(
        token,
        request.method,
        request.url.path,
        ciphertext,
        request_timestamp,
        server_nonce,
        client_nonce,
    )
    supplied = signature.removeprefix("v2=")
    if not signature.startswith("v2=") or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid backend request signature")
    try:
        body = decrypt_backend_message(
            token,
            ciphertext,
            encryption_nonce,
            direction="request",
            method=request.method,
            path=request.url.path,
            timestamp=request_timestamp,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return AuthenticatedBackendRequest(
        body=body,
        client_nonce=client_nonce,
        server_nonce=server_nonce,
        method=request.method,
        path=request.url.path,
    )

app = FastAPI(
    title="mcpstrike backend",
    version="3.0.0",
    description="Optional local subprocess execution backend for mcpstrike",
)


@app.middleware("http")
async def enforce_local_client(request: Request, call_next):
    """Keep the command API local even if ASGI is launched with a remote bind."""
    client_host = request.client.host if request.client else ""
    if not is_loopback_host(client_host):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "mcpstrike backend accepts loopback clients only"},
        )
    return await call_next(request)

_START_TIME = time.monotonic()


# ── Models ─────────────────────────────────────────────────────────────────


class CommandRequest(BaseModel):
    command: str = Field(..., min_length=1, description="Command shown in reports")
    executable: str | None = Field(
        default=None,
        description="Executable passed directly to the OS (no shell)",
    )
    args: list[str] = Field(default_factory=list, description="Executable arguments")
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
    containment: str = (
        "best-effort process-group cleanup; independently daemonized processes "
        "require an external OS sandbox"
    )


# ── Health ─────────────────────────────────────────────────────────────────


@app.get("/auth/challenge")
async def issue_auth_challenge(
    client_nonce: Annotated[str, Query(min_length=32, max_length=128)],
) -> dict[str, str | int]:
    """Bind a short-lived backend proof to a caller-generated nonce."""
    token = settings.resolve_backend_auth_token(create=True)
    if token is None:
        raise HTTPException(status_code=500, detail="Backend authentication unavailable")
    try:
        validate_backend_nonce(client_nonce)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    now = int(time.time())
    cutoff = now - BACKEND_AUTH_WINDOW_SECONDS
    for old_nonce, (issued_at, _client_nonce) in list(_AUTH_CHALLENGES.items()):
        if issued_at < cutoff:
            _AUTH_CHALLENGES.pop(old_nonce, None)
    while len(_AUTH_CHALLENGES) >= _MAX_PENDING_CHALLENGES:
        _AUTH_CHALLENGES.pop(next(iter(_AUTH_CHALLENGES)))
    server_nonce = secrets.token_urlsafe(24)
    _AUTH_CHALLENGES[server_nonce] = (now, client_nonce)
    return {
        "client_nonce": client_nonce,
        "nonce": server_nonce,
        "timestamp": now,
        "proof": backend_challenge_proof(
            token,
            client_nonce,
            server_nonce,
            now,
        ),
    }


def _encrypted_json_response(
    auth: AuthenticatedBackendRequest,
    payload: BaseModel | dict[str, Any],
    *,
    status_code: int = 200,
) -> Response:
    """Encrypt and authenticate a JSON response for the verified caller."""
    token = settings.resolve_backend_auth_token(create=True)
    if token is None:
        raise HTTPException(status_code=500, detail="Backend authentication unavailable")
    serializable = payload.model_dump(mode="json") if isinstance(payload, BaseModel) else payload
    plaintext = json.dumps(
        serializable,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    response_timestamp = int(time.time())
    message_nonce, ciphertext = encrypt_backend_message(
        token,
        plaintext,
        direction="response",
        method=auth.method,
        path=auth.path,
        timestamp=response_timestamp,
        client_nonce=auth.client_nonce,
        server_nonce=auth.server_nonce,
        status_code=status_code,
    )
    return Response(
        content=ciphertext,
        status_code=status_code,
        media_type="application/octet-stream",
        headers={
            "X-MCPStrike-Response-Timestamp": str(response_timestamp),
            "X-MCPStrike-Encryption-Nonce": message_nonce,
        },
    )


@app.get("/health")
async def health_check(
    auth: Annotated[AuthenticatedBackendRequest, Depends(_require_signed_request)],
) -> Response:
    return _encrypted_json_response(auth, {
        "status": "ok",
        "service": "mcpstrike-backend",
        "version": "3.0.0",
        "uptime_seconds": round(time.monotonic() - _START_TIME, 1),
        "timestamp": datetime.now().isoformat(),
    })


# ── Command execution ─────────────────────────────────────────────────────


def _command_argv(req: CommandRequest) -> list[str]:
    if req.executable is not None:
        argv = [req.executable, *req.args]
    else:
        try:
            argv = shlex.split(req.command, posix=os.name != "nt")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid command: {exc}") from exc
    if not argv or not argv[0]:
        raise HTTPException(status_code=422, detail="Command is empty")
    if any("\x00" in part or "\n" in part or "\r" in part for part in argv):
        raise HTTPException(status_code=422, detail="Command arguments contain control characters")
    return argv


def _descendant_pids(root_pid: int) -> set[int]:
    """Snapshot descendants, including children that created a new session."""
    ps_binary = "/bin/ps" if Path("/bin/ps").exists() else "ps"
    try:
        completed = subprocess.run(
            [ps_binary, "-axo", "pid=,ppid="],
            capture_output=True,
            text=True,
            check=False,
            timeout=1,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    children: dict[int, set[int]] = {}
    for line in completed.stdout.splitlines():
        try:
            pid_text, ppid_text = line.split()
            pid, ppid = int(pid_text), int(ppid_text)
        except (TypeError, ValueError):
            continue
        children.setdefault(ppid, set()).add(pid)
    descendants: set[int] = set()
    pending = list(children.get(root_pid, set()))
    while pending:
        pid = pending.pop()
        if pid in descendants:
            continue
        descendants.add(pid)
        pending.extend(children.get(pid, set()))
    return descendants


def _tagged_pids(execution_id: str) -> set[int]:
    """Find reparented descendants that inherited this execution marker."""
    ps_binary = "/bin/ps" if Path("/bin/ps").exists() else "ps"
    try:
        completed = subprocess.run(
            [ps_binary, "eww", "-axo", "pid=,command="],
            capture_output=True,
            text=True,
            check=False,
            timeout=1,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    marker = f"MCPSTRIKE_EXECUTION_ID={execution_id}"
    tagged: set[int] = set()
    for line in completed.stdout.splitlines():
        if marker not in line:
            continue
        try:
            tagged.add(int(line.split(None, 1)[0]))
        except (IndexError, ValueError):
            continue
    return tagged


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _signal_pids(pids: set[int], sig: signal.Signals) -> None:
    for pid in sorted(pids, reverse=True):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, sig)


async def _terminate_process_tree(
    proc: asyncio.subprocess.Process,
    execution_id: str,
) -> None:
    if os.name == "posix":
        descendants = await asyncio.to_thread(_descendant_pids, proc.pid)
        descendants.update(await asyncio.to_thread(_tagged_pids, execution_id))
        descendants.discard(os.getpid())

        def group_exists() -> bool:
            try:
                os.killpg(proc.pid, 0)
                return True
            except ProcessLookupError:
                return False
            except PermissionError:
                return True

        _signal_pids(descendants, signal.SIGTERM)
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGTERM)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=0.1)
        deadline = time.monotonic() + 2.0
        while (
            group_exists() or any(_pid_exists(pid) for pid in descendants)
        ) and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        _signal_pids(descendants, signal.SIGKILL)
        if group_exists():
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=2)
        return

    if os.name == "nt":
        await asyncio.to_thread(
            subprocess.run,
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=2)
        return

    if proc.returncode is not None:
        return
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=2)
        return
    except asyncio.TimeoutError:
        proc.kill()
    except ProcessLookupError:
        return
    await proc.wait()


async def _execute_command(req: CommandRequest) -> CommandResponse:
    """Execute an argv vector directly, without a command shell."""
    start = time.monotonic()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        argv = _command_argv(req)
        process_kwargs: dict[str, Any] = {}
        if os.name == "posix":
            process_kwargs["start_new_session"] = True
        elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            process_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        execution_id = secrets.token_urlsafe(18)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={
                **os.environ,
                "MCPSTRIKE_EXECUTION_ID": execution_id,
            },
            **process_kwargs,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=req.timeout,
            )
        except asyncio.TimeoutError:
            await _terminate_process_tree(proc, execution_id)
            duration = time.monotonic() - start
            return CommandResponse(
                status="timeout",
                command=req.command,
                output=(
                    f"Command timed out after {req.timeout}s. The direct process, "
                    "its process group and observed descendants were terminated; "
                    "this timeout is not an OS sandbox for independently daemonized code."
                ),
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


@app.post("/api/command")
async def execute_command(
    auth: Annotated[AuthenticatedBackendRequest, Depends(_require_signed_request)],
) -> Response:
    """Validate an encrypted command request and return an encrypted result."""
    try:
        req = CommandRequest.model_validate_json(auth.body)
    except ValidationError as exc:
        return _encrypted_json_response(
            auth,
            {"detail": exc.errors(include_url=False)},
            status_code=422,
        )
    return _encrypted_json_response(auth, await _execute_command(req))


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
                    mcpstrike-backend (this, port 8890)
                              |
                              v
                         subprocess (nmap, nikto, ...)

Examples:
  mcpstrike-backend
  mcpstrike-backend --port 9999
  mcpstrike-backend --host 127.0.0.1 --port 8890
        """,
    )
    parser.add_argument(
        "--host", default=settings.backend_host,
        help="Bind address (loopback only; default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=settings.backend_port,
        help="Bind port (default: 8890)",
    )
    args = parser.parse_args()

    require_loopback_host(args.host, "mcpstrike backend")
    settings.resolve_backend_auth_token(create=True)

    import uvicorn

    print("=" * 60)
    print("  mcpstrike-backend v3.0.0 (standalone mode)")
    print("=" * 60)
    print(f"  Listening on  http://{args.host}:{args.port}")
    print(f"  Health:  GET  http://{args.host}:{args.port}/health")
    print(f"  Execute: POST http://{args.host}:{args.port}/api/command")
    print("  Note: hexstrike_server uses port 8888 — no conflict")
    print("=" * 60)

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
