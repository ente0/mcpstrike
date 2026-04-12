"""FastMCP server for mcpstrike.

All tool definitions live here. Session/backend state is held by the
:class:`MCPServerWrapper` (see ``wrapper.py``) so this file stays flat.

Tool groups:
    • Configuration:     get_config, set_session_directory
    • Discovery:         discover_sessions, import_external_session
    • Health / exec:     health_check, execute_command
    • Session files:     create_session, list_sessions, write_session_file,
                         read_session_file, list_session_files
    • Parsers:           parse_output, auto_parse_output
    • Findings:          update_session_findings
"""

from __future__ import annotations

import json
import shutil
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

import aiofiles
import httpx

from ..common import parsers
from ..config import settings
from .wrapper import MCPServerWrapper

wrapper = MCPServerWrapper(name="HexStrike Security Tools", version="3.0.0")


# ════════════════════════════════════════════════════════════════════════════
# Configuration tools
# ════════════════════════════════════════════════════════════════════════════


@wrapper.tool()
async def get_config() -> dict[str, Any]:
    """Return current server configuration (backend URL, session dir, env vars)."""
    sd = wrapper.session_dir
    return {
        "status": "success",
        "config": {
            "backend_url": wrapper.backend_url,
            "session_directory": str(sd),
            "session_directory_absolute": str(sd.absolute()),
            "session_directory_exists": sd.exists(),
            "environment_variables": {
                "HEXSTRIKE_BACKEND_URL": settings.backend_url,
                "HEXSTRIKE_SESSION_PATH": settings.session_path or "not set",
                "HEXSTRIKE_SESSION_DIR": settings.session_dir_name or "not set",
            },
        },
    }


@wrapper.tool()
async def set_session_directory(
    path: str | None = None,
    directory_name: str | None = None,
    create_if_missing: bool = True,
) -> dict[str, Any]:
    """Change the session directory for this server process only."""
    try:
        if path:
            new_dir = Path(path).expanduser()
        elif directory_name:
            new_dir = Path.home() / directory_name
        else:
            return {
                "status": "error",
                "error": "Provide 'path' or 'directory_name'",
                "current_directory": str(wrapper.session_dir),
            }

        old = wrapper.session_dir
        new = wrapper.set_session_dir(new_dir, create=create_if_missing)
        return {
            "status": "success",
            "previous_directory": str(old),
            "new_directory": str(new),
            "absolute_path": str(new.absolute()),
            "note": "Temporary — export HEXSTRIKE_SESSION_PATH to persist.",
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ════════════════════════════════════════════════════════════════════════════
# Session discovery / import
# ════════════════════════════════════════════════════════════════════════════


@wrapper.tool()
async def discover_sessions(
    search_paths: list[str] | None = None,
    pattern: str = "*",
) -> dict[str, Any]:
    """Find pentest sessions across one or more directories."""
    try:
        paths = search_paths or [
            str(wrapper.session_dir),
            str(Path.home() / "hexstrike_sessions"),
            str(Path.home() / "pentest_sessions"),
        ]

        found: list[dict[str, Any]] = []
        searched: list[str] = []
        for p in paths:
            root = Path(p).expanduser()
            searched.append(str(root))
            if not root.exists():
                continue
            for session_dir in root.glob(pattern):
                if not session_dir.is_dir():
                    continue
                files = [f for f in session_dir.iterdir() if f.is_file()]
                metadata: dict[str, Any] | None = None
                meta_path = session_dir / "session_metadata.json"
                if meta_path.exists():
                    try:
                        async with aiofiles.open(meta_path) as f:
                            metadata = json.loads(await f.read())
                    except Exception:
                        metadata = None
                found.append(
                    {
                        "session_id": session_dir.name,
                        "full_path": str(session_dir),
                        "parent_directory": str(session_dir.parent),
                        "file_count": len(files),
                        "metadata": metadata,
                    }
                )

        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for s in found:
            if s["full_path"] not in seen:
                seen.add(s["full_path"])
                unique.append(s)

        return {
            "status": "success",
            "sessions_found": len(unique),
            "searched_directories": searched,
            "current_session_dir": str(wrapper.session_dir),
            "sessions": sorted(unique, key=lambda x: x["session_id"]),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@wrapper.tool()
async def import_external_session(
    source_path: str,
    session_id: str | None = None,
    copy_files: bool = True,
) -> dict[str, Any]:
    """Import a session folder from an external path into the current SESSION_DIR."""
    try:
        source = Path(source_path).expanduser()
        if not source.exists():
            return {"status": "error", "error": f"Source path does not exist: {source}"}
        if not source.is_dir():
            return {"status": "error", "error": f"Source path is not a directory: {source}"}

        session_id = session_id or source.name
        target = wrapper.session_dir / session_id
        if target.exists():
            return {
                "status": "error",
                "error": f"Session {session_id} already exists",
                "suggestion": "Choose a different session_id",
            }

        if copy_files:
            shutil.copytree(source, target)
            method = "copied"
        else:
            target.symlink_to(source)
            method = "symlinked"

        file_count = len([f for f in target.iterdir() if f.is_file()])
        return {
            "status": "success",
            "session_id": session_id,
            "source_path": str(source),
            "target_path": str(target),
            "method": method,
            "files_imported": file_count,
            "imported_at": datetime.now().isoformat(),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ════════════════════════════════════════════════════════════════════════════
# Backend health + command execution
# ════════════════════════════════════════════════════════════════════════════


@wrapper.tool()
async def health_check() -> dict[str, Any]:
    """Ping the HexStrike backend."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(f"{wrapper.backend_url}/health")
            return response.json()
        except Exception as e:
            return {"status": "failed", "error": str(e)}


@wrapper.tool()
async def list_models(ollama_url: str | None = None) -> dict[str, Any]:
    """List available Ollama models.

    Queries the Ollama API and returns the installed models with their
    sizes and modification dates. Useful to check which models are
    available before switching with ``/model``.
    """
    url = ollama_url or settings.ollama_url
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(f"{url}/api/tags")
            response.raise_for_status()
            data = response.json()
            models = [
                {
                    "name": m.get("name"),
                    "size_gb": round(m.get("size", 0) / 1e9, 1),
                    "modified": m.get("modified_at", "")[:10],
                }
                for m in data.get("models", [])
            ]
            return {
                "status": "ok",
                "ollama_url": url,
                "model_count": len(models),
                "models": models,
            }
        except Exception as e:
            return {"status": "failed", "ollama_url": url, "error": str(e)}


@wrapper.tool()
async def execute_command(
    command: str,
    args: list[str] | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """Run a security command on the HexStrike backend."""
    start = datetime.now()
    full_command = f"{command} {' '.join(args)}" if args else command
    payload = {"command": full_command, "timeout": timeout}
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.post(f"{wrapper.backend_url}/api/command", json=payload)
            result = response.json()
            end = datetime.now()
            return {
                "output": result.get("output", result.get("stdout", "")),
                "status": result.get("status", "unknown"),
                "command": full_command,
                "timestamp": start.strftime("%Y-%m-%d %H:%M:%S"),
                "duration": (end - start).total_seconds(),
                "exit_code": result.get("exit_code", "unknown"),
            }
        except Exception as e:
            return {
                "status": "failed",
                "command": full_command,
                "output": f"Error: {e}",
                "error": str(e),
            }


# ════════════════════════════════════════════════════════════════════════════
# Session file I/O
# ════════════════════════════════════════════════════════════════════════════


def _resolve_target_dir(
    session_id: str | None,
    session_path: str | None,
    mkdir: bool = False,
) -> Path:
    if session_path:
        target = Path(session_path).expanduser()
    elif session_id:
        target = wrapper.session_dir / session_id
    else:
        target = wrapper.session_dir
    if mkdir:
        target.mkdir(parents=True, exist_ok=True)
    return target


@wrapper.tool()
async def create_session(
    session_id: str,
    metadata: dict[str, Any] | str | None = None,
) -> dict[str, Any]:
    """Create a new pentest session in the configured SESSION_DIR."""
    try:
        session_dir = wrapper.session_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        if metadata:
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except json.JSONDecodeError:
                    metadata = {"raw": metadata}
            if isinstance(metadata, dict):
                metadata["created_at"] = datetime.now().isoformat()
                metadata["session_directory"] = str(session_dir)
                async with aiofiles.open(session_dir / "session_metadata.json", "w") as f:
                    await f.write(json.dumps(metadata, indent=2))

        return {
            "status": "success",
            "session_id": session_id,
            "session_path": str(session_dir),
            "session_directory": str(wrapper.session_dir),
            "absolute_path": str(session_dir.absolute()),
            "metadata": metadata,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc(),
        }


@wrapper.tool()
async def list_sessions() -> dict[str, Any]:
    """List all sessions in the current SESSION_DIR."""
    try:
        sessions: list[dict[str, Any]] = []
        for session_dir in wrapper.session_dir.iterdir():
            if not session_dir.is_dir():
                continue
            metadata: dict[str, Any] | None = None
            meta_path = session_dir / "session_metadata.json"
            if meta_path.exists():
                async with aiofiles.open(meta_path) as f:
                    metadata = json.loads(await f.read())
            files = [f for f in session_dir.iterdir() if f.is_file()]
            sessions.append(
                {
                    "session_id": session_dir.name,
                    "file_count": len(files),
                    "metadata": metadata,
                }
            )
        return {
            "status": "success",
            "session_count": len(sessions),
            "sessions": sorted(sessions, key=lambda x: x["session_id"]),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@wrapper.tool()
async def write_session_file(
    filename: str,
    content: str,
    session_id: str | None = None,
    append: bool = False,
    session_path: str | None = None,
) -> dict[str, Any]:
    """Write content to a session file."""
    try:
        target_dir = _resolve_target_dir(session_id, session_path, mkdir=True)
        file_path = target_dir / filename
        mode = "a" if append else "w"
        async with aiofiles.open(file_path, mode=mode, encoding="utf-8") as f:
            await f.write(content)
        stat = file_path.stat()
        return {
            "status": "success",
            "file_path": str(file_path),
            "filename": filename,
            "session_id": session_id,
            "size_bytes": stat.st_size,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@wrapper.tool()
async def read_session_file(
    filename: str,
    session_id: str | None = None,
    session_path: str | None = None,
) -> dict[str, Any]:
    """Read content from a session file."""
    try:
        target_dir = _resolve_target_dir(session_id, session_path)
        file_path = target_dir / filename
        if not file_path.exists():
            return {"status": "error", "error": "File not found"}
        async with aiofiles.open(file_path, encoding="utf-8") as f:
            content = await f.read()
        return {
            "status": "success",
            "content": content,
            "filename": filename,
            "session_id": session_id,
            "size_bytes": len(content),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@wrapper.tool()
async def list_session_files(
    session_id: str | None = None,
    pattern: str | None = None,
    session_path: str | None = None,
) -> dict[str, Any]:
    """List all files in a session."""
    try:
        target_dir = _resolve_target_dir(session_id, session_path)
        if not target_dir.exists():
            return {"status": "error", "error": "Directory not found"}
        files = (
            list(target_dir.glob(pattern))
            if pattern
            else [f for f in target_dir.iterdir() if f.is_file()]
        )
        file_list = []
        for fp in sorted(files):
            stat = fp.stat()
            file_list.append(
                {"filename": fp.name, "size_bytes": stat.st_size, "modified": stat.st_mtime}
            )
        return {
            "status": "success",
            "session_id": session_id,
            "file_count": len(file_list),
            "files": file_list,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ════════════════════════════════════════════════════════════════════════════
# Parser tools (NEW — promoted from dead code)
# ════════════════════════════════════════════════════════════════════════════


@wrapper.tool()
async def parse_output(parser: str, content: str) -> dict[str, Any]:
    """Parse raw tool output into structured findings.

    ``parser`` must be one of: ``nmap``, ``whatweb``, ``nuclei``, ``nikto``,
    ``dirb``. Use :func:`auto_parse_output` if you don't know the tool.
    """
    dispatch = {
        "nmap": parsers.parse_nmap,
        "whatweb": parsers.parse_whatweb,
        "nuclei": parsers.parse_nuclei,
        "nikto": parsers.parse_nikto,
        "dirb": parsers.parse_dirb,
    }
    fn = dispatch.get(parser.lower())
    if fn is None:
        return {"status": "error", "error": f"Unknown parser: {parser}", "available": list(dispatch)}
    try:
        return {"status": "success", "parser": parser.lower(), "findings": fn(content)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@wrapper.tool()
async def auto_parse_output(command: str, content: str) -> dict[str, Any]:
    """Auto-route a command's raw output to the right parser."""
    try:
        result = parsers.auto_parse(command, content)
        if result["parser"] is None:
            return {
                "status": "unsupported",
                "command": command,
                "note": "No parser registered for this command.",
            }
        return {"status": "success", **result}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ════════════════════════════════════════════════════════════════════════════
# Findings persistence
# ════════════════════════════════════════════════════════════════════════════


@wrapper.tool()
async def update_session_findings(
    session_id: str,
    parser: str,
    findings: dict[str, Any] | list[Any],
    command: str | None = None,
    session_path: str | None = None,
) -> dict[str, Any]:
    """Merge structured parser findings into session_metadata.json.

    Call this after ``auto_parse_output`` to persist discovered ports,
    vulnerabilities, technologies, etc. across the session lifetime.
    Findings are appended under ``metadata.findings[<parser>][]``.
    """
    try:
        target_dir = _resolve_target_dir(session_id, session_path)
        meta_path = target_dir / "session_metadata.json"

        # Load existing metadata or start fresh.
        metadata: dict[str, Any] = {}
        if meta_path.exists():
            async with aiofiles.open(meta_path, encoding="utf-8") as f:
                metadata = json.loads(await f.read())

        # Ensure findings structure exists.
        if "findings" not in metadata:
            metadata["findings"] = {}
        if parser not in metadata["findings"]:
            metadata["findings"][parser] = []

        # Build the entry.
        entry: dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "data": findings,
        }
        if command:
            entry["command"] = command

        metadata["findings"][parser].append(entry)
        metadata["last_updated"] = datetime.now().isoformat()

        # Write back.
        async with aiofiles.open(meta_path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(metadata, indent=2))

        # Count totals for the response.
        total = sum(len(v) for v in metadata["findings"].values())
        return {
            "status": "success",
            "session_id": session_id,
            "parser": parser,
            "entries_for_parser": len(metadata["findings"][parser]),
            "total_finding_entries": total,
            "metadata_path": str(meta_path),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════


def main() -> None:
    wrapper.run(transport="http")


if __name__ == "__main__":
    main()
