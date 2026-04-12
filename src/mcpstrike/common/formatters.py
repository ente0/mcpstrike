"""Human-readable report formatting for command execution output.

Shared between server (auto-saving on ``execute_command``) and client (TUI
preview). Single copy, single format.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .filenames import extract_target


def _coerce_text(value: Any) -> str:
    if isinstance(value, dict):
        if "stdout" in value:
            return str(value["stdout"])
        if "output" in value:
            return str(value["output"])
        return json.dumps(value, indent=2)
    return "" if value is None else str(value)


def extract_output_and_error(result: dict[str, Any]) -> tuple[str, str]:
    """Best-effort extraction of stdout/stderr from a heterogeneous MCP result.

    Handles: MCP ``content`` array, ``structuredContent``, and a pile of
    historical field names (``output``, ``stdout``, ``result``, ``data``,
    ``text``, ``error``, ``stderr``, ``errors``).
    """
    output_text = ""
    error_text = ""

    # MCP standard: result["content"] is a list of {type, text} blocks.
    content_blocks = result.get("content")
    if isinstance(content_blocks, list):
        for item in content_blocks:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text" and "text" in item:
                text = item["text"]
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, dict) and "output" in parsed:
                        output_text += _coerce_text(parsed["output"])
                    else:
                        output_text += text + "\n"
                except (json.JSONDecodeError, TypeError):
                    output_text += text + "\n"
            elif "content" in item:
                output_text += _coerce_text(item["content"]) + "\n"

    # FastMCP sometimes also sets a structuredContent field.
    struct = result.get("structuredContent")
    if isinstance(struct, dict):
        if not output_text and "output" in struct:
            output_text = _coerce_text(struct["output"])
        if "stderr" in struct:
            error_text = _coerce_text(struct["stderr"])

    # Legacy fallbacks.
    if not output_text:
        for field in ("output", "stdout", "result", "data", "text"):
            if field in result:
                output_text = _coerce_text(result[field])
                if output_text:
                    break

    if not error_text:
        for field in ("error", "stderr", "errors"):
            if field in result:
                error_text = _coerce_text(result[field])
                if error_text:
                    break

    if not output_text and not error_text:
        output_text = json.dumps(result, indent=2)

    return output_text, error_text


def format_command_report(command: str, args: list[str], result: dict[str, Any]) -> str:
    """Render a single-command execution report for on-disk storage."""
    output_text, error_text = extract_output_and_error(result)
    target = extract_target(args)
    full_command = f"{command} {' '.join(args)}"

    meta = result.get("structuredContent", result) if isinstance(result, dict) else {}
    timestamp = meta.get("timestamp", result.get("timestamp", datetime.now().isoformat()))
    exit_code = meta.get("exit_code", result.get("exit_code", result.get("exitCode", "N/A")))
    duration = meta.get("duration", result.get("duration", 0)) or 0
    status = meta.get("status", result.get("status", "completed"))

    try:
        duration_str = f"{float(duration):.2f}"
    except (TypeError, ValueError):
        duration_str = str(duration)

    bar = "=" * 80
    return (
        f"{bar}\n"
        f"MCPSTRIKE COMMAND EXECUTION REPORT\n"
        f"{bar}\n\n"
        f"EXECUTION DETAILS:\n"
        f"  Command:    {command}\n"
        f"  Arguments:  {' '.join(args)}\n"
        f"  Full CMD:   {full_command}\n"
        f"  Target:     {target}\n"
        f"  Timestamp:  {timestamp}\n"
        f"  Exit Code:  {exit_code}\n"
        f"  Duration:   {duration_str} seconds\n"
        f"  Status:     {status}\n\n"
        f"{bar}\nOUTPUT\n{bar}\n\n"
        f"{output_text.strip() if output_text else '(no output captured)'}\n\n"
        f"{bar}\nERRORS\n{bar}\n\n"
        f"{error_text.strip() if error_text else '(no errors)'}\n\n"
        f"{bar}\nEND OF REPORT\n{bar}\n"
    )
