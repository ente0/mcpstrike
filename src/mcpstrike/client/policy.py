"""Deterministic policy for model-requested MCP actions."""

from __future__ import annotations

HIGH_IMPACT_TOOLS = frozenset(
    {
        "create_session",
        "discover_sessions",
        "execute_command",
        "import_external_session",
        "list_models",
        "read_session_file",
        "set_session_directory",
        "update_session_findings",
        "write_session_file",
    }
)


def requires_human_approval(tool_name: str) -> bool:
    """Return whether a model-requested tool may create a host-side effect."""
    return tool_name in HIGH_IMPACT_TOOLS


def untrusted_tool_result(tool_name: str, result_json: str) -> dict[str, str]:
    """Build the canonical Ollama tool-result message."""
    return {
        "role": "tool",
        "tool_name": tool_name,
        "content": result_json,
    }
