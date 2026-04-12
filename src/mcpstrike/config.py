"""Single source of truth for configuration.

All env vars are resolved here via pydantic-settings. Both the server and the
client import :data:`settings` instead of reading ``os.getenv`` directly — this
kills the "config sparse in 4 places" problem of the legacy layout.

Env vars (all optional):
    HEXSTRIKE_BACKEND_URL  — URL del backend HexStrike (default http://localhost:8888)
    MCPSTRIKE_HOST         — host del server FastMCP (default 0.0.0.0)
    MCPSTRIKE_PORT         — porta del server FastMCP (default 8889)
    MCPSTRIKE_MCP_URL      — URL del server MCP per il client (default http://localhost:8889/mcp)
    OLLAMA_URL             — URL del daemon Ollama (default http://localhost:11434)
    OLLAMA_MODEL           — modello Ollama predefinito (default llama3.2)
    HEXSTRIKE_SESSION_PATH — path completo per la directory sessioni (priorità massima)
    HEXSTRIKE_SESSION_DIR  — nome cartella in $HOME (usato solo se SESSION_PATH è assente)
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # ── Backend ────────────────────────────────────────────────────────────
    backend_url: str = Field(
        default="http://localhost:8888",
        validation_alias="HEXSTRIKE_BACKEND_URL",
    )

    # ── MCP server (lato server) ───────────────────────────────────────────
    server_host: str = Field(default="0.0.0.0", validation_alias="MCPSTRIKE_HOST")
    server_port: int = Field(default=8889, validation_alias="MCPSTRIKE_PORT")

    # ── MCP client (lato client) ───────────────────────────────────────────
    mcp_url: str = Field(
        default="http://localhost:8889/mcp",
        validation_alias="MCPSTRIKE_MCP_URL",
    )

    # ── Ollama ─────────────────────────────────────────────────────────────
    ollama_url: str = Field(default="http://localhost:11434", validation_alias="OLLAMA_URL")
    ollama_model: str = Field(default="llama3.2", validation_alias="OLLAMA_MODEL")

    # ── Sessions ───────────────────────────────────────────────────────────
    session_path: str | None = Field(default=None, validation_alias="HEXSTRIKE_SESSION_PATH")
    session_dir_name: str | None = Field(default=None, validation_alias="HEXSTRIKE_SESSION_DIR")

    def resolve_session_dir(self) -> Path:
        """Resolve the effective session directory.

        Priority:
            1. ``HEXSTRIKE_SESSION_PATH`` (absolute path)
            2. ``HEXSTRIKE_SESSION_DIR`` (folder name in $HOME)
            3. ``~/hexstrike_sessions`` (default)
        """
        if self.session_path:
            return Path(self.session_path).expanduser()
        if self.session_dir_name:
            return Path.home() / self.session_dir_name
        return Path.home() / "hexstrike_sessions"


settings = Settings()
