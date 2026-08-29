"""Single source of truth for configuration.

All env vars are resolved here via pydantic-settings. Both the server and the
client import :data:`settings` instead of reading ``os.getenv`` directly — this
kills the "config sparse in 4 places" problem of the legacy layout.

Env vars (all optional):
    HEXSTRIKE_BACKEND_URL  — URL del backend HexStrike (default http://localhost:8888)
    MCPSTRIKE_BACKEND_HOST — host del backend locale (default 127.0.0.1)
    MCPSTRIKE_BACKEND_PORT — porta del backend locale (default 8890)
    MCPSTRIKE_BACKEND_AUTH_TOKEN — token esplicito per backend su URL personalizzato
    MCPSTRIKE_BACKEND_AUTH_TOKEN_PATH — file chiave HMAC dedicato al backend
    MCPSTRIKE_HOST         — host del server FastMCP (default 127.0.0.1)
    MCPSTRIKE_PORT         — porta del server FastMCP (default 8889)
    MCPSTRIKE_MCP_URL      — URL del server MCP per il client (default https://localhost:8889/mcp)
    MCPSTRIKE_AUTH_TOKEN   — bearer token condiviso (minimo 32 caratteri)
    MCPSTRIKE_AUTH_TOKEN_PATH — file token privato (default ~/.config/mcpstrike/auth-token)
    MCPSTRIKE_AUTH_SCOPES  — scope assegnati al token, separati da virgola
    MCPSTRIKE_TLS_CERT_PATH — certificato TLS locale pinned dal client
    MCPSTRIKE_TLS_KEY_PATH  — chiave TLS locale privata del server
    OLLAMA_URL             — URL del daemon Ollama (default http://localhost:11434)
    OLLAMA_MODEL           — modello Ollama predefinito (default llama3.2)
    HEXSTRIKE_SESSION_PATH — path completo per la directory sessioni (priorità massima)
    HEXSTRIKE_SESSION_DIR  — nome cartella in $HOME (usato solo se SESSION_PATH è assente)
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .common.security import (
    DEFAULT_AUTH_SCOPES,
    is_loopback_host,
    load_or_create_auth_token,
    load_or_create_local_tls_identity,
    require_secure_backend_url,
    validate_auth_token,
)


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
    backend_host: str = Field(
        default="127.0.0.1",
        validation_alias="MCPSTRIKE_BACKEND_HOST",
    )
    backend_port: int = Field(default=8890, validation_alias="MCPSTRIKE_BACKEND_PORT")
    backend_auth_token: str | None = Field(
        default=None,
        validation_alias="MCPSTRIKE_BACKEND_AUTH_TOKEN",
    )
    backend_auth_token_path: str = Field(
        default="~/.config/mcpstrike/backend-auth-token",
        validation_alias="MCPSTRIKE_BACKEND_AUTH_TOKEN_PATH",
    )

    # ── MCP server (lato server) ───────────────────────────────────────────
    server_host: str = Field(default="127.0.0.1", validation_alias="MCPSTRIKE_HOST")
    server_port: int = Field(default=8889, validation_alias="MCPSTRIKE_PORT")

    # ── Authentication ─────────────────────────────────────────────────────
    auth_token: str | None = Field(default=None, validation_alias="MCPSTRIKE_AUTH_TOKEN")
    auth_token_path: str = Field(
        default="~/.config/mcpstrike/auth-token",
        validation_alias="MCPSTRIKE_AUTH_TOKEN_PATH",
    )
    auth_scopes: str = Field(
        default=",".join(DEFAULT_AUTH_SCOPES),
        validation_alias="MCPSTRIKE_AUTH_SCOPES",
    )
    tls_cert_path: str = Field(
        default="~/.config/mcpstrike/mcp-local.crt",
        validation_alias="MCPSTRIKE_TLS_CERT_PATH",
    )
    tls_key_path: str = Field(
        default="~/.config/mcpstrike/mcp-local.key",
        validation_alias="MCPSTRIKE_TLS_KEY_PATH",
    )

    # ── MCP client (lato client) ───────────────────────────────────────────
    mcp_url: str = Field(
        default="https://localhost:8889/mcp",
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

    def resolve_auth_token(self, *, create: bool = False) -> str | None:
        """Return the configured token or the private per-user token file."""
        return load_or_create_auth_token(
            Path(self.auth_token_path),
            self.auth_token,
            create=create,
        )

    def auth_scope_list(self) -> tuple[str, ...]:
        """Return normalized bearer-token scopes."""
        scopes = tuple(scope.strip() for scope in self.auth_scopes.split(",") if scope.strip())
        if "mcpstrike:read" not in scopes:
            raise ValueError("MCPSTRIKE_AUTH_SCOPES must include mcpstrike:read")
        return scopes

    def resolve_mcp_tls_identity(self, *, create: bool = False) -> tuple[Path, Path] | None:
        """Return the pinned loopback TLS certificate and its server key."""
        return load_or_create_local_tls_identity(
            Path(self.tls_cert_path),
            Path(self.tls_key_path),
            create=create,
        )

    def resolve_backend_auth_token(self, *, create: bool = False) -> str | None:
        """Return a credential dedicated to the standalone backend."""
        return load_or_create_auth_token(
            Path(self.backend_auth_token_path),
            self.backend_auth_token,
            create=create,
        )

    def auth_token_for_backend_url(self, url: str) -> str | None:
        """Authenticate only the built-in backend or an explicitly configured peer.

        The default ``localhost:8888`` service is external HexStrike. Sending the
        MCP bearer token there would disclose a more privileged credential.
        """
        if self.backend_auth_token is not None:
            require_secure_backend_url(url, "mcpstrike backend")
            return validate_auth_token(self.backend_auth_token)
        parsed = urlparse(url)
        if (
            parsed.scheme in {"http", "https"}
            and parsed.hostname is not None
            and is_loopback_host(parsed.hostname)
            and parsed.port == self.backend_port
        ):
            require_secure_backend_url(url, "mcpstrike backend")
            return self.resolve_backend_auth_token(create=False)
        return None

    def backend_auth_required_for_url(self, url: str) -> bool:
        """Return whether this URL is configured to use mcpstrike HMAC auth."""
        if self.backend_auth_token is not None:
            return True
        parsed = urlparse(url)
        return bool(
            parsed.scheme in {"http", "https"}
            and parsed.hostname is not None
            and is_loopback_host(parsed.hostname)
            and parsed.port == self.backend_port
        )


settings = Settings()
