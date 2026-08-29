"""Security primitives shared by the MCP server and local backend."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import ipaddress
import os
import secrets
import stat
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

MIN_TOKEN_LENGTH = 32
BACKEND_AUTH_WINDOW_SECONDS = 30
DEFAULT_AUTH_SCOPES = (
    "mcpstrike:read",
    "mcpstrike:write",
    "mcpstrike:execute",
)


def is_loopback_host(host: str) -> bool:
    """Return whether *host* is an explicit loopback address or localhost."""
    normalized = host.strip().lower()
    if normalized in {"localhost", "localhost.localdomain"}:
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def require_loopback_host(host: str, service: str) -> None:
    """Reject listeners that would expose a privileged service directly."""
    if not is_loopback_host(host):
        raise ValueError(
            f"{service} only accepts loopback listeners; got {host!r}. "
            "Use 127.0.0.1 or ::1 and a TLS-authenticated reverse proxy or SSH tunnel."
        )


def require_secure_bearer_url(url: str, service: str) -> None:
    """Require TLS before transmitting a reusable bearer credential."""
    parsed = urlparse(url)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{service} URL must not contain embedded credentials")
    if parsed.scheme == "https" and parsed.hostname:
        return
    raise ValueError(f"{service} bearer authentication requires HTTPS; got {url!r}")


def require_secure_backend_url(url: str, service: str) -> None:
    """Allow the nonce-bound AEAD backend protocol on HTTPS or loopback HTTP."""
    parsed = urlparse(url)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{service} URL must not contain embedded credentials")
    if parsed.scheme == "https" and parsed.hostname:
        return
    if parsed.scheme == "http" and parsed.hostname and is_loopback_host(parsed.hostname):
        return
    raise ValueError(
        f"{service} authentication requires HTTPS for remote hosts; got {url!r}"
    )


def _backend_request_payload(
    method: str,
    path: str,
    body: bytes,
    timestamp: int,
    server_nonce: str,
    client_nonce: str,
) -> bytes:
    body_digest = hashlib.sha256(body).hexdigest()
    return (
        f"mcpstrike-backend-request-v2\n{timestamp}\n{client_nonce}\n{server_nonce}\n"
        f"{method.upper()}\n{path}\n{body_digest}"
    ).encode()


def backend_request_signature(
    token: str,
    method: str,
    path: str,
    body: bytes,
    timestamp: int,
    server_nonce: str,
    client_nonce: str,
) -> str:
    """Sign one exact backend request without transmitting the shared key."""
    key = validate_auth_token(token).encode("ascii")
    payload = _backend_request_payload(
        method,
        path,
        body,
        timestamp,
        server_nonce,
        client_nonce,
    )
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def backend_signature_headers(
    token: str,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    server_nonce: str,
    client_nonce: str,
    timestamp: int | None = None,
) -> dict[str, str]:
    """Build nonce-bound authentication headers for one backend request."""
    request_timestamp = int(time.time()) if timestamp is None else int(timestamp)
    signature = backend_request_signature(
        token,
        method,
        path,
        body,
        request_timestamp,
        server_nonce,
        client_nonce,
    )
    return {
        "X-MCPStrike-Timestamp": str(request_timestamp),
        "X-MCPStrike-Nonce": server_nonce,
        "X-MCPStrike-Client-Nonce": client_nonce,
        "X-MCPStrike-Signature": f"v2={signature}",
    }


def validate_backend_nonce(nonce: str) -> str:
    """Validate a bounded URL-safe nonce used by the local backend protocol."""
    if not 32 <= len(nonce) <= 128 or any(
        char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for char in nonce
    ):
        raise ValueError("Backend nonces must be 32-128 URL-safe characters")
    return nonce


def backend_challenge_proof(
    token: str,
    client_nonce: str,
    server_nonce: str,
    timestamp: int,
) -> str:
    """Prove backend possession of the shared key for one client nonce."""
    key = validate_auth_token(token).encode("ascii")
    client_nonce = validate_backend_nonce(client_nonce)
    server_nonce = validate_backend_nonce(server_nonce)
    payload = (
        f"mcpstrike-backend-challenge-v2\n{timestamp}\n"
        f"{client_nonce}\n{server_nonce}"
    ).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_backend_challenge(
    token: str,
    client_nonce: str,
    server_nonce: str,
    timestamp: int,
    proof: str,
    *,
    now: int | None = None,
) -> bool:
    """Verify a fresh backend challenge response in constant time."""
    current = int(time.time()) if now is None else int(now)
    if abs(current - int(timestamp)) > BACKEND_AUTH_WINDOW_SECONDS:
        return False
    try:
        expected = backend_challenge_proof(
            token,
            client_nonce,
            server_nonce,
            int(timestamp),
        )
    except ValueError:
        return False
    return hmac.compare_digest(proof, expected)


def _backend_session_key(token: str, client_nonce: str, server_nonce: str) -> bytes:
    key = validate_auth_token(token).encode("ascii")
    client_nonce = validate_backend_nonce(client_nonce)
    server_nonce = validate_backend_nonce(server_nonce)
    context = (
        f"mcpstrike-backend-session-v2\n{client_nonce}\n{server_nonce}"
    ).encode()
    return hmac.new(key, context, hashlib.sha256).digest()


def _backend_aead_aad(
    *,
    direction: str,
    method: str,
    path: str,
    timestamp: int,
    client_nonce: str,
    server_nonce: str,
    status_code: int | None,
) -> bytes:
    if direction not in {"request", "response"}:
        raise ValueError("Invalid backend message direction")
    status_value = "" if status_code is None else str(int(status_code))
    return (
        f"mcpstrike-backend-aead-v2\n{direction}\n{timestamp}\n"
        f"{client_nonce}\n{server_nonce}\n{method.upper()}\n{path}\n{status_value}"
    ).encode()


def encrypt_backend_message(
    token: str,
    plaintext: bytes,
    *,
    direction: str,
    method: str,
    path: str,
    timestamp: int,
    client_nonce: str,
    server_nonce: str,
    status_code: int | None = None,
) -> tuple[str, bytes]:
    """Encrypt and authenticate one backend request or response with AES-GCM."""
    key = _backend_session_key(token, client_nonce, server_nonce)
    message_nonce = os.urandom(12)
    aad = _backend_aead_aad(
        direction=direction,
        method=method,
        path=path,
        timestamp=timestamp,
        client_nonce=client_nonce,
        server_nonce=server_nonce,
        status_code=status_code,
    )
    ciphertext = AESGCM(key).encrypt(message_nonce, plaintext, aad)
    encoded_nonce = urlsafe_b64encode(message_nonce).rstrip(b"=").decode("ascii")
    return encoded_nonce, ciphertext


def decrypt_backend_message(
    token: str,
    ciphertext: bytes,
    message_nonce: str,
    *,
    direction: str,
    method: str,
    path: str,
    timestamp: int,
    client_nonce: str,
    server_nonce: str,
    status_code: int | None = None,
) -> bytes:
    """Decrypt one backend message and reject tampering or context reuse."""
    try:
        padded_nonce = message_nonce + "=" * (-len(message_nonce) % 4)
        nonce_bytes = urlsafe_b64decode(padded_nonce.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("Invalid backend encryption nonce") from exc
    if len(nonce_bytes) != 12:
        raise ValueError("Invalid backend encryption nonce")
    key = _backend_session_key(token, client_nonce, server_nonce)
    aad = _backend_aead_aad(
        direction=direction,
        method=method,
        path=path,
        timestamp=timestamp,
        client_nonce=client_nonce,
        server_nonce=server_nonce,
        status_code=status_code,
    )
    try:
        return AESGCM(key).decrypt(nonce_bytes, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError("Backend message authentication failed") from exc


def validate_auth_token(token: str) -> str:
    """Reject empty or guessable bearer tokens."""
    token = token.strip()
    if len(token) < MIN_TOKEN_LENGTH:
        raise ValueError(
            f"MCPSTRIKE_AUTH_TOKEN must contain at least {MIN_TOKEN_LENGTH} characters"
        )
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in token):
        raise ValueError("MCPSTRIKE_AUTH_TOKEN must contain printable ASCII without spaces")
    return token


def load_or_create_auth_token(
    token_path: Path,
    configured_token: str | None = None,
    *,
    create: bool,
) -> str | None:
    """Load a private bearer token, optionally creating it atomically."""
    if configured_token is not None:
        return validate_auth_token(configured_token)

    token_path = token_path.expanduser()
    if token_path.is_symlink():
        raise RuntimeError(f"Refusing symlinked authentication token: {token_path}")

    if token_path.exists():
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(token_path, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError(
                    f"Authentication token is not a regular file: {token_path}"
                )
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise PermissionError(
                    f"Authentication token is not owned by this user: {token_path}"
                )
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "r", encoding="ascii") as handle:
                fd = -1
                return validate_auth_token(handle.read())
        finally:
            if fd >= 0:
                os.close(fd)

    if not create:
        return None

    parent = token_path.parent
    if parent.is_symlink():
        raise RuntimeError(f"Refusing symlinked authentication directory: {parent}")
    parent_existed = parent.exists()
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    parent_info = parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode):
        raise RuntimeError(f"Authentication token parent is not a directory: {parent}")
    if hasattr(os, "getuid") and parent_info.st_uid != os.getuid():
        raise PermissionError(f"Authentication directory is not owned by this user: {parent}")
    # Only tighten a directory created for this token. A configured path may
    # point into an existing application directory that must not be chmodded.
    if not parent_existed and os.name == "posix":
        parent.chmod(0o700)

    token = secrets.token_urlsafe(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(token_path, flags, 0o600)
    except FileExistsError:
        return load_or_create_auth_token(token_path, create=False)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(token + "\n")
        handle.flush()
        if os.name == "posix":
            os.fchmod(handle.fileno(), 0o600)
    return token


def _read_private_regular_file(path: Path, label: str) -> bytes:
    if path.is_symlink():
        raise RuntimeError(f"Refusing symlinked {label}: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"{label.capitalize()} is not a regular file: {path}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise PermissionError(f"{label.capitalize()} is not owned by this user: {path}")
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        chunks: list[bytes] = []
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_private_file(path: Path, content: bytes, label: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"Refusing to replace existing {label}: {path}") from exc
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)


def load_or_create_local_tls_identity(
    cert_path: Path,
    key_path: Path,
    *,
    create: bool,
) -> tuple[Path, Path] | None:
    """Load or create the pinned TLS identity used by the loopback MCP server."""
    cert_path = cert_path.expanduser()
    key_path = key_path.expanduser()
    if cert_path.parent != key_path.parent:
        raise ValueError("MCP TLS certificate and key must share one private directory")

    cert_exists = cert_path.exists() or cert_path.is_symlink()
    key_exists = key_path.exists() or key_path.is_symlink()
    if cert_exists or key_exists:
        if not cert_exists or not key_exists:
            raise RuntimeError(
                "MCP TLS identity is incomplete; both certificate and key are required"
            )
        cert_pem = _read_private_regular_file(cert_path, "MCP TLS certificate")
        key_pem = _read_private_regular_file(key_path, "MCP TLS private key")
        try:
            certificate = x509.load_pem_x509_certificate(cert_pem)
            private_key = serialization.load_pem_private_key(key_pem, password=None)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("MCP TLS identity is malformed") from exc
        cert_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if not hmac.compare_digest(cert_public, key_public):
            raise RuntimeError("MCP TLS certificate does not match its private key")
        return cert_path, key_path

    if not create:
        return None

    parent = cert_path.parent
    if parent.is_symlink():
        raise RuntimeError(f"Refusing symlinked MCP TLS directory: {parent}")
    parent_existed = parent.exists()
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    parent_info = parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode):
        raise RuntimeError(f"MCP TLS parent is not a directory: {parent}")
    if hasattr(os, "getuid") and parent_info.st_uid != os.getuid():
        raise PermissionError(f"MCP TLS directory is not owned by this user: {parent}")
    if not parent_existed and os.name == "posix":
        parent.chmod(0o700)

    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "mcpstrike local MCP")]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    _write_private_file(key_path, key_pem, "MCP TLS private key")
    try:
        _write_private_file(cert_path, cert_pem, "MCP TLS certificate")
    except Exception:
        # The private key was just created in this call and is unusable without
        # its matching certificate; remove only that exact owner-controlled file.
        with contextlib.suppress(OSError):
            key_path.unlink()
        raise
    return cert_path, key_path
