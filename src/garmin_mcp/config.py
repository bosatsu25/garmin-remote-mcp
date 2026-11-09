"""Runtime configuration, read from environment variables. Fails closed."""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .security import OwnerSecret, SecretFormatError, has_control_chars

logger = logging.getLogger(__name__)

MIN_OWNER_PASSWORD_LENGTH = 16
MAX_OWNER_PASSWORD_LENGTH = 1024

DEFAULT_REDIRECT_HOSTS = ("claude.ai", "claude.com", "localhost", "127.0.0.1")

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


class ConfigError(RuntimeError):
    pass


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    v = raw.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise ConfigError(f"{name} must be true/false, got {raw!r}")


def validate_public_url(raw: str) -> str:
    url = raw.strip().rstrip("/")
    if not url:
        raise ConfigError("PUBLIC_URL is required (e.g. https://my-garmin-mcp.fly.dev)")
    try:
        parts = urlsplit(url)
        _ = parts.port
    except ValueError as e:
        raise ConfigError(f"PUBLIC_URL is not a valid URL: {raw!r}") from e
    host = (parts.hostname or "").lower()
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigError("PUBLIC_URL must not contain credentials, query or fragment")
    if parts.path not in ("", "/"):
        raise ConfigError("PUBLIC_URL must be an origin without a path")
    if parts.scheme == "https" and host:
        return url
    if parts.scheme == "http" and host in {"localhost", "127.0.0.1"}:
        return url
    raise ConfigError("PUBLIC_URL must be https:// (http is only allowed for localhost)")


def load_owner_secret(env: Mapping[str, str]) -> OwnerSecret:
    hashed = env.get("OWNER_PASSWORD_HASH", "").strip()
    plain = env.get("OWNER_PASSWORD", "")
    if hashed and plain:
        raise ConfigError("Set only one of OWNER_PASSWORD_HASH or OWNER_PASSWORD")
    if hashed:
        try:
            return OwnerSecret.from_hash(hashed)
        except SecretFormatError as e:
            raise ConfigError(str(e)) from e
    if not plain:
        raise ConfigError("OWNER_PASSWORD_HASH (recommended) or OWNER_PASSWORD is required")
    if len(plain) < MIN_OWNER_PASSWORD_LENGTH:
        raise ConfigError(
            f"OWNER_PASSWORD must be at least {MIN_OWNER_PASSWORD_LENGTH} characters"
        )
    if len(plain) > MAX_OWNER_PASSWORD_LENGTH:
        raise ConfigError(f"OWNER_PASSWORD must be at most {MAX_OWNER_PASSWORD_LENGTH} characters")
    if has_control_chars(plain):
        raise ConfigError("OWNER_PASSWORD must not contain control characters")
    logger.warning(
        "OWNER_PASSWORD is set in plaintext; prefer OWNER_PASSWORD_HASH "
        "(generate with `garmin-mcp-hash-password`)"
    )
    return OwnerSecret.from_plaintext(plain)


@dataclass(frozen=True)
class Settings:
    public_url: str
    """Externally reachable origin, e.g. https://my-garmin-mcp.fly.dev (no trailing slash)."""

    owner_secret: OwnerSecret = field(repr=False)
    data_dir: Path = Path("/data")
    host: str = "0.0.0.0"  # noqa: S104 - container listens on all interfaces by design
    port: int = 8000
    allow_write: bool = True
    """Expose write tools at all. Each connection must additionally be granted
    the garmin:write scope on the consent page."""
    enable_raw_api: bool = False
    """Expose garmin_api_get (arbitrary read-only Garmin API GETs)."""
    trust_fly_client_ip: bool = False
    """Use the Fly-Client-IP header for rate limiting. Only safe behind Fly's proxy,
    which overwrites the header; elsewhere it is client-controlled."""
    allowed_redirect_hosts: tuple[str, ...] = DEFAULT_REDIRECT_HOSTS
    access_token_ttl: int = 3600
    refresh_token_ttl: int = 60 * 60 * 24 * 30
    token_family_max_age: int = 60 * 60 * 24 * 90
    garmin_tokens_seed: str | None = field(default=None, repr=False)

    @property
    def mcp_path(self) -> str:
        return "/mcp"

    @property
    def resource_url(self) -> str:
        return f"{self.public_url}{self.mcp_path}"

    @property
    def garmin_token_dir(self) -> Path:
        return self.data_dir / "garmin"

    @property
    def oauth_state_file(self) -> Path:
        return self.data_dir / "oauth_state.json"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        public_url = validate_public_url(env.get("PUBLIC_URL", ""))
        owner_secret = load_owner_secret(env)

        hosts_raw = env.get("ALLOWED_REDIRECT_HOSTS", "")
        hosts = (
            tuple(h.strip().lower() for h in hosts_raw.split(",") if h.strip())
            if hosts_raw.strip()
            else DEFAULT_REDIRECT_HOSTS
        )
        if any("*" in h or "/" in h or ":" in h for h in hosts):
            raise ConfigError("ALLOWED_REDIRECT_HOSTS takes bare hostnames (no wildcards/ports)")

        try:
            port = int(env.get("PORT", "8000"))
        except ValueError as e:
            raise ConfigError("PORT must be an integer") from e
        if not 1 <= port <= 65535:
            raise ConfigError("PORT must be 1-65535")

        on_fly = bool(env.get("FLY_APP_NAME"))
        return cls(
            public_url=public_url,
            owner_secret=owner_secret,
            data_dir=Path(env.get("DATA_DIR", "/data")),
            host=env.get("HOST", "0.0.0.0"),  # noqa: S104
            port=port,
            allow_write=_bool(env, "GARMIN_ALLOW_WRITE", True),
            enable_raw_api=_bool(env, "GARMIN_ENABLE_RAW_API", False),
            trust_fly_client_ip=_bool(env, "TRUST_FLY_CLIENT_IP", on_fly),
            allowed_redirect_hosts=hosts,
            garmin_tokens_seed=env.get("GARMIN_TOKENS") or None,
        )
