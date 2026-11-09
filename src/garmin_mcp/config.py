"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

MIN_OWNER_PASSWORD_LENGTH = 16

DEFAULT_REDIRECT_HOSTS = ("claude.ai", "claude.com", "localhost", "127.0.0.1")


class ConfigError(RuntimeError):
    pass


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    public_url: str
    """Externally reachable base URL, e.g. https://my-garmin-mcp.fly.dev (no trailing slash)."""

    owner_password: str
    """Passphrase the owner types on the OAuth consent page."""

    data_dir: Path
    host: str = "0.0.0.0"
    port: int = 8000
    allow_write: bool = True
    allowed_redirect_hosts: tuple[str, ...] = DEFAULT_REDIRECT_HOSTS
    access_token_ttl: int = 3600
    refresh_token_ttl: int = 60 * 60 * 24 * 30
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
    def from_env(cls) -> Settings:
        public_url = os.getenv("PUBLIC_URL", "").strip().rstrip("/")
        if not public_url:
            raise ConfigError("PUBLIC_URL is required (e.g. https://my-garmin-mcp.fly.dev)")
        if not public_url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise ConfigError("PUBLIC_URL must be https:// (http is only allowed for localhost)")

        owner_password = os.getenv("OWNER_PASSWORD", "")
        if len(owner_password) < MIN_OWNER_PASSWORD_LENGTH:
            raise ConfigError(
                f"OWNER_PASSWORD must be at least {MIN_OWNER_PASSWORD_LENGTH} characters"
            )

        hosts_raw = os.getenv("ALLOWED_REDIRECT_HOSTS", "")
        hosts = (
            tuple(h.strip().lower() for h in hosts_raw.split(",") if h.strip())
            if hosts_raw
            else DEFAULT_REDIRECT_HOSTS
        )

        return cls(
            public_url=public_url,
            owner_password=owner_password,
            data_dir=Path(os.getenv("DATA_DIR", "/data")),
            host=os.getenv("HOST", "0.0.0.0"),
            port=int(os.getenv("PORT", "8000")),
            allow_write=_bool("GARMIN_ALLOW_WRITE", True),
            allowed_redirect_hosts=hosts,
            garmin_tokens_seed=os.getenv("GARMIN_TOKENS") or None,
        )
