"""Thread-safe, lazily-authenticated Garmin Connect client.

The server never stores the Garmin password. Tokens are minted once on the
owner's machine (``garmin-mcp-login``), seeded into the server via the
``GARMIN_TOKENS`` secret, and from then on refreshed and persisted on the
volume by ``garminconnect`` itself. Repeated SSO logins from a datacenter IP
are exactly what gets accounts rate-limited (429) by Garmin, so we avoid them.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import anyio
from garminconnect import (
    Garmin,
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


class GarminUnavailable(RuntimeError):
    """Raised with a message that is safe and useful to show to the model/user."""


MAX_SEED_LENGTH = 16 * 1024


def write_private_file(path: Path, text: str) -> None:
    """Create/replace ``path`` with mode 0600 from the first byte (no umask window),
    refusing to follow symlinks, via an atomic rename."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def decode_token_seed(raw: str) -> str:
    """Accept the token blob as raw JSON or base64(JSON); return JSON text."""
    raw = raw.strip()
    if len(raw) > MAX_SEED_LENGTH:
        raise ValueError("GARMIN_TOKENS is too large")
    if raw.startswith("{"):
        text = raw
    else:
        try:
            text = base64.b64decode(raw, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError("GARMIN_TOKENS is neither JSON nor base64-encoded JSON") from e
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ValueError("GARMIN_TOKENS is not valid JSON") from e
    if not isinstance(data, dict) or not isinstance(data.get("di_refresh_token"), str):
        raise ValueError("GARMIN_TOKENS does not contain a di_refresh_token")  # noqa: TRY004
    return text


def seed_tokens(token_dir: Path, seed: str | None) -> None:
    """Write the seed to the volume unless tokens already exist there.

    Existing tokens win because they are newer: garminconnect rewrites the
    file whenever it refreshes.
    """
    token_file = token_dir / "garmin_tokens.json"
    if token_file.exists() or token_file.is_symlink() or not seed:
        return
    text = decode_token_seed(seed)
    write_private_file(token_file, text)
    logger.info("Seeded Garmin tokens into %s", token_file)


class GarminService:
    def __init__(self, token_dir: Path):
        self._token_dir = token_dir
        self._client: Garmin | None = None
        self._lock = threading.Lock()

    def _ensure(self) -> Garmin:
        with self._lock:
            if self._client is not None:
                return self._client
            token_file = self._token_dir / "garmin_tokens.json"
            if not token_file.exists():
                raise GarminUnavailable(
                    "Garmin tokens are not configured on the server. Run `garmin-mcp-login` "
                    "locally and set the GARMIN_TOKENS secret (see README)."
                )
            client = Garmin()  # no credentials: token-only, never hits SSO login
            try:
                client.login(tokenstore=str(self._token_dir))
            except GarminConnectTooManyRequestsError as e:
                raise GarminUnavailable(
                    "Garmin is rate limiting this account (429). Wait and retry later."
                ) from e
            except (GarminConnectAuthenticationError, GarminConnectConnectionError) as e:
                raise GarminUnavailable(
                    "Garmin rejected the stored tokens. Re-run `garmin-mcp-login` locally, delete "
                    "/data/garmin/garmin_tokens.json on the server and update GARMIN_TOKENS. "
                    f"Detail: {e}"
                ) from e
            self._client = client
            return client

    def _reset(self) -> None:
        with self._lock:
            self._client = None

    def call_sync(self, fn: Callable[[Garmin], T]) -> T:
        client = self._ensure()
        try:
            return fn(client)
        except GarminConnectAuthenticationError:
            # Token may have been invalidated server-side; reload from disk once.
            logger.warning("Garmin auth error; reloading tokens and retrying once")
            self._reset()
            client = self._ensure()
            try:
                return fn(client)
            except GarminConnectAuthenticationError as e:
                raise GarminUnavailable(f"Garmin authentication failed: {e}") from e
        except GarminConnectTooManyRequestsError as e:
            raise GarminUnavailable("Garmin rate limit hit (429). Retry later.") from e

    async def call(self, fn: Callable[[Garmin], T]) -> T:
        return await anyio.to_thread.run_sync(self.call_sync, fn)
