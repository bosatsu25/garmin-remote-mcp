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
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

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


def decode_token_seed(raw: str) -> str:
    """Accept the token blob as raw JSON or base64(JSON); return JSON text."""
    raw = raw.strip()
    if raw.startswith("{"):
        text = raw
    else:
        try:
            text = base64.b64decode(raw, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError("GARMIN_TOKENS is neither JSON nor base64-encoded JSON") from e
    data = json.loads(text)
    if not isinstance(data, dict) or not data.get("di_refresh_token"):
        raise ValueError("GARMIN_TOKENS does not contain a di_refresh_token")
    return text


def seed_tokens(token_dir: Path, seed: str | None) -> None:
    """Write the seed to the volume unless tokens already exist there.

    Existing tokens win because they are newer: garminconnect rewrites the
    file whenever it refreshes.
    """
    token_file = token_dir / "garmin_tokens.json"
    if token_file.exists() or not seed:
        return
    text = decode_token_seed(seed)
    token_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    token_file.write_text(text, encoding="utf-8")
    token_file.chmod(0o600)
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

    async def profile(self) -> dict[str, Any]:
        def _p(g: Garmin) -> dict[str, Any]:
            return {
                "full_name": g.get_full_name(),
                "unit_system": g.get_unit_system(),
                "timezone": g.get_user_timezone(),
                "today": g.today().isoformat(),
            }

        return await self.call(_p)
