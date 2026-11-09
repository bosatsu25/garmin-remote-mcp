"""Security primitives: owner secret verification, redirect policy, rate limiting,
secret redaction. Kept free of I/O so each piece can be unit tested in isolation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# ---------------------------------------------------------------- owner secret
# scrypt parameters (OWASP 2023 minimum is N=2^17, r=8, p=1; ~128 MiB, ~0.1-0.3 s).
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 256 * 1024 * 1024
_HASH_PREFIX = "scrypt"


class SecretFormatError(ValueError):
    pass


def has_control_chars(s: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )


def hash_owner_password(password: str, *, n: int = SCRYPT_N, r: int = SCRYPT_R,
                        p: int = SCRYPT_P) -> str:
    """Return ``scrypt$N$r$p$salt$hash`` (base64url, unpadded)."""
    if has_control_chars(password):
        raise ValueError("password must not contain control characters")
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, n, r, p)
    return f"{_HASH_PREFIX}${n}${r}${p}${_b64e(salt)}${_b64e(digest)}"


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass(frozen=True)
class OwnerSecret:
    """Verifier for the owner passphrase. Holds only a salted scrypt digest."""

    n: int
    r: int
    p: int
    salt: bytes = field(repr=False)
    digest: bytes = field(repr=False)

    @classmethod
    def from_hash(cls, encoded: str) -> OwnerSecret:
        parts = encoded.strip().split("$")
        if len(parts) != 6 or parts[0] != _HASH_PREFIX:
            raise SecretFormatError("OWNER_PASSWORD_HASH must look like scrypt$N$r$p$salt$hash")
        try:
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            salt, digest = _b64d(parts[4]), _b64d(parts[5])
        except (ValueError, binascii.Error) as e:
            raise SecretFormatError("OWNER_PASSWORD_HASH is malformed") from e
        if n < 2**14 or n & (n - 1) or r < 8 or p < 1:
            raise SecretFormatError("OWNER_PASSWORD_HASH uses scrypt parameters that are too weak")
        if len(salt) < 16 or len(digest) != SCRYPT_DKLEN:
            raise SecretFormatError("OWNER_PASSWORD_HASH salt/hash length is invalid")
        return cls(n=n, r=r, p=p, salt=salt, digest=digest)

    @classmethod
    def from_plaintext(cls, password: str, *, n: int = SCRYPT_N) -> OwnerSecret:
        return cls.from_hash(hash_owner_password(password, n=n))

    def verify(self, candidate: str) -> bool:
        # Bound the work an attacker can force per request.
        if len(candidate) > 1024:
            return False
        # scrypt's inner HMAC zero-pads keys, so "pw" and "pw\0" would collide.
        if has_control_chars(candidate):
            return False
        actual = _scrypt(candidate, self.salt, self.n, self.r, self.p)
        return hmac.compare_digest(actual, self.digest)


# ------------------------------------------------------------- redirect policy
MAX_REDIRECT_URI_LENGTH = 512
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1"})


def redirect_uri_allowed(uri: str, allowed_hosts: frozenset[str] | tuple[str, ...]) -> bool:
    """Decide whether a client may register ``uri`` as an OAuth redirect target.

    Rules (decision table in docs/test-plan.md):
    * https to an allowlisted host, any path.
    * http only to a loopback host that is also allowlisted (native app callbacks).
    * Never: userinfo, fragments, non-default schemes, control chars, overlong URIs.
    """
    if not isinstance(uri, str) or len(uri) > MAX_REDIRECT_URI_LENGTH:
        return False
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in uri) or "\\" in uri:
        return False
    try:
        parts = urlsplit(uri)
        port = parts.port  # raises ValueError on garbage ports
    except ValueError:
        return False
    if parts.fragment or "#" in uri:
        return False
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return False
    host = (parts.hostname or "").lower()
    if not host or host not in {h.lower() for h in allowed_hosts}:
        return False
    if parts.scheme == "https":
        return True
    if parts.scheme == "http" and host in LOOPBACK_HOSTS:
        return port is None or 1 <= port <= 65535
    return False


# ---------------------------------------------------------------- rate limiter
@dataclass
class FailureRateLimiter:
    """Sliding-window limiter for failed password attempts.

    States per key: OPEN (failures < max) -> LOCKED (failures >= max within window)
    -> OPEN again once old failures age out of the window.
    """

    per_key_max: int = 5
    per_key_window: float = 15 * 60
    global_max: int = 30
    global_window: float = 60 * 60
    max_keys: int = 10_000
    clock: Callable[[], float] = time.time
    _hits: dict[str, list[float]] = field(default_factory=dict)
    _global: list[float] = field(default_factory=list)

    def _prune(self, now: float) -> None:
        self._global = [t for t in self._global if t > now - self.global_window]
        for k in list(self._hits):
            kept = [t for t in self._hits[k] if t > now - self.per_key_window]
            if kept:
                self._hits[k] = kept
            else:
                del self._hits[k]

    def is_locked(self, key: str) -> bool:
        now = self.clock()
        self._prune(now)
        return (
            len(self._hits.get(key, ())) >= self.per_key_max
            or len(self._global) >= self.global_max
        )

    def record_failure(self, key: str) -> None:
        now = self.clock()
        self._prune(now)
        if key not in self._hits and len(self._hits) >= self.max_keys:
            # Memory bound: drop the key whose newest failure is oldest.
            oldest = min(self._hits, key=lambda k: self._hits[k][-1])
            del self._hits[oldest]
        self._hits.setdefault(key, []).append(now)
        self._global.append(now)

    def record_success(self, key: str) -> None:
        self._hits.pop(key, None)


# ------------------------------------------------------------------- redaction
_REDACTIONS = [
    # JWTs (Garmin DI tokens are JWTs)
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # Authorization headers
    re.compile(r"(?i)(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    # key=value / "key": "value" pairs for well-known secret names
    re.compile(
        r"(?i)(\"?(?:access_token|refresh_token|di_token|di_refresh_token|password|"
        r"client_secret|code_verifier|token)\"?\s*[:=]\s*\"?)[^\"&,\s}]+"
    ),
    # Long opaque base64url blobs (JWT parts, token_urlsafe). "/" is excluded so URL paths
    # split into short segments and survive. Must look random: letters+digits or mixed case.
    # Anchored at the start of a run, so matching stays linear-time.
    re.compile(
        r"(?<![A-Za-z0-9_\-])"
        r"(?:(?=[A-Za-z0-9_\-]*[A-Za-z])(?=[A-Za-z0-9_\-]*[0-9])"
        r"|(?=[A-Za-z0-9_\-]*[A-Z])(?=[A-Za-z0-9_\-]*[a-z]))"
        r"[A-Za-z0-9_\-]{32,}={0,2}"
    ),
    # Long hex blobs
    re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])"),
]


def redact(text: str) -> str:
    """Strip anything that looks like a credential from text bound for users/logs."""
    out = text
    for i, pat in enumerate(_REDACTIONS):
        if i == 2:
            out = pat.sub(lambda m: m.group(1) + "[REDACTED]", out)
        else:
            out = pat.sub("[REDACTED]", out)
    return out
