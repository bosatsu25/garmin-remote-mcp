"""Security primitives: owner secret verification, redirect policy, rate limiting,
secret redaction. Kept free of I/O so each piece can be unit tested in isolation."""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import re
import secrets
import time
import unicodedata
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
# "scrypt-nfkc": passphrase NFKC-normalized before hashing (current).
# "scrypt": legacy, raw passphrase bytes (hashes made before normalization existed);
#           still accepted so an upgrade never locks the owner out.
_HASH_PREFIX = "scrypt-nfkc"
_LEGACY_PREFIX = "scrypt"


class SecretFormatError(ValueError):
    pass


def has_control_chars(s: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)


def normalize_password(s: str) -> str:
    """NFKC, as NIST SP 800-63B recommends, so the same passphrase typed on different
    keyboards/IMEs (composed vs decomposed kana, full-width vs half-width) verifies."""
    return unicodedata.normalize("NFKC", s)


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )


def hash_owner_password(password: str, *, n: int = SCRYPT_N, r: int = SCRYPT_R,
                        p: int = SCRYPT_P) -> str:
    """Return ``scrypt-nfkc$N$r$p$salt$hash`` (base64url, unpadded)."""
    if has_control_chars(password):
        raise ValueError("password must not contain control characters")
    salt = secrets.token_bytes(16)
    digest = _scrypt(normalize_password(password), salt, n, r, p)
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
    normalize: bool = True

    @classmethod
    def from_hash(cls, encoded: str) -> OwnerSecret:
        parts = encoded.strip().split("$")
        if len(parts) != 6 or parts[0] not in (_HASH_PREFIX, _LEGACY_PREFIX):
            raise SecretFormatError(
                "OWNER_PASSWORD_HASH must look like scrypt-nfkc$N$r$p$salt$hash"
            )
        try:
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            salt, digest = _b64d(parts[4]), _b64d(parts[5])
        except (ValueError, binascii.Error) as e:
            raise SecretFormatError("OWNER_PASSWORD_HASH is malformed") from e
        if n < 2**14 or n & (n - 1) or r < 8 or p < 1:
            raise SecretFormatError("OWNER_PASSWORD_HASH uses scrypt parameters that are too weak")
        if len(salt) < 16 or len(digest) != SCRYPT_DKLEN:
            raise SecretFormatError("OWNER_PASSWORD_HASH salt/hash length is invalid")
        return cls(n=n, r=r, p=p, salt=salt, digest=digest,
                   normalize=parts[0] == _HASH_PREFIX)

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
        material = normalize_password(candidate) if self.normalize else candidate
        actual = _scrypt(material, self.salt, self.n, self.r, self.p)
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
    # reservation id -> (key, timestamp) for attempts counted but not yet decided
    _inflight: dict[int, tuple[str, float]] = field(default_factory=dict)
    _next_id: int = 0

    def _prune(self, now: float) -> None:
        self._global = [t for t in self._global if t > now - self.global_window]
        self._inflight = {
            rid: (k, t) for rid, (k, t) in self._inflight.items()
            if t > now - max(self.per_key_window, self.global_window)
        }
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

    def record_failure(self, key: str) -> int:
        """Count one attempt against ``key`` and return its reservation id.

        Callers count an attempt *before* the slow password check (counting afterwards
        lets N concurrent requests all pass ``is_locked`` and get N guesses), then settle
        the reservation: ``commit`` it on a wrong password, or pass it to
        ``record_success`` on a right one.
        """
        now = self.clock()
        self._prune(now)
        if key not in self._hits and len(self._hits) >= self.max_keys:
            # Memory bound: drop the key whose newest failure is oldest.
            oldest = min(self._hits, key=lambda k: self._hits[k][-1])
            del self._hits[oldest]
        self._hits.setdefault(key, []).append(now)
        self._global.append(now)
        self._next_id += 1
        self._inflight[self._next_id] = (key, now)
        return self._next_id

    def commit(self, reservation: int) -> None:
        """The attempt failed: it stays counted, it is just no longer in flight."""
        self._inflight.pop(reservation, None)

    def record_success(self, key: str, reservation: int | None = None) -> None:
        """Release this attempt and reset the key's *completed* failures.

        Other attempts from the same key that are still being checked stay counted:
        resetting them too would let a burst queued behind a correct login evade the
        per-key limit.
        """
        mine = self._inflight.pop(reservation, None) if reservation is not None else None
        if mine is not None:
            with contextlib.suppress(ValueError):
                self._global.remove(mine[1])
        pending = [t for k, t in self._inflight.values() if k == key]
        if pending:
            self._hits[key] = pending
        else:
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
