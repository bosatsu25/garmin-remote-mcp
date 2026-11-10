"""Minimal single-owner OAuth 2.1 authorization server.

claude.ai custom connectors require OAuth (Dynamic Client Registration + PKCE),
so this module implements the MCP SDK's ``OAuthAuthorizationServerProvider``
for exactly one human: the owner, who proves identity by typing the owner
passphrase on a consent page served by this process.

Security properties (each is covered by tests, see docs/test-plan.md):
* Least privilege: every grant gets ``garmin:read``; ``garmin:write`` only when
  the owner ticks it on the consent page (and write tools are enabled at all).
* Tokens are stored only as SHA-256 hashes on disk (0600, atomic writes).
* Refresh tokens rotate on use; replaying a rotated refresh token revokes the
  whole token family (OAuth 2.1 / RFC 9700 refresh token reuse detection).
* Token families have an absolute lifetime, independent of rotation.
* Redirect URIs restricted to an allowlist of hosts; no userinfo/fragments.
* Password checks are scrypt-based, serialized (bounded memory) and rate limited.
* All unauthenticated in-memory structures are size-bounded.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import os
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .config import Settings
from .security import FailureRateLimiter, redirect_uri_allowed

logger = logging.getLogger(__name__)
audit = logging.getLogger("garmin_mcp.audit")

SCOPE_READ = "garmin:read"
SCOPE_WRITE = "garmin:write"
ALL_SCOPES = (SCOPE_READ, SCOPE_WRITE)
OWNER_SUBJECT = "owner"

AUTH_CODE_TTL = 300
PENDING_TTL = 600
MAX_PENDING = 100
MAX_CODES = 100
MAX_CLIENTS = 50
MAX_REDIRECT_URIS = 5
MAX_CLIENT_NAME = 100
MAX_PASSWORD_FIELD = 1024
REQUEST_ID_BYTES = 32
MAX_STATE_LENGTH = 512
ALLOWED_GRANT_TYPES = frozenset({"authorization_code", "refresh_token"})
ADMIN_SESSION_TTL = 300
MAX_ADMIN_SESSIONS = 5
CODE_CHALLENGE_RE = re.compile(r"[A-Za-z0-9._~-]{43,128}", re.ASCII)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class Pending:
    client_id: str
    client_name: str | None
    params: AuthorizationParams
    expires_at: float
    created_at: float


class OwnerOAuthProvider:
    """OAuthAuthorizationServerProvider for a single owner."""

    def __init__(self, settings: Settings, *, clock: Callable[[], float] = time.time):
        self.settings = settings
        self.clock = clock
        self._state_file: Path = settings.oauth_state_file
        self._lock = asyncio.Lock()
        self._verify_lock = asyncio.Lock()
        self._clients: dict[str, dict[str, Any]] = {}
        self._access: dict[str, dict[str, Any]] = {}
        self._refresh: dict[str, dict[str, Any]] = {}
        self._retired: dict[str, dict[str, Any]] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._pending: dict[str, Pending] = {}
        # Redeemed codes -> the token family they produced, kept until the code would
        # have expired, so a replayed code can revoke what it issued (ASVS V10.4.2).
        self._used_codes: dict[str, dict[str, Any]] = {}
        self._admin_sessions: dict[str, float] = {}
        self.limiter = FailureRateLimiter(clock=clock)
        self._load()

    # ------------------------------------------------------------------ storage
    def _load(self) -> None:
        if not self._state_file.exists():
            return
        try:
            data = json.loads(self._state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            # Fail closed: an unreadable state file means nobody is authorized.
            logger.error("Could not read OAuth state (%s); starting empty", type(e).__name__)  # noqa: TRY400
            return
        if not isinstance(data, dict):
            logger.error("OAuth state root is not an object; starting empty")
            return
        self._clients = dict(data.get("clients", {}))
        self._access = dict(data.get("access", {}))
        self._refresh = dict(data.get("refresh", {}))
        self._retired = dict(data.get("retired", {}))
        self._purge_expired()

    def _save(self) -> None:
        self._purge_expired()
        self._state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(
            {
                "clients": self._clients,
                "access": self._access,
                "refresh": self._refresh,
                "retired": self._retired,
            }
        )
        tmp = self._state_file.with_name(f".{self._state_file.name}.{secrets.token_hex(6)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            tmp.replace(self._state_file)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def _purge_expired(self) -> None:
        now = self.clock()

        def live(rec: dict[str, Any]) -> bool:
            exp = rec.get("expires_at")
            return isinstance(exp, (int, float)) and exp > now

        self._access = {k: v for k, v in self._access.items() if live(v)}
        self._refresh = {k: v for k, v in self._refresh.items() if live(v)}
        self._retired = {k: v for k, v in self._retired.items() if live(v)}
        self._codes = {k: v for k, v in self._codes.items() if v.expires_at > now}
        self._used_codes = {k: v for k, v in self._used_codes.items() if v["expires_at"] > now}
        self._admin_sessions = {k: v for k, v in self._admin_sessions.items() if v > now}
        self._pending = {k: v for k, v in self._pending.items() if v.expires_at > now}

    # ------------------------------------------------------------------ clients
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = self._clients.get(client_id)
        return OAuthClientInformationFull.model_validate(raw) if raw else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        if not uris or len(uris) > MAX_REDIRECT_URIS:
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description=f"between 1 and {MAX_REDIRECT_URIS} redirect_uris required",
            )
        for uri in uris:
            if not redirect_uri_allowed(uri, self.settings.allowed_redirect_hosts):
                audit.warning("register_rejected reason=redirect_uri")
                raise RegistrationError(
                    error="invalid_redirect_uri", error_description="redirect_uri not allowed"
                )
        if client_info.client_name and len(client_info.client_name) > MAX_CLIENT_NAME:
            raise RegistrationError(
                error="invalid_client_metadata", error_description="client_name too long"
            )
        grants = set(client_info.grant_types or [])
        if "authorization_code" not in grants or not grants <= ALLOWED_GRANT_TYPES:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="only authorization_code and refresh_token grants are offered",
            )
        if client_info.scope:
            requested = client_info.scope.split()
            if any(s not in ALL_SCOPES for s in requested):
                raise RegistrationError(
                    error="invalid_client_metadata", error_description="unknown scope"
                )
        async with self._lock:
            if len(self._clients) >= MAX_CLIENTS:
                live = {r["client_id"] for r in self._refresh.values()}
                victims = sorted(
                    (c for c in self._clients.values() if c["client_id"] not in live),
                    key=lambda c: c.get("client_id_issued_at") or 0,
                )
                if not victims:
                    raise RegistrationError(
                        error="invalid_client_metadata", error_description="too many clients"
                    )
                self._clients.pop(victims[0]["client_id"], None)
            self._clients[client_info.client_id] = client_info.model_dump(mode="json")
            self._save()
        audit.info("client_registered client_id=%s", client_info.client_id)

    # ---------------------------------------------------------------- authorize
    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if params.resource and not _same_resource(params.resource, self.settings.resource_url):
            raise AuthorizeError(error="invalid_target", error_description="unknown resource")
        if params.scopes and any(s not in ALL_SCOPES for s in params.scopes):
            raise AuthorizeError(error="invalid_scope", error_description="unknown scope")
        # RFC 7636 §4.2: 43-128 unreserved chars. Also bounds what we keep per request.
        if not CODE_CHALLENGE_RE.fullmatch(params.code_challenge or ""):
            raise AuthorizeError(error="invalid_request",
                                 error_description="malformed code_challenge")
        if params.state is not None and len(params.state) > MAX_STATE_LENGTH:
            raise AuthorizeError(error="invalid_request", error_description="state too long")
        now = self.clock()
        self._purge_expired()
        if len(self._pending) >= MAX_PENDING:
            oldest = min(self._pending, key=lambda k: self._pending[k].created_at)
            del self._pending[oldest]
        request_id = secrets.token_urlsafe(REQUEST_ID_BYTES)
        self._pending[request_id] = Pending(
            client_id=client.client_id,
            client_name=client.client_name,
            params=params,
            expires_at=now + PENDING_TTL,
            created_at=now,
        )
        return f"{self.settings.public_url}/oauth/login?request={request_id}"

    def _get_pending(self, request_id: str) -> Pending | None:
        p = self._pending.get(request_id)
        if p is None or p.expires_at <= self.clock():
            return None
        return p

    async def verify_owner(self, password: str) -> bool:
        if len(password) > MAX_PASSWORD_FIELD:
            return False
        # scrypt needs ~128 MiB: serialize so parallel requests cannot exhaust memory.
        async with self._verify_lock:
            return await anyio.to_thread.run_sync(self.settings.owner_secret.verify, password)

    def client_ip(self, request: Request) -> str:
        if self.settings.trust_fly_client_ip:
            ip = request.headers.get("fly-client-ip", "").strip()
            if ip and len(ip) <= 64:
                return ip
        return request.client.host if request.client else "unknown"

    # The consent page --------------------------------------------------------
    async def login_page(self, request: Request) -> Response:
        if request.method == "GET":
            pending = self._get_pending(request.query_params.get("request", ""))
            if not pending:
                return _page(_EXPIRED, status=400)
            return self._login_form(request.query_params["request"], pending)

        form = await request.form()
        request_id = str(form.get("request", ""))[:128]
        password = str(form.get("password", ""))
        want_write = form.get("allow_write") == "1"
        ip = self.client_ip(request)

        if self.limiter.is_locked(ip):
            audit.warning("login_rate_limited ip=%s", ip)
            return _page("試行回数が多すぎます。しばらく待ってから再試行してください。", status=429,
                         extra_headers={"Retry-After": "900"})

        pending = self._get_pending(request_id)
        if not pending:
            return _page(_EXPIRED, status=400)

        # Count the attempt *before* the slow check (no await between the lock test above
        # and this line), so concurrent submissions cannot exceed the limit.
        reservation = self.limiter.record_failure(ip)
        if not await self.verify_owner(password):
            audit.warning("login_failed ip=%s client_id=%s", ip, pending.client_id)
            return self._login_form(request_id, pending, error="パスワードが違います。",
                                    status=401)

        # The pending request may have been consumed by a concurrent submit.
        if self._pending.pop(request_id, None) is None:
            return _page(_EXPIRED, status=400)
        if pending.client_id not in self._clients:
            return _page(_EXPIRED, status=400)
        self.limiter.record_success(ip, reservation)

        scopes = [SCOPE_READ]
        if want_write and self.settings.allow_write:
            scopes.append(SCOPE_WRITE)

        if len(self._codes) >= MAX_CODES:
            self._purge_expired()
        code = secrets.token_urlsafe(32)
        params = pending.params
        self._codes[code] = AuthorizationCode(
            code=code,
            scopes=scopes,
            expires_at=self.clock() + AUTH_CODE_TTL,
            client_id=pending.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=self.settings.resource_url,
            subject=OWNER_SUBJECT,
        )
        audit.info("owner_approved client_id=%s scopes=%s ip=%s", pending.client_id,
                   ",".join(scopes), ip)
        target = construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)
        return RedirectResponse(target, status_code=302, headers=_NO_STORE)

    def _login_form(self, request_id: str, pending: Pending, error: str | None = None,
                    status: int = 200) -> HTMLResponse:
        return _login_form(request_id, pending, allow_write=self.settings.allow_write,
                           max_days=self.settings.token_family_max_age // 86400,
                           error=error, status=status)

    # ------------------------------------------------- owner: review / revoke
    def connections(self) -> list[dict[str, Any]]:
        """One entry per live grant (token family), newest first."""
        self._purge_expired()
        out = []
        for rec in self._refresh.values():
            client = self._clients.get(rec["client_id"], {})
            out.append({
                "family": rec["family"],
                "client_name": client.get("client_name") or rec["client_id"],
                "scopes": list(rec["scopes"]),
                "created_at": rec["family_created_at"],
                "expires_at": rec["family_created_at"] + self.settings.token_family_max_age,
            })
        return sorted(out, key=lambda c: c["created_at"], reverse=True)

    def _new_admin_session(self) -> str:
        self._purge_expired()
        while len(self._admin_sessions) >= MAX_ADMIN_SESSIONS:
            del self._admin_sessions[min(self._admin_sessions, key=self._admin_sessions.get)]
        token = secrets.token_urlsafe(32)
        self._admin_sessions[token_hash(token)] = self.clock() + ADMIN_SESSION_TTL
        return token

    def _admin_session_valid(self, token: str) -> bool:
        exp = self._admin_sessions.get(token_hash(token)) if token else None
        return exp is not None and exp > self.clock()

    async def connections_page(self, request: Request) -> Response:
        """GET: passphrase form. POST: verify the owner, then list live connections.

        No cookies: the short-lived session token lives only in the rendered page's hidden
        fields, so a cross-site request can never carry it (no CSRF surface).
        """
        if request.method == "GET":
            return _connections_login()
        form = await request.form()
        ip = self.client_ip(request)
        if self.limiter.is_locked(ip):
            audit.warning("login_rate_limited ip=%s", ip)
            return _page("試行回数が多すぎます。しばらく待ってから再試行してください。", status=429,
                         extra_headers={"Retry-After": "900"})
        reservation = self.limiter.record_failure(ip)
        if not await self.verify_owner(str(form.get("password", ""))):
            audit.warning("admin_login_failed ip=%s", ip)
            return _connections_login(error="パスワードが違います。", status=401)
        self.limiter.record_success(ip, reservation)
        audit.info("connections_viewed ip=%s", ip)
        return _connections_list(self.connections(), self._new_admin_session())

    async def connections_revoke(self, request: Request) -> Response:
        form = await request.form()
        session = str(form.get("session", ""))[:128]
        if not self._admin_session_valid(session):
            return _connections_login(error="セッションの有効期限が切れました。", status=401)
        target = str(form.get("family", ""))[:64]
        live = {c["family"] for c in self.connections()}
        victims = live if target == "*" else live & {target}
        async with self._lock:
            n = sum(self._revoke_family(f) for f in victims)
            self._save()
        audit.warning("connections_revoked families=%d tokens=%d ip=%s", len(victims), n,
                      self.client_ip(request))
        return _connections_list(self.connections(), session,
                                 notice=f"{len(victims)} 件の接続を取り消しました。")

    # -------------------------------------------------------------------- codes
    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if code is None:
            await self._revoke_if_code_reused(authorization_code)
            return None
        if code.client_id != client.client_id or code.expires_at <= self.clock():
            return None
        return code

    async def _revoke_if_code_reused(self, code: str) -> None:
        """A code that was already redeemed came back: it leaked. Revoke what it issued."""
        used = self._used_codes.get(token_hash(code))
        if used is None or used["expires_at"] <= self.clock():
            return
        async with self._lock:
            n = self._revoke_family(used["family"])
            self._save()
        audit.warning("authorization_code_reuse_detected client_id=%s tokens_revoked=%d",
                      used["client_id"], n)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        if self._codes.pop(authorization_code.code, None) is None:
            await self._revoke_if_code_reused(authorization_code.code)
            raise TokenError(error="invalid_grant", error_description="code already used")
        # Recorded synchronously with the pop above, so a concurrent second redemption
        # always finds it.
        family = {"id": secrets.token_hex(16), "created_at": self.clock()}
        self._used_codes[token_hash(authorization_code.code)] = {
            "family": family["id"],
            "client_id": client.client_id,
            "expires_at": authorization_code.expires_at,
        }
        async with self._lock:
            token = self._issue(client.client_id, authorization_code.scopes, family=family)
            self._save()
        audit.info("token_issued client_id=%s grant=authorization_code", client.client_id)
        return token

    # ------------------------------------------------------------------- tokens
    def _issue(self, client_id: str, scopes: list[str], family: dict[str, Any]) -> OAuthToken:
        now = self.clock()
        family_deadline = family["created_at"] + self.settings.token_family_max_age
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(48)
        a_hash, r_hash = token_hash(access), token_hash(refresh)
        access_exp = min(now + self.settings.access_token_ttl, family_deadline)
        refresh_exp = min(now + self.settings.refresh_token_ttl, family_deadline)
        self._access[a_hash] = {
            "client_id": client_id,
            "scopes": list(scopes),
            "expires_at": access_exp,
            "refresh": r_hash,
            "family": family["id"],
            "resource": self.settings.resource_url,
        }
        self._refresh[r_hash] = {
            "client_id": client_id,
            "scopes": list(scopes),
            "expires_at": refresh_exp,
            "access": a_hash,
            "family": family["id"],
            "family_created_at": family["created_at"],
            "resource": self.settings.resource_url,
        }
        return OAuthToken(
            access_token=access,
            token_type="Bearer",  # noqa: S106
            expires_in=max(1, int(access_exp - now)),
            scope=" ".join(scopes),
            refresh_token=refresh,
        )

    def _revoke_family(self, family_id: str) -> int:
        n = 0
        for store in (self._access, self._refresh, self._retired):
            for k in [k for k, v in store.items() if v.get("family") == family_id]:
                del store[k]
                n += 1
        return n

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        h = token_hash(refresh_token)
        rec = self._refresh.get(h)
        if rec is None:
            retired = self._retired.get(h)
            if retired is not None:
                # A rotated token came back: someone holds a stolen copy. Kill the family.
                async with self._lock:
                    n = self._revoke_family(retired["family"])
                    self._save()
                audit.warning("refresh_reuse_detected client_id=%s family_tokens_revoked=%d",
                              retired.get("client_id"), n)
            return None
        if rec["client_id"] != client.client_id or rec["expires_at"] <= self.clock():
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=rec["client_id"],
            scopes=rec["scopes"],
            expires_at=int(rec["expires_at"]),
            resource=rec.get("resource"),
            subject=OWNER_SUBJECT,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        async with self._lock:
            h = token_hash(refresh_token.token)
            rec = self._refresh.get(h)
            if rec is None or rec["client_id"] != client.client_id:
                raise TokenError(error="invalid_grant", error_description="refresh token revoked")
            # Scope may only be narrowed, never widened (RFC 6749 §6). Checked before
            # consuming the token so a bad request does not destroy the session.
            if scopes and any(s not in rec["scopes"] for s in scopes):
                raise TokenError(error="invalid_scope", error_description="cannot widen scope")
            del self._refresh[h]
            self._access.pop(rec.get("access", ""), None)
            self._retired[h] = {
                "family": rec["family"],
                "client_id": rec["client_id"],
                "expires_at": rec["family_created_at"] + self.settings.token_family_max_age,
            }
            granted = list(scopes) if scopes else list(rec["scopes"])
            family = {"id": rec["family"], "created_at": rec["family_created_at"]}
            token = self._issue(client.client_id, granted, family=family)
            self._save()
        audit.info("token_issued client_id=%s grant=refresh_token", client.client_id)
        return token

    async def load_access_token(self, token: str) -> AccessToken | None:
        if not token or len(token) > 512:
            return None
        rec = self._access.get(token_hash(token))
        if not rec or rec["expires_at"] <= self.clock():
            return None
        return AccessToken(
            token=token,
            client_id=rec["client_id"],
            scopes=rec["scopes"],
            expires_at=int(rec["expires_at"]),
            # The audience the token was issued for, as stored: the bearer middleware
            # refuses anything that is not this server (ASVS V10.3.1).
            resource=rec.get("resource"),
            subject=OWNER_SUBJECT,
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        h = token_hash(token.token)
        async with self._lock:
            rec = self._access.get(h) or self._refresh.get(h)
            if rec is not None:
                self._revoke_family(rec["family"])
                self._save()
        audit.info("token_revoked client_id=%s", token.client_id)


# ----------------------------------------------------------------------- helpers
_EXPIRED = "リクエストの有効期限が切れました。クライアントから接続し直してください。"


def _same_resource(a: str, b: str) -> bool:
    return a.rstrip("/").lower() == b.rstrip("/").lower()


_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}

_STYLE = """
body{font-family:system-ui,-apple-system,sans-serif;background:#f5f5f4;color:#1c1917;
margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}
main{background:#fff;border-radius:12px;padding:28px;max-width:420px;width:100%;
box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:1.2rem;margin:0 0 12px}p{line-height:1.6;font-size:.95rem}
code{background:#f5f5f4;padding:2px 6px;border-radius:4px;word-break:break-all}
input[type=password]{width:100%;box-sizing:border-box;padding:10px;font-size:1rem;
border:1px solid #d6d3d1;border-radius:8px;margin:8px 0 16px}
ul{list-style:none;padding:0}li{padding:12px 0;border-top:1px solid #d6d3d1;font-size:.9rem}
li form{margin-top:8px}
label.cb{display:flex;gap:8px;align-items:flex-start;margin:0 0 16px;font-size:.9rem}
button{width:100%;padding:10px;font-size:1rem;border:0;border-radius:8px;background:#1c1917;
color:#fff;cursor:pointer}.err{color:#b91c1c}
@media (prefers-color-scheme:dark){body{background:#1c1917;color:#f5f5f4}
main{background:#292524}code{background:#44403c}input[type=password]{background:#1c1917;
color:#f5f5f4;border-color:#57534e}button{background:#f5f5f4;color:#1c1917}.err{color:#f87171}}
"""


def _headers(form_target: str | None = None) -> dict[str, str]:
    form_action = "'self'"
    if form_target:
        form_action += f" {form_target}"
    return {
        **_NO_STORE,
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
            f"form-action {form_action}; frame-ancestors 'none'"
        ),
        "Referrer-Policy": "no-referrer",
    }


def _shell(body: str) -> str:
    return (
        "<!doctype html><html lang=ja><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<meta name=robots content=noindex>"
        f"<title>Garmin MCP</title><style>{_STYLE}</style></head><body><main>{body}"
        "</main></body></html>"
    )


def _page(message: str, status: int = 200,
          extra_headers: dict[str, str] | None = None) -> HTMLResponse:
    body = _shell(f"<h1>Garmin MCP</h1><p>{html.escape(message)}</p>")
    return HTMLResponse(body, status_code=status, headers={**_headers(), **(extra_headers or {})})


def _origin(uri: str) -> str:
    p = urlsplit(uri)
    return f"{p.scheme}://{p.netloc}"


def _login_form(request_id: str, pending: Pending, *, allow_write: bool, max_days: int,
                error: str | None = None, status: int = 200) -> HTMLResponse:
    redirect = str(pending.params.redirect_uri)
    client = html.escape(pending.client_name or pending.client_id)
    err = f"<p class=err role=alert>{html.escape(error)}</p>" if error else ""
    write_box = (
        "<label class=cb><input type=checkbox name=allow_write value=1>"
        "<span>ワークアウトの作成・削除（書き込み）も許可する</span></label>"
        if allow_write else ""
    )
    body = f"""<h1>Garmin MCP への接続を許可</h1>
<p><b>{client}</b> があなたの Garmin Connect データの<b>読み取り</b>を求めています。</p>
<p>許可後の戻り先: <code>{html.escape(_origin(redirect))}</code></p>
<p>この名前はクライアントの自己申告で、検証されていません。自分で開始した接続でなければ、
このページを閉じてください。</p>
<p>許可は最長 {max_days} 日間有効です。接続の確認と取り消しは
<code>/oauth/connections</code> で行えます。</p>
{err}
<form method=post action="/oauth/login">
<input type=hidden name=request value="{html.escape(request_id)}">
<label for=pw>オーナーパスワード</label>
<input id=pw type=password name=password autocomplete=current-password required autofocus
 maxlength={MAX_PASSWORD_FIELD}>
{write_box}
<button type=submit>許可する</button>
</form>"""
    return HTMLResponse(_shell(body), status_code=status, headers=_headers(_origin(redirect)))


def _connections_login(error: str | None = None, status: int = 200) -> HTMLResponse:
    err = f"<p class=err role=alert>{html.escape(error)}</p>" if error else ""
    body = f"""<h1>接続の管理</h1>
<p>このサーバーへのアクセスを許可している接続を確認し、取り消せます。</p>
{err}
<form method=post action="/oauth/connections">
<label for=pw>オーナーパスワード</label>
<input id=pw type=password name=password autocomplete=current-password required autofocus
 maxlength={MAX_PASSWORD_FIELD}>
<button type=submit>表示する</button>
</form>"""
    return HTMLResponse(_shell(body), status_code=status, headers=_headers())


def _fmt_day(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def _connections_list(conns: list[dict[str, Any]], session: str,
                      notice: str | None = None) -> HTMLResponse:
    sess = html.escape(session)
    note = f"<p role=status>{html.escape(notice)}</p>" if notice else ""
    rows = []
    for c in conns:
        access = "読み取り＋書き込み" if SCOPE_WRITE in c["scopes"] else "読み取りのみ"
        rows.append(f"""<li><b>{html.escape(str(c["client_name"]))}</b><br>
{access}・接続日 {_fmt_day(c["created_at"])}・期限 {_fmt_day(c["expires_at"])}（UTC）
<form method=post action="/oauth/connections/revoke">
<input type=hidden name=session value="{sess}">
<input type=hidden name=family value="{html.escape(str(c["family"]))}">
<button type=submit>この接続を取り消す</button></form></li>""")
    listing = f"<ul>{''.join(rows)}</ul>" if rows else "<p>有効な接続はありません。</p>"
    revoke_all = f"""<form method=post action="/oauth/connections/revoke">
<input type=hidden name=session value="{sess}"><input type=hidden name=family value="*">
<button type=submit>すべての接続を取り消す</button></form>""" if rows else ""
    body = f"<h1>接続の管理</h1>{note}{listing}{revoke_all}"
    return HTMLResponse(_shell(body), headers=_headers())
