"""Minimal single-owner OAuth 2.1 authorization server.

claude.ai custom connectors require OAuth (Dynamic Client Registration + PKCE),
so this module implements the MCP SDK's ``OAuthAuthorizationServerProvider``
for exactly one human: the owner, who proves identity by typing
``OWNER_PASSWORD`` on a consent page served by this same process.

Security notes:
* Tokens are stored only as SHA-256 hashes on disk.
* Redirect URIs are restricted to an allowlist of hosts (claude.ai etc.), so a
  third party cannot register a client that ships codes to their own server.
* Failed password attempts are rate limited per client IP and globally.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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

logger = logging.getLogger(__name__)

SCOPE = "garmin"
OWNER_SUBJECT = "owner"
AUTH_CODE_TTL = 300
PENDING_TTL = 600
MAX_CLIENTS = 50

# Rate limiting for the password form.
PER_IP_MAX_FAILURES = 5
PER_IP_WINDOW = 15 * 60
GLOBAL_MAX_FAILURES = 30
GLOBAL_WINDOW = 60 * 60


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> float:
    return time.time()


@dataclass
class _Pending:
    client_id: str
    client_name: str | None
    params: AuthorizationParams
    expires_at: float


class OwnerOAuthProvider:
    """OAuthAuthorizationServerProvider for a single owner."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._state_file: Path = settings.oauth_state_file
        self._lock = asyncio.Lock()
        self._clients: dict[str, dict[str, Any]] = {}
        self._access: dict[str, dict[str, Any]] = {}
        self._refresh: dict[str, dict[str, Any]] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._pending: dict[str, _Pending] = {}
        self._failures: dict[str, list[float]] = {}
        self._load()

    # ------------------------------------------------------------------ storage
    def _load(self) -> None:
        if not self._state_file.exists():
            return
        try:
            data = json.loads(self._state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            logger.error("Could not read OAuth state (%s); starting empty", e)
            return
        self._clients = data.get("clients", {})
        self._access = data.get("access", {})
        self._refresh = data.get("refresh", {})
        self._purge_expired()

    def _save(self) -> None:
        self._purge_expired()
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {"clients": self._clients, "access": self._access, "refresh": self._refresh}
        )
        tmp = self._state_file.with_name(f".{self._state_file.name}.{secrets.token_hex(6)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        tmp.replace(self._state_file)

    def _purge_expired(self) -> None:
        now = _now()
        self._access = {
            k: v for k, v in self._access.items() if not v.get("expires_at") or v["expires_at"] > now
        }
        self._refresh = {
            k: v
            for k, v in self._refresh.items()
            if not v.get("expires_at") or v["expires_at"] > now
        }
        self._codes = {k: v for k, v in self._codes.items() if v.expires_at > now}
        self._pending = {k: v for k, v in self._pending.items() if v.expires_at > now}

    # ------------------------------------------------------------------ clients
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = self._clients.get(client_id)
        return OAuthClientInformationFull.model_validate(raw) if raw else None

    def _redirect_allowed(self, uri: str) -> bool:
        parsed = urlparse(uri)
        host = (parsed.hostname or "").lower()
        if host not in self.settings.allowed_redirect_hosts:
            return False
        if parsed.scheme == "https":
            return True
        # Plain http only for loopback callbacks (Claude Desktop / Claude Code).
        return parsed.scheme == "http" and host in {"localhost", "127.0.0.1"}

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            if not self._redirect_allowed(str(uri)):
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description=f"redirect_uri host not allowed: {uri}",
                )
        async with self._lock:
            if len(self._clients) >= MAX_CLIENTS:
                # Evict the oldest registration that holds no live refresh token.
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

    # ---------------------------------------------------------------- authorize
    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if params.resource and not _same_resource(params.resource, self.settings.resource_url):
            raise AuthorizeError(error="invalid_target", error_description="unknown resource")
        if params.scopes and any(s != SCOPE for s in params.scopes):
            raise AuthorizeError(error="invalid_scope", error_description=f"only '{SCOPE}'")
        request_id = secrets.token_urlsafe(32)
        self._pending[request_id] = _Pending(
            client_id=client.client_id,
            client_name=client.client_name,
            params=params,
            expires_at=_now() + PENDING_TTL,
        )
        return f"{self.settings.public_url}/oauth/login?request={request_id}"

    # The consent page --------------------------------------------------------
    async def login_page(self, request: Request) -> Response:
        if request.method == "GET":
            request_id = request.query_params.get("request", "")
            pending = self._pending.get(request_id)
            if not pending or pending.expires_at < _now():
                return _page("リクエストの有効期限が切れました。クライアントから接続し直してください。",
                             status=400)
            return _login_form(request_id, pending)

        form = await request.form()
        request_id = str(form.get("request", ""))
        password = str(form.get("password", ""))
        ip = _client_ip(request)

        if self._rate_limited(ip):
            return _page("試行回数が多すぎます。しばらく待ってから再試行してください。", status=429)

        pending = self._pending.get(request_id)
        if not pending or pending.expires_at < _now():
            return _page("リクエストの有効期限が切れました。クライアントから接続し直してください。",
                         status=400)

        if not hmac.compare_digest(password.encode(), self.settings.owner_password.encode()):
            self._record_failure(ip)
            logger.warning("Failed owner login from %s", ip)
            return _login_form(request_id, pending, error="パスワードが違います。", status=401)

        self._pending.pop(request_id, None)
        code = secrets.token_urlsafe(32)
        params = pending.params
        self._codes[code] = AuthorizationCode(
            code=code,
            scopes=[SCOPE],
            expires_at=_now() + AUTH_CODE_TTL,
            client_id=pending.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=self.settings.resource_url,
            subject=OWNER_SUBJECT,
        )
        logger.info("Owner approved client %s", pending.client_id)
        target = construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)
        return RedirectResponse(target, status_code=302)

    def _rate_limited(self, ip: str) -> bool:
        now = _now()
        ip_hits = [t for t in self._failures.get(ip, []) if t > now - PER_IP_WINDOW]
        all_hits = [t for t in self._failures.get("*", []) if t > now - GLOBAL_WINDOW]
        self._failures[ip] = ip_hits
        self._failures["*"] = all_hits
        return len(ip_hits) >= PER_IP_MAX_FAILURES or len(all_hits) >= GLOBAL_MAX_FAILURES

    def _record_failure(self, ip: str) -> None:
        now = _now()
        self._failures.setdefault(ip, []).append(now)
        self._failures.setdefault("*", []).append(now)

    # -------------------------------------------------------------------- codes
    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if not code or code.client_id != client.client_id or code.expires_at < _now():
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        if self._codes.pop(authorization_code.code, None) is None:
            raise TokenError(error="invalid_grant", error_description="code already used")
        async with self._lock:
            token = self._issue(client.client_id, authorization_code.scopes)
            self._save()
        return token

    # ------------------------------------------------------------------- tokens
    def _issue(self, client_id: str, scopes: list[str]) -> OAuthToken:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(48)
        now = int(_now())
        a_hash, r_hash = _hash(access), _hash(refresh)
        self._access[a_hash] = {
            "client_id": client_id,
            "scopes": scopes,
            "expires_at": now + self.settings.access_token_ttl,
            "refresh": r_hash,
        }
        self._refresh[r_hash] = {
            "client_id": client_id,
            "scopes": scopes,
            "expires_at": now + self.settings.refresh_token_ttl,
            "access": a_hash,
        }
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=self.settings.access_token_ttl,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        rec = self._refresh.get(_hash(refresh_token))
        if not rec or rec["client_id"] != client.client_id:
            return None
        if rec.get("expires_at") and rec["expires_at"] < _now():
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=rec["client_id"],
            scopes=rec["scopes"],
            expires_at=rec.get("expires_at"),
            resource=self.settings.resource_url,
            subject=OWNER_SUBJECT,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        async with self._lock:
            rec = self._refresh.pop(_hash(refresh_token.token), None)
            if rec is None:
                raise TokenError(error="invalid_grant", error_description="refresh token revoked")
            self._access.pop(rec.get("access", ""), None)
            granted = [s for s in (scopes or rec["scopes"]) if s in rec["scopes"]] or rec["scopes"]
            token = self._issue(client.client_id, granted)
            self._save()
        return token

    async def load_access_token(self, token: str) -> AccessToken | None:
        rec = self._access.get(_hash(token))
        if not rec:
            return None
        if rec.get("expires_at") and rec["expires_at"] < _now():
            return None
        return AccessToken(
            token=token,
            client_id=rec["client_id"],
            scopes=rec["scopes"],
            expires_at=rec.get("expires_at"),
            resource=self.settings.resource_url,
            subject=OWNER_SUBJECT,
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        h = _hash(token.token)
        async with self._lock:
            a = self._access.pop(h, None)
            r = self._refresh.pop(h, None)
            if a:
                self._refresh.pop(a.get("refresh", ""), None)
            if r:
                self._access.pop(r.get("access", ""), None)
            self._save()


# ----------------------------------------------------------------------- helpers
def _same_resource(a: str, b: str) -> bool:
    return a.rstrip("/").lower() == b.rstrip("/").lower()


def _client_ip(request: Request) -> str:
    # Fly.io sets Fly-Client-IP; fall back to the socket peer.
    return (
        request.headers.get("fly-client-ip")
        or (request.client.host if request.client else "unknown")
    )


_STYLE = """
body{font-family:system-ui,-apple-system,sans-serif;background:#f5f5f4;color:#1c1917;
margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}
main{background:#fff;border-radius:12px;padding:28px;max-width:420px;width:100%;
box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:1.2rem;margin:0 0 12px}p{line-height:1.6;font-size:.95rem}
code{background:#f5f5f4;padding:2px 6px;border-radius:4px;word-break:break-all}
input[type=password]{width:100%;box-sizing:border-box;padding:10px;font-size:1rem;
border:1px solid #d6d3d1;border-radius:8px;margin:8px 0 16px}
button{width:100%;padding:10px;font-size:1rem;border:0;border-radius:8px;background:#1c1917;
color:#fff;cursor:pointer}.err{color:#b91c1c}
@media (prefers-color-scheme:dark){body{background:#1c1917;color:#f5f5f4}
main{background:#292524}code{background:#44403c}input[type=password]{background:#1c1917;
color:#f5f5f4;border-color:#57534e}button{background:#f5f5f4;color:#1c1917}.err{color:#f87171}}
"""


def _page(message: str, status: int = 200) -> HTMLResponse:
    body = (
        f"<!doctype html><html lang=ja><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>Garmin MCP</title><style>{_STYLE}</style></head>"
        f"<body><main><h1>Garmin MCP</h1><p>{html.escape(message)}</p></main></body></html>"
    )
    return HTMLResponse(body, status_code=status, headers=_SECURITY_HEADERS)


def _login_form(
    request_id: str, pending: _Pending, error: str | None = None, status: int = 200
) -> HTMLResponse:
    redirect_host = urlparse(str(pending.params.redirect_uri)).netloc
    client = html.escape(pending.client_name or pending.client_id)
    err = f"<p class=err>{html.escape(error)}</p>" if error else ""
    body = f"""<!doctype html><html lang=ja><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Garmin MCP</title><style>{_STYLE}</style></head><body><main>
<h1>Garmin MCP への接続を許可</h1>
<p><b>{client}</b> があなたの Garmin Connect データへのアクセスを求めています。</p>
<p>許可後の戻り先: <code>{html.escape(redirect_host)}</code></p>
<p>自分で開始した接続でなければ、このページを閉じてください。</p>
{err}
<form method=post action="/oauth/login">
<input type=hidden name=request value="{html.escape(request_id)}">
<label for=pw>オーナーパスワード</label>
<input id=pw type=password name=password autocomplete=current-password required autofocus>
<button type=submit>許可する</button>
</form></main></body></html>"""
    return HTMLResponse(body, status_code=status, headers=_SECURITY_HEADERS)


_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
    "form-action 'self' https: http://localhost:* http://127.0.0.1:*; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
