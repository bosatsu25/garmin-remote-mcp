"""Component tests: OwnerOAuthProvider, driven directly with a fake clock.

State transition model of one grant (states in CAPS, events in lower case):

  (none) --authorize--> PENDING --approve--> CODE --exchange--> ACTIVE(gen 1)
  PENDING --ttl--> (gone)          CODE --ttl--> (gone)     CODE --exchange again--> rejected
  ACTIVE(gen n) --refresh--> ACTIVE(gen n+1)   [gen n refresh token -> RETIRED]
  ACTIVE --access ttl--> ACTIVE(access expired, refresh still valid)
  ACTIVE --refresh ttl / family max age--> EXPIRED
  RETIRED --replayed--> REVOKED (whole family, including the newest generation)
  ACTIVE --revoke(access|refresh)--> REVOKED

Tests below cover every state, every valid transition, and representative invalid ones
(full-transition coverage of the table in docs/test-plan.md). Time boundaries use 3-value BVA.
"""

import json
import os
import stat

import pytest
from mcp.server.auth.provider import (
    AuthorizationParams,
    AuthorizeError,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from garmin_mcp import oauth as o
from garmin_mcp.oauth import (
    AUTH_CODE_TTL,
    MAX_CLIENTS,
    MAX_PENDING,
    PENDING_TTL,
    SCOPE_READ,
    SCOPE_WRITE,
    OwnerOAuthProvider,
    token_hash,
)

from ..conftest import BASE, REDIRECT

pytestmark = pytest.mark.risk("R03", "R04")


def client(cid="c1", redirect=REDIRECT, name="Claude", scope=None, issued=0):
    return OAuthClientInformationFull(
        client_id=cid,
        redirect_uris=[AnyUrl(redirect)] if redirect else None,
        client_name=name,
        scope=scope,
        client_id_issued_at=issued,
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
    )


def params(scopes=None, resource=f"{BASE}/mcp"):
    return AuthorizationParams(
        state="s", scopes=scopes, code_challenge="x" * 43, redirect_uri=AnyUrl(REDIRECT),
        redirect_uri_provided_explicitly=True, resource=resource,
    )


@pytest.fixture
def provider(settings, clock):
    return OwnerOAuthProvider(settings, clock=clock)


async def grant(p: OwnerOAuthProvider, scopes=(SCOPE_READ,), cid="c1"):
    """Shortcut to ACTIVE(gen 1): register, issue a code, exchange it."""
    c = client(cid)
    if cid not in p._clients:
        await p.register_client(c)
    code = o.AuthorizationCode(
        code=f"code-{cid}-{len(p._codes)}", scopes=list(scopes), expires_at=p.clock() + 300,
        client_id=cid, code_challenge="x" * 43, redirect_uri=AnyUrl(REDIRECT),
        redirect_uri_provided_explicitly=True,
    )
    p._codes[code.code] = code
    return c, await p.exchange_authorization_code(c, code)


# ------------------------------------------------------------ PENDING state
async def test_authorize_creates_pending_with_unguessable_id(provider):
    url = await provider.authorize(client(), params())
    assert url.startswith(f"{BASE}/oauth/login?request=")
    rid = url.split("request=")[1]
    assert len(rid) >= 43                       # >= 256 bits
    assert provider._get_pending(rid) is not None


@pytest.mark.parametrize(("elapsed", "alive"),
                         [(PENDING_TTL - 1, True), (PENDING_TTL, False), (PENDING_TTL + 1, False)])
async def test_pending_ttl_boundary(provider, clock, elapsed, alive):
    rid = (await provider.authorize(client(), params())).split("request=")[1]
    clock.advance(elapsed)
    assert (provider._get_pending(rid) is not None) is alive


@pytest.mark.risk("R07")
@pytest.mark.parametrize(("n", "size"), [(MAX_PENDING - 1, MAX_PENDING - 1),
                                         (MAX_PENDING, MAX_PENDING), (MAX_PENDING + 1, MAX_PENDING)])
async def test_pending_is_bounded_and_evicts_oldest(provider, clock, n, size):
    ids = []
    for _ in range(n):
        clock.advance(0.001)
        ids.append((await provider.authorize(client(), params())).split("request=")[1])
    assert len(provider._pending) == size
    if n > MAX_PENDING:
        assert ids[0] not in provider._pending
        assert ids[-1] in provider._pending


@pytest.mark.parametrize("resource", [f"{BASE}/mcp", f"{BASE}/mcp/", f"{BASE.upper()}/MCP", None])
async def test_authorize_accepts_own_resource(provider, resource):
    await provider.authorize(client(), params(resource=resource))


@pytest.mark.parametrize("resource", ["https://other.example/mcp", f"{BASE}/admin",
                                      "https://garmin.example.com.evil/mcp"])
async def test_authorize_rejects_foreign_resource(provider, resource):
    with pytest.raises(AuthorizeError) as e:
        await provider.authorize(client(), params(resource=resource))
    assert e.value.error == "invalid_target"


@pytest.mark.risk("R05")
@pytest.mark.parametrize("scopes", [["garmin"], ["admin"], [SCOPE_READ, "garmin:admin"]])
async def test_authorize_rejects_unknown_scopes(provider, scopes):
    with pytest.raises(AuthorizeError) as e:
        await provider.authorize(client(), params(scopes=scopes))
    assert e.value.error == "invalid_scope"


# --------------------------------------------------------------- CODE state
@pytest.mark.parametrize(("elapsed", "valid"),
                         [(AUTH_CODE_TTL - 1, True), (AUTH_CODE_TTL, False), (AUTH_CODE_TTL + 1, False)])
async def test_code_ttl_boundary(provider, clock, elapsed, valid):
    c = client()
    await provider.register_client(c)
    provider._codes["k"] = o.AuthorizationCode(
        code="k", scopes=[SCOPE_READ], expires_at=clock() + AUTH_CODE_TTL, client_id="c1",
        code_challenge="x" * 43, redirect_uri=AnyUrl(REDIRECT),
        redirect_uri_provided_explicitly=True,
    )
    clock.advance(elapsed)
    assert (await provider.load_authorization_code(c, "k") is not None) is valid


async def test_code_is_single_use(provider):
    c, _ = await grant(provider)
    code = o.AuthorizationCode(
        code="once", scopes=[SCOPE_READ], expires_at=provider.clock() + 60, client_id="c1",
        code_challenge="x" * 43, redirect_uri=AnyUrl(REDIRECT),
        redirect_uri_provided_explicitly=True,
    )
    provider._codes["once"] = code
    await provider.exchange_authorization_code(c, code)
    with pytest.raises(TokenError) as e:
        await provider.exchange_authorization_code(c, code)
    assert e.value.error == "invalid_grant"


async def test_code_bound_to_client(provider):
    await grant(provider)
    provider._codes["k"] = o.AuthorizationCode(
        code="k", scopes=[SCOPE_READ], expires_at=provider.clock() + 60, client_id="c1",
        code_challenge="x" * 43, redirect_uri=AnyUrl(REDIRECT),
        redirect_uri_provided_explicitly=True,
    )
    assert await provider.load_authorization_code(client("other"), "k") is None


# ------------------------------------------------------------- ACTIVE state
async def test_exchange_issues_bearer_tokens_with_granted_scopes(provider):
    _, tok = await grant(provider, scopes=(SCOPE_READ, SCOPE_WRITE))
    assert tok.token_type == "Bearer"
    assert tok.scope == f"{SCOPE_READ} {SCOPE_WRITE}"
    at = await provider.load_access_token(tok.access_token)
    assert at.scopes == [SCOPE_READ, SCOPE_WRITE]
    assert at.resource == f"{BASE}/mcp"
    assert at.subject == "owner"


@pytest.mark.parametrize(("elapsed", "valid"), [(3599, True), (3600, False), (3601, False)])
async def test_access_token_ttl_boundary(provider, clock, elapsed, valid):
    _, tok = await grant(provider)
    clock.advance(elapsed)
    assert (await provider.load_access_token(tok.access_token) is not None) is valid


@pytest.mark.parametrize("bad", ["", "x", "a" * 513, "Bearer abc"])
async def test_unknown_or_malformed_access_token(provider, bad):
    await grant(provider)
    assert await provider.load_access_token(bad) is None


async def test_refresh_rotates_and_old_access_dies(provider):
    c, t1 = await grant(provider)
    rt = await provider.load_refresh_token(c, t1.refresh_token)
    t2 = await provider.exchange_refresh_token(c, rt, [])
    assert t2.refresh_token != t1.refresh_token
    assert t2.access_token != t1.access_token
    assert await provider.load_access_token(t1.access_token) is None
    assert await provider.load_access_token(t2.access_token) is not None


@pytest.mark.parametrize(("elapsed", "valid"),
                         [(30 * 86400 - 1, True), (30 * 86400, False), (30 * 86400 + 1, False)])
async def test_refresh_token_ttl_boundary(provider, clock, elapsed, valid):
    c, t = await grant(provider)
    clock.advance(elapsed)
    assert (await provider.load_refresh_token(c, t.refresh_token) is not None) is valid


async def test_family_max_age_caps_rotation(provider, clock):
    """Rotating forever must not extend access beyond the family's absolute lifetime."""
    max_age = provider.settings.token_family_max_age
    c, t = await grant(provider)
    start = clock()
    while clock() - start < max_age - 20 * 86400:
        clock.advance(20 * 86400)
        rt = await provider.load_refresh_token(c, t.refresh_token)
        assert rt is not None
        t = await provider.exchange_refresh_token(c, rt, [])
    rt = await provider.load_refresh_token(c, t.refresh_token)
    assert rt.expires_at <= start + max_age
    clock.advance(start + max_age - clock())
    assert await provider.load_refresh_token(c, t.refresh_token) is None
    assert await provider.load_access_token(t.access_token) is None


@pytest.mark.risk("R05")
async def test_refresh_can_narrow_scope(provider):
    c, t = await grant(provider, scopes=(SCOPE_READ, SCOPE_WRITE))
    rt = await provider.load_refresh_token(c, t.refresh_token)
    t2 = await provider.exchange_refresh_token(c, rt, [SCOPE_READ])
    assert (await provider.load_access_token(t2.access_token)).scopes == [SCOPE_READ]


@pytest.mark.risk("R05")
async def test_refresh_cannot_widen_scope_and_keeps_token(provider):
    c, t = await grant(provider, scopes=(SCOPE_READ,))
    rt = await provider.load_refresh_token(c, t.refresh_token)
    with pytest.raises(TokenError) as e:
        await provider.exchange_refresh_token(c, rt, [SCOPE_READ, SCOPE_WRITE])
    assert e.value.error == "invalid_scope"
    # rejected request must not have consumed the session
    assert await provider.load_refresh_token(c, t.refresh_token) is not None


async def test_refresh_bound_to_client(provider):
    _, t = await grant(provider)
    await provider.register_client(client("c2"))
    assert await provider.load_refresh_token(client("c2"), t.refresh_token) is None


async def test_exchange_refresh_rejects_foreign_client_record(provider):
    c, t = await grant(provider)
    rt = await provider.load_refresh_token(c, t.refresh_token)
    with pytest.raises(TokenError):
        await provider.exchange_refresh_token(client("c2"), rt, [])


# ----------------------------------------------------- RETIRED -> REVOKED
async def test_refresh_reuse_revokes_entire_family(provider):
    c, t1 = await grant(provider)
    t2 = await provider.exchange_refresh_token(
        c, await provider.load_refresh_token(c, t1.refresh_token), [])
    # attacker replays the rotated (RETIRED) token
    assert await provider.load_refresh_token(c, t1.refresh_token) is None
    # ... which kills the legitimate newest generation too
    assert await provider.load_access_token(t2.access_token) is None
    assert await provider.load_refresh_token(c, t2.refresh_token) is None


async def test_reuse_detection_does_not_touch_other_families(provider):
    c, a1 = await grant(provider)
    _, b1 = await grant(provider)
    await provider.exchange_refresh_token(c, await provider.load_refresh_token(c, a1.refresh_token), [])
    await provider.load_refresh_token(c, a1.refresh_token)          # replay family A
    assert await provider.load_access_token(b1.access_token) is not None


async def test_concurrent_double_exchange_only_one_wins(provider):
    import asyncio

    c, t = await grant(provider)
    rt = await provider.load_refresh_token(c, t.refresh_token)
    results = await asyncio.gather(
        provider.exchange_refresh_token(c, rt, []),
        provider.exchange_refresh_token(c, rt, []),
        return_exceptions=True,
    )
    assert sum(isinstance(r, TokenError) for r in results) == 1


# ---------------------------------------------------------- revoke
@pytest.mark.parametrize("which", ["access", "refresh"])
async def test_revoke_either_token_kills_both(provider, which):
    c, t = await grant(provider)
    target = (await provider.load_access_token(t.access_token) if which == "access"
              else await provider.load_refresh_token(c, t.refresh_token))
    await provider.revoke_token(target)
    assert await provider.load_access_token(t.access_token) is None
    assert await provider.load_refresh_token(c, t.refresh_token) is None


async def test_revoke_unknown_token_is_noop(provider):
    _, t = await grant(provider)
    await provider.revoke_token(o.AccessToken(token="nope", client_id="c1", scopes=[]))
    assert await provider.load_access_token(t.access_token) is not None


# ---------------------------------------------------- client registration
@pytest.mark.risk("R02", "R07")
@pytest.mark.parametrize(("count", "ok"), [(0, False), (1, True), (5, True), (6, False)])
async def test_redirect_uri_count_boundary(provider, count, ok):
    c = client()
    c.redirect_uris = [AnyUrl(f"{REDIRECT}?n={i}") for i in range(count)] or None
    if ok:
        await provider.register_client(c)
    else:
        with pytest.raises(RegistrationError):
            await provider.register_client(c)


@pytest.mark.risk("R07", "R08")
@pytest.mark.parametrize(("length", "ok"), [(99, True), (100, True), (101, False)])
async def test_client_name_length_boundary(provider, length, ok):
    c = client(name="n" * length)
    if ok:
        await provider.register_client(c)
    else:
        with pytest.raises(RegistrationError):
            await provider.register_client(c)


@pytest.mark.risk("R05")
@pytest.mark.parametrize(("scope", "ok"), [(None, True), (SCOPE_READ, True),
                                           (f"{SCOPE_READ} {SCOPE_WRITE}", True),
                                           ("garmin:admin", False), ("openid", False)])
async def test_client_scope_registration(provider, scope, ok):
    if ok:
        await provider.register_client(client(scope=scope))
    else:
        with pytest.raises(RegistrationError):
            await provider.register_client(client(scope=scope))


@pytest.mark.risk("R02")
async def test_registration_rejects_foreign_redirect(provider):
    with pytest.raises(RegistrationError) as e:
        await provider.register_client(client(redirect="https://evil.example/cb"))
    assert e.value.error == "invalid_redirect_uri"


@pytest.mark.risk("R07")
@pytest.mark.parametrize(("n", "size"), [(MAX_CLIENTS - 1, MAX_CLIENTS - 1),
                                         (MAX_CLIENTS, MAX_CLIENTS), (MAX_CLIENTS + 1, MAX_CLIENTS)])
async def test_client_cap_boundary(provider, n, size):
    for i in range(n):
        await provider.register_client(client(f"c{i}", issued=i))
    assert len(provider._clients) == size


@pytest.mark.risk("R07")
async def test_client_eviction_spares_clients_with_live_tokens(provider):
    await grant(provider, cid="owner-claude")          # oldest, but has live tokens
    provider._clients["owner-claude"]["client_id_issued_at"] = -1
    for i in range(MAX_CLIENTS):
        await provider.register_client(client(f"spam{i}", issued=i))
    assert "owner-claude" in provider._clients


@pytest.mark.risk("R07")
async def test_client_cap_with_all_live_rejects(provider):
    for i in range(MAX_CLIENTS):
        await grant(provider, cid=f"live{i}")
    with pytest.raises(RegistrationError):
        await provider.register_client(client("one-too-many"))


# ------------------------------------------------------------- persistence
@pytest.mark.risk("R06", "R13")
async def test_state_file_holds_only_hashes_with_0600(provider, settings):
    _, t = await grant(provider)
    path = settings.oauth_state_file
    text = path.read_text()
    assert t.access_token not in text
    assert t.refresh_token not in text
    assert token_hash(t.access_token) in text
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


@pytest.mark.risk("R13")
async def test_state_survives_restart(provider, settings, clock):
    c, t = await grant(provider)
    again = OwnerOAuthProvider(settings, clock=clock)
    assert await again.load_access_token(t.access_token) is not None
    assert await again.load_refresh_token(c, t.refresh_token) is not None


@pytest.mark.risk("R13")
async def test_reuse_detection_survives_restart(provider, settings, clock):
    c, t1 = await grant(provider)
    t2 = await provider.exchange_refresh_token(c, await provider.load_refresh_token(c, t1.refresh_token), [])
    again = OwnerOAuthProvider(settings, clock=clock)
    assert await again.load_refresh_token(c, t1.refresh_token) is None
    assert await again.load_access_token(t2.access_token) is None


@pytest.mark.risk("R13")
@pytest.mark.parametrize("content", ["{not json", "[]", '"str"', "null", ""])
async def test_corrupt_state_fails_closed(settings, clock, content):
    settings.oauth_state_file.parent.mkdir(parents=True, exist_ok=True)
    settings.oauth_state_file.write_text(content)
    p = OwnerOAuthProvider(settings, clock=clock)
    assert p._access == {}
    assert p._clients == {}


@pytest.mark.risk("R13")
async def test_expired_records_are_purged_on_load(provider, settings, clock):
    await grant(provider)
    clock.advance(provider.settings.token_family_max_age + 1)
    again = OwnerOAuthProvider(settings, clock=clock)
    assert again._access == {}
    assert again._refresh == {}
    assert again._retired == {}


@pytest.mark.risk("R13")
async def test_records_with_garbage_expiry_are_dropped(settings, clock):
    settings.oauth_state_file.parent.mkdir(parents=True, exist_ok=True)
    settings.oauth_state_file.write_text(json.dumps({
        "access": {"h": {"client_id": "c", "scopes": [SCOPE_WRITE], "expires_at": "never"}},
        "refresh": {"h2": {"client_id": "c", "scopes": [], "expires_at": None}},
    }))
    p = OwnerOAuthProvider(settings, clock=clock)
    assert p._access == {}
    assert p._refresh == {}
