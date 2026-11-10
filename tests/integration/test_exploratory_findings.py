"""Confirmation tests (JSTQB FL §2.2.3) for defects found in the exploratory session
(§4.4.2) run against the real container image. Charter and notes: docs/test-plan.md §6."""

import asyncio
from collections import Counter

import pytest

from garmin_mcp.oauth import MAX_STATE_LENGTH

from ..conftest import PASSWORD, REDIRECT, pkce


# X1 ---------------------------------------------------------------------------------
@pytest.mark.risk("R01")
@pytest.mark.parametrize("n", [6, 40])
async def test_concurrent_wrong_passwords_cannot_exceed_limit(http, n):
    """Was: N parallel submissions all passed the lock check before any failure was
    recorded, giving N guesses instead of 5."""
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    rid = http.request_id(auth)
    rs = await asyncio.gather(*[http.consent(rid, f"wrong-{i}") for i in range(n)])
    counts = Counter(r.status_code for r in rs)
    assert counts[401] == 5
    assert counts[429] == n - 5


@pytest.mark.risk("R01")
async def test_only_five_password_hashes_are_computed_under_flood(settings, make_app):
    from ..conftest import OAuthDriver, asgi_client

    app = make_app(settings)
    calls = 0
    real = app.provider.verify_owner

    async def counting(pw):
        nonlocal calls
        calls += 1
        return await real(pw)

    app.provider.verify_owner = counting
    async with asgi_client(app) as c:
        d = OAuthDriver(c)
        auth, _ = await d.start(await d.client_id())
        rid = d.request_id(auth)
        await asyncio.gather(*[d.consent(rid, "nope") for _ in range(30)])
    assert calls == 5            # scrypt work is bounded too, not just the responses


@pytest.mark.risk("R01")
async def test_successful_login_does_not_consume_the_global_budget(settings, make_app):
    from ..conftest import OAuthDriver, asgi_client

    app = make_app(settings)
    async with asgi_client(app) as c:
        d = OAuthDriver(c)
        for _ in range(3):
            await d.connect()
    assert app.provider.limiter._global == []
    assert app.provider.limiter._hits == {}


@pytest.mark.risk("R01")
async def test_right_password_among_concurrent_wrong_ones_still_single_code(http):
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    rid = http.request_id(auth)
    rs = await asyncio.gather(http.consent(rid, "bad-1"), http.consent(rid, PASSWORD),
                              http.consent(rid, "bad-2"))
    assert sorted(r.status_code for r in rs).count(302) == 1


# X2 ---------------------------------------------------------------------------------
@pytest.mark.risk("R14")
@pytest.mark.parametrize(("method", "path"), [("POST", "/mcp/"), ("GET", "/oauth/login/"),
                                              ("GET", "/healthz/"), ("POST", "/token/"),
                                              ("POST", "/mcp%2f")])
async def test_no_host_header_controlled_redirects(http, method, path):
    """Was: Starlette's trailing-slash redirect answered 307 with
    `Location: http://<Host header>/mcp`."""
    r = await http.c.request(method, path, headers={"Host": "evil.example"})
    assert r.status_code not in (301, 302, 307, 308)
    assert "location" not in r.headers


# X3 ---------------------------------------------------------------------------------
@pytest.mark.risk("R02", "R07")
@pytest.mark.parametrize(("challenge", "ok"), [
    ("a" * 42, False), ("a" * 43, True), ("a" * 44, True),
    ("a" * 127, True), ("a" * 128, True), ("a" * 129, False),
    ("a" * 20000, False),
    ("a" * 42 + "!", False), ("a" * 42 + " ", False), ("a" * 43 + "\n", False),
    ("A-Za-z0-9._~" + "b" * 31, True),
])
async def test_code_challenge_format_boundaries(http, challenge, ok):
    cid = await http.client_id()
    r, _ = await http.start(cid, challenge=challenge)
    loc = r.headers.get("location", "")
    assert ("/oauth/login?request=" in loc) is ok
    if not ok:
        assert r.status_code in (302, 400)
        assert "error=invalid_request" in loc or r.status_code == 400


@pytest.mark.risk("R07")
@pytest.mark.parametrize(("length", "ok"), [(MAX_STATE_LENGTH - 1, True),
                                            (MAX_STATE_LENGTH, True),
                                            (MAX_STATE_LENGTH + 1, False)])
async def test_state_length_boundary(http, length, ok):
    cid = await http.client_id()
    _, ch = pkce()
    r = await http.c.get("/authorize", params={
        "response_type": "code", "client_id": cid, "redirect_uri": REDIRECT,
        "code_challenge": ch, "code_challenge_method": "S256", "state": "s" * length})
    assert ("/oauth/login?request=" in r.headers.get("location", "")) is ok


# X4: characterize that only two grant types exist, whatever a client registered ----
@pytest.mark.risk("R04")
@pytest.mark.parametrize("grant", ["client_credentials", "password", "implicit",
                                   "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                   "urn:ietf:params:oauth:grant-type:device_code"])
async def test_unsupported_grant_types_never_issue_tokens(http, grant):
    r = await http.register(token_endpoint_auth_method="client_secret_post",
                            grant_types=["authorization_code", "refresh_token"])
    c = r.json()
    t = await http.c.post("/token", data={
        "grant_type": grant, "client_id": c["client_id"],
        "client_secret": c.get("client_secret", ""), "username": "owner", "password": PASSWORD,
        "assertion": "x", "scope": "garmin:read garmin:write"})
    assert t.status_code >= 400
    assert "access_token" not in t.text
