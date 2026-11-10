"""Checklist-based tests (JSTQB FL §4.4.3) for OWASP ASVS 5.0.0 chapter V10 (OAuth and
OIDC), the chapter that describes what this server is. Each test names its requirement;
the full mapping, including not-applicable items, is tests/asvs_v10.py."""

import asyncio
import logging
from urllib.parse import parse_qs, urlsplit

import pytest

from garmin_mcp.oauth import ADMIN_SESSION_TTL, AUTH_CODE_TTL, MAX_ADMIN_SESSIONS, token_hash

from ..conftest import BASE, PASSWORD, REDIRECT, OAuthDriver, asgi_client, pkce


async def issue_code(d: OAuthDriver, **register_extra):
    r = await d.register(**register_extra)
    assert r.status_code == 201, r.text
    client = r.json()
    auth, verifier = await d.start(client["client_id"])
    ok = await d.consent(d.request_id(auth))
    code = parse_qs(urlsplit(ok.headers["location"]).query)["code"][0]
    return client, code, verifier


# ---------------------------------------------------------------- V10.3.1 audience
@pytest.mark.risk("R04")
@pytest.mark.parametrize("stored", ["https://other.example/mcp", f"{BASE}/admin", "", None,
                                    "MISSING"])
async def test_v10_3_1_token_for_another_audience_is_refused(settings, make_app, stored):
    app = make_app(settings)
    async with asgi_client(app) as c:
        d = OAuthDriver(c)
        conn = await d.connect()
        assert (await d.rpc(conn.access_token, "tools/list")).status_code == 200
        rec = app.provider._access[token_hash(conn.access_token)]
        if stored == "MISSING":
            del rec["resource"]
        else:
            rec["resource"] = stored
        assert (await d.rpc(conn.access_token, "tools/list")).status_code == 401


@pytest.mark.risk("R04")
async def test_v10_3_1_audience_is_stored_per_token(settings, make_app):
    app = make_app(settings)
    async with asgi_client(app) as c:
        conn = await OAuthDriver(c).connect()
        assert app.provider._access[token_hash(conn.access_token)]["resource"] == f"{BASE}/mcp"
        assert app.provider._refresh[token_hash(conn.refresh_token)]["resource"] == f"{BASE}/mcp"


# ------------------------------------------------- V10.4.2 code reuse revokes tokens
@pytest.mark.risk("R02", "R03")
async def test_v10_4_2_replayed_code_revokes_tokens_it_issued(http):
    client, code, verifier = await issue_code(http)
    cid = client["client_id"]
    tok = (await http.exchange(cid, code, verifier)).json()
    assert (await http.rpc(tok["access_token"], "tools/list")).status_code == 200
    replay = await http.exchange(cid, code, verifier)
    assert replay.status_code == 400
    assert (await http.rpc(tok["access_token"], "tools/list")).status_code == 401
    assert (await http.refresh(cid, tok["refresh_token"])).status_code == 400


@pytest.mark.risk("R02")
async def test_v10_4_2_replay_without_pkce_verifier_still_revokes(http):
    """An interceptor has the code but not the verifier; presenting it is still proof the
    code leaked."""
    client, code, verifier = await issue_code(http)
    cid = client["client_id"]
    tok = (await http.exchange(cid, code, verifier)).json()
    assert (await http.exchange(cid, code, "w" * 50)).status_code == 400
    assert (await http.rpc(tok["access_token"], "tools/list")).status_code == 401


@pytest.mark.risk("R02")
async def test_v10_4_2_concurrent_double_redemption(http):
    client, code, verifier = await issue_code(http)
    cid = client["client_id"]
    a, b = await asyncio.gather(http.exchange(cid, code, verifier),
                                http.exchange(cid, code, verifier))
    assert sorted([a.status_code, b.status_code]) == [200, 400]
    winner = a if a.status_code == 200 else b
    assert (await http.rpc(winner.json()["access_token"], "tools/list")).status_code == 401


@pytest.mark.risk("R02")
@pytest.mark.parametrize(("elapsed", "revoked"), [(AUTH_CODE_TTL - 1, True),
                                                  (AUTH_CODE_TTL, False),
                                                  (AUTH_CODE_TTL + 1, False)])
async def test_v10_4_2_reuse_window_boundary(http, clock, elapsed, revoked):
    """Reuse is tracked for the code's lifetime; afterwards the code is simply unknown."""
    client, code, verifier = await issue_code(http)
    cid = client["client_id"]
    tok = (await http.exchange(cid, code, verifier)).json()
    clock.advance(elapsed)
    assert (await http.exchange(cid, code, verifier)).status_code == 400
    alive = (await http.refresh(cid, tok["refresh_token"])).status_code == 200
    assert alive is not revoked


@pytest.mark.risk("R02")
async def test_v10_4_2_reuse_does_not_touch_other_grants(http):
    other = await http.connect()
    client, code, verifier = await issue_code(http)
    await http.exchange(client["client_id"], code, verifier)
    await http.exchange(client["client_id"], code, verifier)
    assert (await http.rpc(other.access_token, "tools/list")).status_code == 200


# --------------------------------------------------------------- V10.4.4 grant types
@pytest.mark.risk("R04")
@pytest.mark.parametrize(("grants", "ok"), [
    (["authorization_code", "refresh_token"], True),
    (["authorization_code"], True),
    (["authorization_code", "refresh_token", "client_credentials"], False),
    (["authorization_code", "password"], False),
    (["authorization_code", "implicit"], False),
    (["refresh_token"], False),
    (["client_credentials"], False),
])
async def test_v10_4_4_clients_can_only_register_needed_grants(http, grants, ok):
    r = await http.register(grant_types=grants)
    assert (r.status_code == 201) is ok
    if not ok:
        assert r.json()["error"] == "invalid_client_metadata"


# ---------------------------------------------------------------------- V10.4.6 PKCE
@pytest.mark.risk("R02")
async def test_v10_4_6_code_challenge_is_mandatory(http):
    cid = await http.client_id()
    r = await http.c.get("/authorize", params={"response_type": "code", "client_id": cid,
                                               "redirect_uri": REDIRECT, "state": "s"})
    assert "/oauth/login" not in r.headers.get("location", "")
    assert r.status_code in (302, 400)


@pytest.mark.risk("R02")
async def test_v10_4_6_code_verifier_is_mandatory(http):
    client, code, _ = await issue_code(http)
    r = await http.c.post("/token", data={"grant_type": "authorization_code", "code": code,
                                          "redirect_uri": REDIRECT,
                                          "client_id": client["client_id"]})
    assert r.status_code == 400
    assert "access_token" not in r.text


# ------------------------------------------- V10.4.10 confidential client authentication
@pytest.mark.risk("R04")
@pytest.mark.parametrize(("secret", "status"), [("right", 200), ("wrong-secret", 401),
                                                ("", 401), (None, 401)])
async def test_v10_4_10_confidential_client_must_authenticate(http, secret, status):
    client, code, verifier = await issue_code(http, token_endpoint_auth_method="client_secret_post")
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "client_id": client["client_id"], "code_verifier": verifier}
    if secret == "right":
        data["client_secret"] = client["client_secret"]
    elif secret is not None:
        data["client_secret"] = secret
    r = await http.c.post("/token", data=data)
    assert r.status_code == status


# ----------------------------------------- V10.4.7 / V10.7.1 / V10.7.2 consent content
@pytest.mark.risk("R01", "R08")
async def test_v10_7_2_consent_page_says_what_who_and_how_long(http):
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    page = (await http.c.get(auth.headers["location"])).text
    assert "Claude" in page                                   # who (self-declared name)
    assert "検証されていません" in page                         # V10.4.7: untrusted client warning
    assert "読み取り" in page                                  # what
    assert "書き込み" in page
    assert "https://claude.ai" in page                        # where the code goes
    assert "最長 90 日間" in page                              # how long
    assert "/oauth/connections" in page                       # where to revoke


@pytest.mark.risk("R01")
async def test_v10_7_1_every_authorization_request_needs_fresh_consent(http):
    """No remembered approval: a client that was approved once is prompted again."""
    conn = await http.connect()
    auth, _ = await http.start(conn.client_id)
    assert auth.status_code == 302
    assert "/oauth/login?request=" in auth.headers["location"]
    assert "code=" not in auth.headers["location"]


# ------------------------------------ V10.4.9 / V10.7.3 owner reviews and revokes grants
async def admin_session(d: OAuthDriver, password: str = PASSWORD):
    r = await d.c.post("/oauth/connections", data={"password": password})
    session = None
    if 'name=session value="' in r.text:
        session = r.text.split('name=session value="')[1].split('"')[0]
    return r, session


def families(html_text: str) -> list[str]:
    return [p.split('"')[0] for p in html_text.split('name=family value="')[1:] if p[0] != "*"]


@pytest.mark.risk("R08")
async def test_v10_4_9_connections_page_requires_passphrase(http):
    conn = await http.connect()
    page = await http.c.get("/oauth/connections")
    assert page.status_code == 200
    assert "type=password" in page.text
    assert "Claude" not in page.text                         # nothing listed before auth
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["cache-control"] == "no-store"
    bad, session = await admin_session(http, "wrong-passphrase-1234")
    assert bad.status_code == 401
    assert session is None
    assert (await http.rpc(conn.access_token, "tools/list")).status_code == 200


@pytest.mark.risk("R03", "R04")
async def test_v10_4_9_owner_lists_and_revokes_one_connection(http, clock):
    keep = await http.connect(allow_write=False)
    clock.advance(60)
    kill = await http.connect(allow_write=True)
    page, session = await admin_session(http)
    assert page.status_code == 200
    assert "読み取りのみ" in page.text
    assert "読み取り＋書き込み" in page.text
    assert "set-cookie" not in page.headers                   # no ambient credential
    fams = families(page.text)
    assert len(fams) == 2
    # newest first -> the write connection is listed first
    r = await http.c.post("/oauth/connections/revoke", data={"session": session,
                                                              "family": fams[0]})
    assert r.status_code == 200
    assert "1 件の接続を取り消しました" in r.text
    assert (await http.rpc(kill.access_token, "tools/list")).status_code == 401
    assert (await http.refresh(kill.client_id, kill.refresh_token)).status_code == 400
    assert (await http.rpc(keep.access_token, "tools/list")).status_code == 200


@pytest.mark.risk("R03")
async def test_v10_7_3_owner_revokes_everything(http):
    conns = [await http.connect() for _ in range(3)]
    _, session = await admin_session(http)
    r = await http.c.post("/oauth/connections/revoke", data={"session": session, "family": "*"})
    assert "3 件の接続を取り消しました" in r.text
    assert "有効な接続はありません" in r.text
    for c in conns:
        assert (await http.rpc(c.access_token, "tools/list")).status_code == 401


@pytest.mark.risk("R04")
@pytest.mark.parametrize("session", ["", "nope", "a" * 500])
async def test_v10_4_9_revoke_needs_valid_session(http, session):
    conn = await http.connect()
    r = await http.c.post("/oauth/connections/revoke", data={"session": session, "family": "*"})
    assert r.status_code == 401
    assert (await http.rpc(conn.access_token, "tools/list")).status_code == 200


@pytest.mark.risk("R04")
@pytest.mark.parametrize(("elapsed", "valid"), [(ADMIN_SESSION_TTL - 1, True),
                                                (ADMIN_SESSION_TTL, False),
                                                (ADMIN_SESSION_TTL + 1, False)])
async def test_v10_4_9_admin_session_ttl_boundary(http, clock, elapsed, valid):
    await http.connect()
    _, session = await admin_session(http)
    clock.advance(elapsed)
    r = await http.c.post("/oauth/connections/revoke", data={"session": session, "family": "*"})
    assert (r.status_code == 200) is valid


@pytest.mark.risk("R04")
@pytest.mark.parametrize("family", ["", "unknown", "../x", "<script>"])
async def test_v10_4_9_unknown_family_revokes_nothing(http, family):
    conn = await http.connect()
    _, session = await admin_session(http)
    r = await http.c.post("/oauth/connections/revoke", data={"session": session,
                                                              "family": family})
    assert "0 件の接続を取り消しました" in r.text
    assert "<script>" not in r.text
    assert (await http.rpc(conn.access_token, "tools/list")).status_code == 200


@pytest.mark.risk("R01")
async def test_v10_4_9_admin_login_shares_the_lockout(http):
    """Guessing via the admin page must not be a second, separate budget."""
    for _ in range(5):
        assert (await admin_session(http, "nope"))[0].status_code == 401
    assert (await admin_session(http, PASSWORD))[0].status_code == 429
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    assert (await http.consent(http.request_id(auth))).status_code == 429


@pytest.mark.risk("R08")
async def test_v10_4_9_client_name_is_escaped_in_listing(http):
    r = await http.register(client_name='<img src=x onerror=alert(1)>')
    cid = r.json()["client_id"]
    auth, verifier = await http.start(cid)
    ok = await http.consent(http.request_id(auth))
    code = parse_qs(urlsplit(ok.headers["location"]).query)["code"][0]
    await http.exchange(cid, code, verifier)
    page, _ = await admin_session(http)
    assert "<img" not in page.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in page.text


@pytest.mark.risk("R07")
async def test_v10_4_9_admin_sessions_are_bounded(settings, make_app):
    app = make_app(settings)
    async with asgi_client(app) as c:
        d = OAuthDriver(c)
        await d.connect()
        first = (await admin_session(d))[1]
        assert first
        for _ in range(MAX_ADMIN_SESSIONS):
            await admin_session(d)
        assert len(app.provider._admin_sessions) == MAX_ADMIN_SESSIONS
        r = await c.post("/oauth/connections/revoke", data={"session": first, "family": "*"})
        assert r.status_code == 401                      # oldest session was evicted


@pytest.mark.risk("R06")
async def test_v10_4_9_admin_session_stored_hashed_and_not_logged(settings, make_app, caplog):
    app = make_app(settings)
    with caplog.at_level(logging.DEBUG):
        async with asgi_client(app) as c:
            d = OAuthDriver(c)
            await d.connect()
            session = (await admin_session(d))[1]
    assert session
    assert session not in app.provider._admin_sessions
    assert token_hash(session) in app.provider._admin_sessions
    assert session not in caplog.text
    assert "connections_viewed" in caplog.text


# ------------------------------------------------------- V16.3.2 denied authorization
@pytest.mark.risk("R05")
async def test_v16_3_2_denied_write_is_audited(http, caplog):
    conn = await http.connect(allow_write=False)
    with caplog.at_level(logging.WARNING, logger="garmin_mcp.audit"):
        await http.call(conn.access_token, "delete_workout", {"workout_id": 42})
    assert f"write_denied client_id={conn.client_id}" in caplog.text


@pytest.mark.risk("R02")
async def test_code_reuse_is_audited(http, caplog):
    client, code, verifier = await issue_code(http)
    await http.exchange(client["client_id"], code, verifier)
    with caplog.at_level(logging.WARNING, logger="garmin_mcp.audit"):
        await http.exchange(client["client_id"], code, verifier)
    assert "authorization_code_reuse_detected" in caplog.text
    assert code not in caplog.text
    _ = pkce


# ------------------------------------------------ V10.4.1 exact redirect URI matching
@pytest.mark.risk("R02")
@pytest.mark.parametrize("variant", [
    REDIRECT + "/", REDIRECT + "?x=1", REDIRECT + "/extra", REDIRECT.replace("/api", "/API"),
    REDIRECT.replace("auth_callback", "auth_callbac"),
    REDIRECT.replace("https://", "http://"),
    REDIRECT.replace("claude.ai", "claude.ai."),
])
async def test_v10_4_1_redirect_uri_is_compared_exactly(http, variant):
    cid = await http.client_id()                      # registered with exactly REDIRECT
    r, _ = await http.start(cid, redirect=variant)
    assert r.status_code == 400
    assert "location" not in r.headers


@pytest.mark.risk("R02")
@pytest.mark.parametrize("variant", [
    REDIRECT.replace("https://claude.ai", "https://claude.ai:443"),     # default port
    "https://claude.ai/api/mcp/x/../auth_callback",                      # dot segments
    REDIRECT.replace("claude.ai", "CLAUDE.AI"),                          # host case
])
async def test_v10_4_1_equivalent_spellings_still_land_on_the_registered_uri(http, variant):
    """Deviation from "exact string comparison": the SDK compares WHATWG-normalized URLs,
    so spellings that normalize to the registered URI are accepted. That is only safe if
    the code is then sent to the registered URI itself, which this test pins down."""
    cid = await http.client_id()
    r, _ = await http.start(cid, redirect=variant)
    assert r.status_code == 302
    ok = await http.consent(http.request_id(r))
    loc = urlsplit(ok.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == REDIRECT
