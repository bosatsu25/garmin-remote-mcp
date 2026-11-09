"""Component integration tests: OAuth endpoints through the real SDK routes."""

from urllib.parse import parse_qs, urlsplit

import pytest

from ..conftest import BASE, PASSWORD, REDIRECT, asgi_client, pkce


# ---------------------------------------------------------------- discovery
@pytest.mark.risk("R04")
async def test_metadata_advertises_scopes_and_endpoints(http):
    prm = (await http.c.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert prm["resource"] == f"{BASE}/mcp"
    asm = (await http.c.get("/.well-known/oauth-authorization-server")).json()
    assert asm["issuer"] == BASE
    assert set(asm["scopes_supported"]) == {"garmin:read", "garmin:write"}
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["registration_endpoint"] == f"{BASE}/register"


@pytest.mark.risk("R04")
async def test_mcp_requires_bearer(http):
    r = await http.rpc(None, "tools/list")
    assert r.status_code == 401
    assert 'resource_metadata="' in r.headers["www-authenticate"]


@pytest.mark.risk("R04")
@pytest.mark.parametrize("header", ["Bearer", "Bearer ", "Basic Zm9vOmJhcg==", "bearer x y",
                                    "Token abc"])
async def test_malformed_authorization_headers(http, header):
    r = await http.rpc(None, "tools/list", headers={"Authorization": header})
    assert r.status_code == 401


@pytest.mark.risk("R04", "R06")
async def test_token_in_query_string_is_not_accepted(http):
    conn = await http.connect()
    r = await http.c.post(f"/mcp?access_token={conn.access_token}",
                          json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                          headers={"Accept": "application/json, text/event-stream"})
    assert r.status_code == 401


# ------------------------------------------------------------- registration
@pytest.mark.risk("R02")
@pytest.mark.parametrize("redirect", ["https://evil.example/cb", "https://claude.ai@evil.example/cb",
                                      "http://claude.ai/api/mcp/auth_callback",
                                      "https://claude.ai/cb#frag"])
async def test_dcr_rejects_bad_redirects(http, redirect):
    r = await http.register(redirect)
    assert r.status_code == 400
    assert r.json()["error"] in ("invalid_redirect_uri", "invalid_client_metadata")


@pytest.mark.risk("R02")
@pytest.mark.parametrize("redirect", [REDIRECT, "https://claude.com/api/mcp/auth_callback",
                                      "http://localhost:33418/callback"])
async def test_dcr_accepts_known_clients(http, redirect):
    assert (await http.register(redirect)).status_code == 201


@pytest.mark.risk("R07")
async def test_oversized_body_rejected(http):
    r = await http.c.post("/register", content=b"{" + b" " * (300 * 1024) + b"}",
                          headers={"content-type": "application/json"})
    assert r.status_code == 413


# -------------------------------------------------------------- authorize
@pytest.mark.risk("R02")
async def test_authorize_with_unregistered_redirect_does_not_redirect(http):
    cid = await http.client_id()
    r, _ = await http.start(cid, redirect="https://claude.ai/other")
    assert r.status_code == 400                    # never redirect to an unregistered URI


@pytest.mark.risk("R02")
async def test_authorize_requires_pkce_s256(http):
    cid = await http.client_id()
    _, ch = pkce()
    r = await http.c.get("/authorize", params={
        "response_type": "code", "client_id": cid, "redirect_uri": REDIRECT,
        "code_challenge": ch, "code_challenge_method": "plain", "state": "s"})
    assert r.status_code in (302, 400)
    if r.status_code == 302:
        assert "error=" in r.headers["location"]
        assert "/oauth/login" not in r.headers["location"]


@pytest.mark.risk("R02")
async def test_authorize_unknown_client(http):
    r, _ = await http.start("no-such-client")
    assert r.status_code == 400


@pytest.mark.risk("R05")
async def test_authorize_unknown_scope_is_error_redirect(http):
    cid = await http.client_id()
    r, _ = await http.start(cid, scope="garmin:admin")
    assert r.status_code == 302
    assert "error=invalid_scope" in r.headers["location"]


# ------------------------------------------------------------ consent page
@pytest.mark.risk("R08")
async def test_consent_page_security_headers(http):
    cid = await http.client_id()
    r, _ = await http.start(cid)
    page = await http.c.get(r.headers["location"])
    assert page.status_code == 200
    h = page.headers
    assert h["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert "form-action 'self' https://claude.ai" in h["content-security-policy"]
    assert "script-src" not in h["content-security-policy"]       # default-src 'none' applies
    assert h["cache-control"] == "no-store"
    assert h["referrer-policy"] == "no-referrer"
    assert h["strict-transport-security"].startswith("max-age=")
    assert h["x-content-type-options"] == "nosniff"
    assert "server" not in h


@pytest.mark.risk("R08")
async def test_consent_page_escapes_client_name(http):
    r = await http.register(client_name='<img src=x onerror=alert(1)>"\'')
    cid = r.json()["client_id"]
    auth, _ = await http.start(cid)
    page = await http.c.get(auth.headers["location"])
    assert "<img" not in page.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in page.text


@pytest.mark.risk("R05")
async def test_consent_page_offers_write_only_when_enabled(settings, make_settings, make_app):
    for allow_write, expected in [(True, True), (False, False)]:
        s = make_settings(allow_write=allow_write)
        async with asgi_client(make_app(s)) as c:
            from ..conftest import OAuthDriver

            d = OAuthDriver(c)
            auth, _ = await d.start(await d.client_id())
            page = await c.get(auth.headers["location"])
            assert ('name=allow_write' in page.text) is expected


@pytest.mark.risk("R08")
@pytest.mark.parametrize("rid", ["", "nope", "a" * 500, "<script>"])
async def test_consent_unknown_request_id(http, rid):
    r = await http.c.get("/oauth/login", params={"request": rid})
    assert r.status_code == 400
    assert "<script>" not in r.text
    r = await http.consent(rid)
    assert r.status_code == 400


@pytest.mark.risk("R01")
async def test_wrong_password_shows_form_again(http):
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    r = await http.consent(http.request_id(auth), "wrong-password-123")
    assert r.status_code == 401
    assert "パスワードが違います" in r.text
    assert "wrong-password-123" not in r.text      # never reflect the password


@pytest.mark.risk("R01")
async def test_lockout_after_five_failures_even_with_right_password(http):
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    rid = http.request_id(auth)
    for _ in range(5):
        assert (await http.consent(rid, "nope")).status_code == 401
    r = await http.consent(rid, PASSWORD)
    assert r.status_code == 429
    assert r.headers["retry-after"] == "900"


@pytest.mark.risk("R01")
async def test_lockout_lifts_after_window(http, clock):
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    rid = http.request_id(auth)
    for _ in range(5):
        await http.consent(rid, "nope")
    clock.advance(15 * 60)
    auth, _ = await http.start(cid)                  # pending TTL also elapsed; start over
    assert (await http.consent(http.request_id(auth))).status_code == 302


@pytest.mark.risk("R01")
async def test_spoofed_fly_client_ip_ignored_when_untrusted(http):
    """Rotating Fly-Client-IP must not evade the per-IP limit off Fly."""
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    rid = http.request_id(auth)
    for i in range(5):
        await http.consent(rid, "nope", headers={"Fly-Client-IP": f"10.0.0.{i}"})
    r = await http.consent(rid, PASSWORD, headers={"Fly-Client-IP": "10.9.9.9"})
    assert r.status_code == 429


@pytest.mark.risk("R01")
async def test_fly_client_ip_honored_when_trusted(make_settings, make_app):
    s = make_settings(trust_fly_client_ip=True)
    async with asgi_client(make_app(s)) as c:
        from ..conftest import OAuthDriver

        d = OAuthDriver(c)
        cid = await d.client_id()
        auth, _ = await d.start(cid)
        rid = d.request_id(auth)
        for _ in range(5):
            await d.consent(rid, "nope", headers={"Fly-Client-IP": "203.0.113.9"})
        ok = await d.consent(rid, PASSWORD, headers={"Fly-Client-IP": "198.51.100.1"})
        assert ok.status_code == 302


@pytest.mark.risk("R01", "R07")
async def test_overlong_password_rejected_without_hashing(http):
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    r = await http.consent(http.request_id(auth), "x" * 5000)
    assert r.status_code == 401


@pytest.mark.risk("R02")
async def test_approval_redirects_with_code_and_state_only_to_registered_uri(http):
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    r = await http.consent(http.request_id(auth))
    assert r.status_code == 302
    loc = urlsplit(r.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == REDIRECT
    q = parse_qs(loc.query)
    assert q["state"] == ["st4te"]
    assert len(q["code"][0]) >= 43
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.risk("R01")
async def test_request_id_is_single_use(http):
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    rid = http.request_id(auth)
    assert (await http.consent(rid)).status_code == 302
    assert (await http.consent(rid)).status_code == 400


# ---------------------------------------------------------------- /token
async def _code(http, allow_write=False):
    cid = await http.client_id()
    auth, verifier = await http.start(cid)
    r = await http.consent(http.request_id(auth), allow_write=allow_write)
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    return cid, code, verifier


@pytest.mark.risk("R02")
async def test_wrong_pkce_verifier_rejected(http):
    cid, code, _ = await _code(http)
    r = await http.exchange(cid, code, "w" * 50)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


@pytest.mark.risk("R02")
async def test_redirect_uri_must_match_at_token(http):
    cid, code, verifier = await _code(http)
    r = await http.exchange(cid, code, verifier, redirect="https://claude.ai/different")
    assert r.status_code == 400


@pytest.mark.risk("R02")
async def test_code_cannot_be_redeemed_by_other_client(http):
    _, code, verifier = await _code(http)
    other = await http.client_id()
    r = await http.exchange(other, code, verifier)
    assert r.status_code in (400, 401)


@pytest.mark.risk("R02")
async def test_code_replay_rejected(http):
    cid, code, verifier = await _code(http)
    assert (await http.exchange(cid, code, verifier)).status_code == 200
    assert (await http.exchange(cid, code, verifier)).status_code == 400


@pytest.mark.risk("R06")
async def test_token_response_not_cacheable(http):
    cid, code, verifier = await _code(http)
    r = await http.exchange(cid, code, verifier)
    assert "no-store" in r.headers.get("cache-control", "")


@pytest.mark.risk("R05")
@pytest.mark.parametrize(("allow_write", "scope"), [(False, "garmin:read"),
                                                    (True, "garmin:read garmin:write")])
async def test_granted_scope_follows_consent_checkbox(http, allow_write, scope):
    conn = await http.connect(allow_write=allow_write)
    assert conn.scope == scope


@pytest.mark.risk("R05")
async def test_write_checkbox_ignored_when_writes_disabled(make_settings, make_app):
    async with asgi_client(make_app(make_settings(allow_write=False))) as c:
        from ..conftest import OAuthDriver

        conn = await OAuthDriver(c).connect(allow_write=True)
        assert conn.scope == "garmin:read"


@pytest.mark.risk("R05")
async def test_refresh_cannot_add_write_scope(http):
    conn = await http.connect(allow_write=False)
    r = await http.refresh(conn.client_id, conn.refresh_token, scope="garmin:read garmin:write")
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_scope"
    # and the session survives the bad request
    assert (await http.refresh(conn.client_id, conn.refresh_token)).status_code == 200


@pytest.mark.risk("R03")
async def test_refresh_reuse_over_http_revokes_family(http):
    conn = await http.connect()
    r1 = await http.refresh(conn.client_id, conn.refresh_token)
    new = r1.json()
    replay = await http.refresh(conn.client_id, conn.refresh_token)
    assert replay.status_code == 400
    assert (await http.rpc(new["access_token"], "tools/list")).status_code == 401
    assert (await http.refresh(conn.client_id, new["refresh_token"])).status_code == 400


@pytest.mark.risk("R04")
async def test_revocation_endpoint(http):
    conn = await http.connect()
    # MCP SDK 2.3 requires the client_secret field even for public clients (empty is fine).
    r = await http.c.post("/revoke", data={"token": conn.access_token,
                                           "client_id": conn.client_id, "client_secret": ""})
    assert r.status_code == 200, r.text
    assert (await http.rpc(conn.access_token, "tools/list")).status_code == 401
    assert (await http.refresh(conn.client_id, conn.refresh_token)).status_code == 400


@pytest.mark.risk("R04")
async def test_characterize_sdk_revoke_requires_client_secret_field(http):
    """Characterization test of an upstream quirk (RFC 7009 allows omitting it).
    If this starts failing, the SDK changed: drop the workaround above."""
    conn = await http.connect()
    r = await http.c.post("/revoke", data={"token": conn.access_token,
                                           "client_id": conn.client_id})
    assert r.status_code == 400
    assert "client_secret" in r.json()["error_description"]


@pytest.mark.risk("R04")
async def test_revoke_cannot_target_another_clients_token(http):
    victim = await http.connect()
    attacker = await http.client_id()
    await http.c.post("/revoke", data={"token": victim.access_token, "client_id": attacker,
                                       "client_secret": ""})
    assert (await http.rpc(victim.access_token, "tools/list")).status_code == 200


@pytest.mark.risk("R04")
async def test_expired_access_token_rejected_at_mcp(http, clock):
    conn = await http.connect()
    clock.advance(3600)
    assert (await http.rpc(conn.access_token, "tools/list")).status_code == 401


# -------------------------------------------------------- transport security
@pytest.mark.risk("R14")
@pytest.mark.parametrize(("headers", "status"), [
    ({"Host": "evil.example"}, 421),
    ({"Host": "localhost:8000"}, 421),
    ({"Origin": "https://evil.example"}, 403),
    ({"Origin": "https://claude.ai"}, 200),
    ({}, 200),
])
async def test_host_and_origin_checks(http, headers, status):
    conn = await http.connect()
    r = await http.rpc(conn.access_token, "tools/list", headers=headers)
    assert r.status_code == status


@pytest.mark.risk("R14")
async def test_mcp_post_requires_json_content_type(http):
    conn = await http.connect()
    r = await http.c.post("/mcp", content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                          headers={"Authorization": f"Bearer {conn.access_token}",
                                   "Content-Type": "text/plain",
                                   "Accept": "application/json, text/event-stream"})
    assert r.status_code in (400, 415)


@pytest.mark.risk("R08")
async def test_default_csp_on_api_responses(http):
    r = await http.c.get("/healthz")
    assert r.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert r.json() == {"status": "ok", "version": r.json()["version"]}
