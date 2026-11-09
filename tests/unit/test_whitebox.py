"""White-box tests (JSTQB FL §4.3) for branches that black-box tests did not reach.

Each test names the branch it exists for; they were found with `pytest --cov-branch`.
"""

import os
from pathlib import Path

import pytest
from starlette.requests import Request

from garmin_mcp import oauth as o
from garmin_mcp.garmin_client import write_private_file
from garmin_mcp.oauth import MAX_CODES, OwnerOAuthProvider
from garmin_mcp.server import SecurityHeadersMiddleware, create_app

from ..conftest import PASSWORD, OAuthDriver, asgi_client


def _req(headers: dict[str, str], client=("1.2.3.4", 1)) -> Request:
    return Request({"type": "http", "headers": [(k.lower().encode(), v.encode())
                                                for k, v in headers.items()], "client": client})


# oauth.client_ip: trusted header present / empty / overlong / no socket peer
@pytest.mark.risk("R01")
@pytest.mark.parametrize(("headers", "client", "expected"), [
    ({"Fly-Client-IP": "203.0.113.7"}, ("1.2.3.4", 1), "203.0.113.7"),
    ({"Fly-Client-IP": "  "}, ("1.2.3.4", 1), "1.2.3.4"),
    ({"Fly-Client-IP": "x" * 65}, ("1.2.3.4", 1), "1.2.3.4"),
    ({}, None, "unknown"),
])
def test_client_ip_branches(make_settings, clock, headers, client, expected):
    p = OwnerOAuthProvider(make_settings(trust_fly_client_ip=True), clock=clock)
    assert p.client_ip(_req(headers, client)) == expected


# oauth.login_page: pending consumed by a concurrent submit between verify and pop
@pytest.mark.risk("R01", "R02")
async def test_concurrent_consent_submits_issue_one_code(http):
    import asyncio

    cid = await http.client_id()
    auth, _ = await http.start(cid)
    rid = http.request_id(auth)
    a, b = await asyncio.gather(http.consent(rid), http.consent(rid))
    assert sorted([a.status_code, b.status_code]) == [302, 400]


# oauth.login_page: client evicted after authorize, before consent
@pytest.mark.risk("R02")
async def test_consent_for_evicted_client_fails(settings, make_app):
    app = make_app(settings)
    async with asgi_client(app) as c:
        d = OAuthDriver(c)
        cid = await d.client_id()
        auth, _ = await d.start(cid)
        del app.provider._clients[cid]
        r = await d.consent(d.request_id(auth))
        assert r.status_code == 400
        assert app.provider._codes == {}


# oauth.login_page: authorization-code store is purged when it reaches MAX_CODES
@pytest.mark.risk("R07")
async def test_code_store_purges_expired_at_cap(settings, make_app, clock):
    app = make_app(settings)
    async with asgi_client(app) as c:
        d = OAuthDriver(c)
        cid = await d.client_id()
        for i in range(MAX_CODES):
            app.provider._codes[f"old{i}"] = o.AuthorizationCode(
                code=f"old{i}", scopes=[], expires_at=clock() + 1, client_id=cid,
                code_challenge="x" * 43, redirect_uri="https://claude.ai/cb",
                redirect_uri_provided_explicitly=True)
        auth, _ = await d.start(cid)
        clock.advance(2)                       # expire the old codes *after* authorize()
        assert (await d.consent(d.request_id(auth), PASSWORD)).status_code == 302
        assert len(app.provider._codes) == 1


# oauth._save / write_private_file: failed write leaves no temp file behind
@pytest.mark.risk("R06", "R13")
async def test_failed_state_write_cleans_up(settings, clock, monkeypatch):
    p = OwnerOAuthProvider(settings, clock=clock)
    monkeypatch.setattr(Path, "replace", lambda self, target: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError):
        p._save()
    assert [f for f in os.listdir(settings.data_dir) if f.endswith(".tmp")] == []


@pytest.mark.risk("R06")
def test_failed_private_write_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "replace", lambda a, b: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError):
        write_private_file(tmp_path / "t.json", "{}")
    assert list(tmp_path.iterdir()) == []


# SecurityHeadersMiddleware: non-HTTP scopes pass through; HSTS can be disabled
@pytest.mark.risk("R08")
async def test_security_headers_middleware_branches():
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["type"])
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"server", b"uvicorn"), (b"x-frame-options", b"SAMEORIGIN")]})

    sent = []

    async def send(msg):
        sent.append(msg)

    await SecurityHeadersMiddleware(inner)({"type": "lifespan"}, None, send)
    assert seen == ["lifespan"]
    assert sent == []

    await SecurityHeadersMiddleware(inner, hsts=False)({"type": "http"}, None, send)
    headers = dict(sent[0]["headers"])
    assert b"server" not in headers
    assert headers[b"x-frame-options"] == b"SAMEORIGIN"       # route's own value wins
    assert b"strict-transport-security" not in headers
    assert headers[b"x-content-type-options"] == b"nosniff"


# create_app: seeding path + localhost host allowlist
@pytest.mark.risk("R09", "R14")
async def test_create_app_seeds_tokens_and_localhost_hosts(make_settings, fake):
    import base64
    import json

    from ..conftest import FakeService

    seed = base64.b64encode(json.dumps({"di_refresh_token": "r"}).encode()).decode()
    s = make_settings(public_url="http://localhost:8000", garmin_tokens_seed=seed)
    app = create_app(s, garmin=FakeService(fake))
    assert (s.garmin_token_dir / "garmin_tokens.json").exists()
    async with app.router.lifespan_context(app):
        import httpx

        t = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=t, base_url="http://localhost:8000") as c:
            r = await c.post("/mcp", json={}, headers={"Host": "127.0.0.1:9999"})
            assert r.status_code == 401        # host allowed in dev; auth still required
