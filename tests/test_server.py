"""End-to-end: DCR -> consent page -> PKCE token -> MCP calls -> refresh."""

import base64
import contextlib
import hashlib
import json
import secrets
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from garmin_mcp.config import Settings
from garmin_mcp.garmin_client import GarminService, decode_token_seed, seed_tokens
from garmin_mcp.server import create_server

BASE = "https://garmin.example.com"
PASSWORD = "correct horse battery staple"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"


class FakeGarmin:
    def __init__(self) -> None:
        self.uploaded: list[dict[str, Any]] = []
        self.scheduled: list[tuple[int, str]] = []

    def today(self):
        return date(2026, 11, 9)

    def get_user_summary(self, d):
        return {"calendarDate": d, "totalSteps": 12345, "unused": None}

    def get_activities(self, start, limit, activity_type):
        return [
            {
                "activityId": 1,
                "activityName": "Morning Run",
                "activityType": {"typeKey": "running"},
                "distance": 10000.0,
                "duration": 3000.0,
                "averageSpeed": 1000 / 300,
                "noise": "x" * 10,
            }
        ][:limit]

    def upload_workout(self, payload):
        self.uploaded.append(payload)
        return {"workoutId": 42}

    def schedule_workout(self, wid, d):
        self.scheduled.append((wid, d))
        return {"workoutScheduleId": 7}


class FakeService(GarminService):
    def __init__(self, fake: FakeGarmin):
        super().__init__(Path("/nonexistent"))
        self.fake = fake

    def call_sync(self, fn):
        return fn(self.fake)


def _settings(tmp_path: Path, allow_write: bool = True) -> Settings:
    return Settings(
        public_url=BASE,
        owner_password=PASSWORD,
        data_dir=tmp_path,
        allow_write=allow_write,
    )


def _app(settings: Settings, fake: FakeGarmin):
    mcp = create_server(settings, FakeService(fake))
    return mcp.streamable_http_app(
        streamable_http_path="/mcp", stateless_http=True, json_response=True, host="0.0.0.0"
    )


@pytest.fixture
def fake():
    return FakeGarmin()


@contextlib.asynccontextmanager
async def _client(app):
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=BASE) as c:
            yield c


async def _register(c: httpx.AsyncClient, redirect: str = REDIRECT) -> httpx.Response:
    return await c.post(
        "/register",
        json={
            "redirect_uris": [redirect],
            "client_name": "Claude",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )


async def _authorize(c: httpx.AsyncClient, client_id: str) -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    r = await c.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
            "scope": "garmin",
            "resource": f"{BASE}/mcp",
        },
    )
    assert r.status_code == 302, r.text
    login_url = r.headers["location"]
    assert login_url.startswith(f"{BASE}/oauth/login?request=")
    request_id = parse_qs(urlparse(login_url).query)["request"][0]

    page = await c.get(login_url)
    assert page.status_code == 200
    assert "Claude" in page.text and "claude.ai" in page.text

    bad = await c.post("/oauth/login", data={"request": request_id, "password": "nope"})
    assert bad.status_code == 401

    ok = await c.post("/oauth/login", data={"request": request_id, "password": PASSWORD})
    assert ok.status_code == 302
    loc = urlparse(ok.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == REDIRECT
    q = parse_qs(loc.query)
    assert q["state"] == ["xyz"]
    return q["code"][0], verifier


async def _token(c: httpx.AsyncClient, client_id: str) -> dict[str, Any]:
    code, verifier = await _authorize(c, client_id)
    r = await c.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": f"{BASE}/mcp",
        },
    )
    assert r.status_code == 200, r.text
    tok = r.json()
    # code is single-use
    again = await c.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert again.status_code == 400
    return tok


async def _rpc(c, token, method, params=None, id_=1):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
    }
    body = {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}
    return await c.post("/mcp", headers=headers, json=body)


async def _init(c, token):
    r = await _rpc(
        c,
        token,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


async def test_metadata_and_unauthenticated(tmp_path, fake):
    async with _client(_app(_settings(tmp_path), fake)) as c:
        prm = (await c.get("/.well-known/oauth-protected-resource/mcp")).json()
        assert prm["resource"] == f"{BASE}/mcp"
        asm = (await c.get("/.well-known/oauth-authorization-server")).json()
        assert asm["registration_endpoint"] == f"{BASE}/register"
        r = await c.post("/mcp", json={})
        assert r.status_code == 401
        assert "resource_metadata" in r.headers["www-authenticate"]
        assert (await c.get("/healthz")).json()["status"] == "ok"


async def test_rejects_foreign_redirect(tmp_path, fake):
    async with _client(_app(_settings(tmp_path), fake)) as c:
        r = await _register(c, "https://evil.example.net/cb")
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"


async def test_full_flow(tmp_path, fake):
    settings = _settings(tmp_path)
    async with _client(_app(settings, fake)) as c:
        reg = await _register(c)
        assert reg.status_code == 201, reg.text
        client_id = reg.json()["client_id"]
        tok = await _token(c, client_id)

        await _init(c, tok["access_token"])
        tools = (await _rpc(c, tok["access_token"], "tools/list", id_=2)).json()
        names = {t["name"] for t in tools["result"]["tools"]}
        assert {"get_daily_summary", "list_activities", "create_workout"} <= names

        res = (
            await _rpc(
                c,
                tok["access_token"],
                "tools/call",
                {"name": "get_daily_summary", "arguments": {}},
                id_=3,
            )
        ).json()["result"]
        assert not res.get("isError"), res
        payload = json.loads(res["content"][0]["text"])
        assert payload == {"calendarDate": "2026-11-09", "totalSteps": 12345}

        res = (
            await _rpc(
                c,
                tok["access_token"],
                "tools/call",
                {"name": "list_activities", "arguments": {"limit": 5}},
                id_=4,
            )
        ).json()["result"]
        acts = json.loads(res["content"][0]["text"])
        assert acts[0]["averagePacePerKm"] == "5:00"
        assert acts[0]["activityType"] == "running"
        assert "noise" not in acts[0]

        res = (
            await _rpc(
                c,
                tok["access_token"],
                "tools/call",
                {
                    "name": "create_workout",
                    "arguments": {
                        "name": "Easy 30",
                        "sport": "running",
                        "steps": [
                            {
                                "type": "interval",
                                "end": "time",
                                "seconds": 1800,
                                "target": {"kind": "hr_zone", "zone": 2},
                            }
                        ],
                        "schedule_date": "2026-11-10",
                    },
                },
                id_=5,
            )
        ).json()["result"]
        assert not res.get("isError"), res
        out = json.loads(res["content"][0]["text"])
        assert out["workoutId"] == 42
        assert out["scheduled"]["scheduledWorkoutId"] == 7
        assert fake.scheduled == [(42, "2026-11-10")]
        assert fake.uploaded[0]["workoutName"] == "Easy 30"

        # bad date -> tool error, not a crash
        res = (
            await _rpc(
                c,
                tok["access_token"],
                "tools/call",
                {"name": "get_daily_summary", "arguments": {"date": "11/09/2026"}},
                id_=6,
            )
        ).json()["result"]
        assert res["isError"] is True

        # refresh rotates tokens and invalidates the old access token
        r = await c.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tok["refresh_token"],
                "client_id": client_id,
            },
        )
        assert r.status_code == 200, r.text
        new = r.json()
        assert new["refresh_token"] != tok["refresh_token"]
        old = await _rpc(c, tok["access_token"], "tools/list", id_=7)
        assert old.status_code == 401
        assert (await _rpc(c, new["access_token"], "tools/list", id_=8)).status_code == 200

    # tokens survive a restart (state persisted on disk, hashed)
    state = (tmp_path / "oauth_state.json").read_text()
    assert new["access_token"] not in state
    async with _client(_app(settings, fake)) as c:
        assert (await _rpc(c, new["access_token"], "tools/list", id_=9)).status_code == 200


async def test_write_tools_can_be_disabled(tmp_path, fake):
    async with _client(_app(_settings(tmp_path, allow_write=False), fake)) as c:
        client_id = (await _register(c)).json()["client_id"]
        tok = await _token(c, client_id)
        tools = (await _rpc(c, tok["access_token"], "tools/list")).json()
        names = {t["name"] for t in tools["result"]["tools"]}
        assert "create_workout" not in names
        assert "delete_workout" not in names


async def test_login_rate_limit(tmp_path, fake):
    async with _client(_app(_settings(tmp_path), fake)) as c:
        client_id = (await _register(c)).json()["client_id"]
        r = await c.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT,
                "code_challenge": "x" * 43,
                "code_challenge_method": "S256",
            },
        )
        rid = parse_qs(urlparse(r.headers["location"]).query)["request"][0]
        for _ in range(5):
            assert (
                await c.post("/oauth/login", data={"request": rid, "password": "wrong"})
            ).status_code == 401
        blocked = await c.post("/oauth/login", data={"request": rid, "password": PASSWORD})
        assert blocked.status_code == 429


def test_token_seed(tmp_path):
    raw = json.dumps({"di_token": "a", "di_refresh_token": "b", "di_client_id": "c"})
    b64 = base64.b64encode(raw.encode()).decode()
    assert json.loads(decode_token_seed(b64))["di_refresh_token"] == "b"
    with pytest.raises(ValueError):
        decode_token_seed(base64.b64encode(b'{"x":1}').decode())

    seed_tokens(tmp_path / "garmin", b64)
    f = tmp_path / "garmin" / "garmin_tokens.json"
    assert json.loads(f.read_text())["di_token"] == "a"
    assert oct(f.stat().st_mode & 0o777) == "0o600"
    # existing (possibly refreshed) tokens are never overwritten by the seed
    f.write_text(json.dumps({"di_token": "newer", "di_refresh_token": "b"}))
    seed_tokens(tmp_path / "garmin", b64)
    assert json.loads(f.read_text())["di_token"] == "newer"


def test_missing_tokens_gives_actionable_error(tmp_path):
    from garmin_mcp.garmin_client import GarminUnavailable

    svc = GarminService(tmp_path / "garmin")
    with pytest.raises(GarminUnavailable, match="garmin-mcp-login"):
        svc.call_sync(lambda g: g.get_full_name())
