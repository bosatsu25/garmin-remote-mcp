"""Shared fixtures and the traceability gate.

Test levels (JSTQB FL §2.2.1) live in sub-packages:
  unit/         component tests       - one module, no network, fake clock
  integration/  component integration - full ASGI stack (SDK + our provider + tools)
  system/       system tests          - real uvicorn process over TCP
  acceptance/   acceptance tests      - owner user stories, Given/When/Then
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import inspect
import json
import secrets
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from garmin_mcp.config import Settings
from garmin_mcp.garmin_client import GarminService
from garmin_mcp.oauth import OwnerOAuthProvider
from garmin_mcp.security import OwnerSecret
from garmin_mcp.server import create_app

from .risks import RISKS

BASE = "https://garmin.example.com"
PASSWORD = "correct horse battery staple"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PROTOCOL = "2025-06-18"

# Low-cost scrypt for tests only (production default is N=2**17).
_SECRET = OwnerSecret.from_plaintext(PASSWORD, n=2**14)


# ------------------------------------------------------------- traceability
_RISK_KEY = pytest.StashKey[dict[str, list[str]]]()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "risk(*ids): product risks this test mitigates")
    config.addinivalue_line("markers", "system: starts a real server process")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.hookimpl(tryfirst=True)
def pytest_pycollect_makeitem(collector: Any, name: str, obj: Any) -> None:
    # Mark coroutine tests for anyio *before* parametrization happens.
    if collector.funcnamefilter(name) and inspect.iscoroutinefunction(obj):
        pytest.mark.anyio(obj)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    covered: dict[str, list[str]] = {}
    problems: list[str] = []
    for item in items:
        ids = [i for m in item.iter_markers("risk") for i in m.args]
        if item.module and item.module.__name__.endswith("test_traceability"):
            continue
        if not ids:
            problems.append(f"{item.nodeid}: missing @pytest.mark.risk")
        for rid in ids:
            if rid not in RISKS:
                problems.append(f"{item.nodeid}: unknown risk id {rid}")
            covered.setdefault(rid, []).append(item.nodeid)
    config.stash[_RISK_KEY] = covered
    if problems:
        raise pytest.UsageError("Traceability violations:\n" + "\n".join(problems))


@pytest.fixture
def risk_coverage(request: pytest.FixtureRequest) -> dict[str, list[str]]:
    return request.config.stash[_RISK_KEY]


# -------------------------------------------------------------------- clock
@dataclass
class FakeClock:
    now: float = field(default_factory=lambda: float(int(time.time())))

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


# ----------------------------------------------------------------- settings
@pytest.fixture
def make_settings(tmp_path: Path) -> Callable[..., Settings]:
    def _make(**overrides: Any) -> Settings:
        base: dict[str, Any] = {
            "public_url": BASE,
            "owner_secret": _SECRET,
            "data_dir": tmp_path / "data",
        }
        base.update(overrides)
        return Settings(**base)

    return _make


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings()


# ------------------------------------------------------------- fake garmin
class FakeGarmin:
    """Stands in for garminconnect.Garmin. Records writes; can be told to fail."""

    def __init__(self) -> None:
        self.uploaded: list[dict[str, Any]] = []
        self.scheduled: list[tuple[int, str]] = []
        self.unscheduled: list[int] = []
        self.deleted: list[int] = []
        self.api_calls: list[tuple[str, Any]] = []
        self.reads: list[str] = []
        self.fail_with: BaseException | None = None

    def _maybe_fail(self) -> None:
        if self.fail_with is not None:
            raise self.fail_with

    def today(self) -> date:
        return date(2026, 11, 9)

    def get_full_name(self) -> str:
        return "Owner"

    def get_unit_system(self) -> str:
        return "metric"

    def get_user_timezone(self) -> str:
        return "Asia/Tokyo"

    def get_devices(self) -> list[dict[str, Any]]:
        return [{"productDisplayName": "Forerunner", "deviceId": 1, "secret": None}]

    def get_user_summary(self, d: str) -> dict[str, Any]:
        self._maybe_fail()
        return {"calendarDate": d, "totalSteps": 12345, "unused": None}

    def get_sleep_data(self, d: str) -> dict[str, Any]:
        return {
            "dailySleepDTO": {"calendarDate": d, "sleepTimeSeconds": 25200},
            "sleepLevels": [{"x": i} for i in range(500)],
            "avgOvernightHrv": 55,
        }

    def get_hrv_data(self, d: str) -> dict[str, Any]:
        return {"hrvSummary": {"lastNightAvg": 55}, "hrvReadings": list(range(300))}

    def get_activities(self, start: int, limit: int, activity_type: str | None) -> list[Any]:
        acts = [
            {
                "activityId": i,
                "activityName": f"Run {i}",
                "activityType": {"typeKey": "running"},
                "distance": 10000.0,
                "duration": 3000.0,
                "averageSpeed": 1000 / 300,
                "noise": "x",
            }
            for i in range(1, 201)
        ]
        return acts[start : start + limit]

    def get_activities_by_date(self, s: str, e: str | None, t: str | None) -> list[Any]:
        return self.get_activities(0, 3, t)

    def get_sleep_daily(self, s: str, e: str) -> list[Any]:
        return [{"calendarDate": s, "sleepScore": 80}]

    def get_workout_by_id(self, wid: int) -> dict[str, Any]:
        return {"workoutId": wid, "workoutName": "Easy"}

    def get_workouts(self, start: int, limit: int) -> list[Any]:
        return [{"workoutId": 1, "workoutName": "Easy", "sportType": {"sportTypeKey": "running"}}]

    def get_scheduled_workouts_by_period(self, s: str, e: str) -> list[Any]:
        return [{"date": s, "workoutScheduleId": 7}]

    def upload_workout(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._maybe_fail()
        self.uploaded.append(payload)
        return {"workoutId": 42}

    def schedule_workout(self, wid: int, d: str) -> dict[str, Any]:
        self.scheduled.append((wid, d))
        return {"workoutScheduleId": 7}

    def unschedule_workout(self, sid: int) -> None:
        self.unscheduled.append(sid)

    def delete_workout(self, wid: int) -> None:
        self.deleted.append(wid)

    def connectapi(self, path: str, params: Any = None) -> Any:
        self.api_calls.append((path, params))
        return {"path": path}

    def get_activity(self, aid: str) -> dict[str, Any]:
        return {"activityId": int(aid), "activityName": "Run"}

    def get_activity_splits(self, aid: str) -> dict[str, Any]:
        return {"lapDTOs": [{"lapIndex": 1}]}

    def __getattr__(self, name: str) -> Any:
        """Contract-checking fallback for read methods.

        Only methods that exist on the real garminconnect.Garmin are allowed, and the
        arguments must bind to the real signature. A typo or arity mismatch in server code
        therefore fails here instead of in production.
        """
        from garminconnect import Garmin

        real = getattr(Garmin, name, None)
        if not name.startswith("get_") or real is None:
            raise AttributeError(name)
        sig = inspect.signature(real)

        def stub(*args: Any, **kwargs: Any) -> Any:
            sig.bind(self, *args, **kwargs)   # raises TypeError on contract mismatch
            self.reads.append(name)
            return {"method": name, "args": [str(a) for a in args]}

        return stub


class FakeService(GarminService):
    def __init__(self, fake: FakeGarmin):
        super().__init__(Path("/nonexistent"))
        self.fake = fake

    def call_sync(self, fn: Callable[[Any], Any]) -> Any:
        return fn(self.fake)


@pytest.fixture
def fake() -> FakeGarmin:
    return FakeGarmin()


# ---------------------------------------------------------------- ASGI app
@pytest.fixture
def make_app(fake: FakeGarmin, clock: FakeClock) -> Callable[[Settings], Any]:
    def _make(s: Settings) -> Any:
        provider = OwnerOAuthProvider(s, clock=clock)
        app = create_app(s, garmin=FakeService(fake), provider=provider, seed=False)
        app.provider = provider
        return app

    return _make


@contextlib.asynccontextmanager
async def asgi_client(app: Any) -> AsyncIterator[httpx.AsyncClient]:
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url=BASE, follow_redirects=False
        ) as c:
            yield c


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


@dataclass
class Connection:
    client_id: str
    access_token: str
    refresh_token: str
    scope: str


class OAuthDriver:
    """Drives the browser + client side of the OAuth dance over HTTP."""

    def __init__(self, client: httpx.AsyncClient):
        self.c = client

    async def register(self, redirect: str = REDIRECT, **extra: Any) -> httpx.Response:
        body = {
            "redirect_uris": [redirect],
            "client_name": "Claude",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            **extra,
        }
        return await self.c.post("/register", json=body)

    async def client_id(self) -> str:
        r = await self.register()
        assert r.status_code == 201, r.text
        return r.json()["client_id"]

    async def start(
        self, client_id: str, *, scope: str | None = None, challenge: str | None = None,
        redirect: str = REDIRECT, resource: str | None = f"{BASE}/mcp",
    ) -> tuple[httpx.Response, str]:
        verifier, ch = pkce()
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect,
            "code_challenge": challenge or ch,
            "code_challenge_method": "S256",
            "state": "st4te",
        }
        if scope:
            params["scope"] = scope
        if resource:
            params["resource"] = resource
        return await self.c.get("/authorize", params=params), verifier

    @staticmethod
    def request_id(authorize_response: httpx.Response) -> str:
        loc = authorize_response.headers["location"]
        return parse_qs(urlsplit(loc).query)["request"][0]

    async def consent(
        self, request_id: str, password: str = PASSWORD, *, allow_write: bool = False,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        data = {"request": request_id, "password": password}
        if allow_write:
            data["allow_write"] = "1"
        return await self.c.post("/oauth/login", data=data, headers=headers or {})

    async def exchange(self, client_id: str, code: str, verifier: str,
                       redirect: str = REDIRECT) -> httpx.Response:
        return await self.c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": f"{BASE}/mcp",
            },
        )

    async def connect(self, *, allow_write: bool = False) -> Connection:
        cid = await self.client_id()
        auth, verifier = await self.start(cid)
        assert auth.status_code == 302, auth.text
        ok = await self.consent(self.request_id(auth), allow_write=allow_write)
        assert ok.status_code == 302, ok.text
        code = parse_qs(urlsplit(ok.headers["location"]).query)["code"][0]
        tok = await self.exchange(cid, code, verifier)
        assert tok.status_code == 200, tok.text
        t = tok.json()
        return Connection(cid, t["access_token"], t["refresh_token"], t["scope"])

    async def refresh(self, client_id: str, refresh_token: str,
                      scope: str | None = None) -> httpx.Response:
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token,
                "client_id": client_id}
        if scope:
            data["scope"] = scope
        return await self.c.post("/token", data=data)

    async def rpc(self, token: str | None, method: str, params: dict[str, Any] | None = None,
                  headers: dict[str, str] | None = None) -> httpx.Response:
        h = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": PROTOCOL,
            **(headers or {}),
        }
        if token:
            h["Authorization"] = f"Bearer {token}"
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        return await self.c.post("/mcp", headers=h, json=body)

    async def tool_names(self, token: str) -> set[str]:
        r = await self.rpc(token, "tools/list")
        assert r.status_code == 200, r.text
        return {t["name"] for t in r.json()["result"]["tools"]}

    async def call(self, token: str, name: str, args: dict[str, Any] | None = None
                   ) -> dict[str, Any]:
        r = await self.rpc(token, "tools/call", {"name": name, "arguments": args or {}})
        assert r.status_code == 200, r.text
        return r.json()["result"]

    @staticmethod
    def text(result: dict[str, Any]) -> str:
        return result["content"][0]["text"]

    @staticmethod
    def payload(result: dict[str, Any]) -> Any:
        assert not result.get("isError"), result
        return json.loads(result["content"][0]["text"])


@pytest.fixture
async def http(settings: Settings, make_app: Callable[[Settings], Any]
               ) -> AsyncIterator[OAuthDriver]:
    async with asgi_client(make_app(settings)) as c:
        yield OAuthDriver(c)
