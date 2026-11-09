"""Component integration tests: MCP tools behind real OAuth tokens.

Decision table for write tools (R05):

  rule | GARMIN_ALLOW_WRITE | token has garmin:write | tool listed | call succeeds | Garmin mutated
  1    | T                  | T                      | yes         | yes           | yes
  2    | T                  | F                      | yes         | no (error)    | no
  3    | F                  | T (impossible: consent drops it; forced here)    | no | no | no
  4    | F                  | F                      | no          | no            | no
"""

import json

import pytest
from garminconnect import GarminConnectConnectionError

from garmin_mcp.garmin_client import GarminUnavailable
from garmin_mcp.oauth import SCOPE_READ, SCOPE_WRITE, token_hash

from ..conftest import OAuthDriver, asgi_client

WRITE_TOOLS = {"create_workout", "schedule_workout", "unschedule_workout", "delete_workout"}
EASY_RUN = {
    "name": "Easy 30",
    "sport": "running",
    "steps": [{"type": "interval", "end": "time", "seconds": 1800,
               "target": {"kind": "hr_zone", "zone": 2}}],
}
WRITE_CALLS = [
    ("create_workout", EASY_RUN),
    ("schedule_workout", {"workout_id": 42, "date": "2026-11-10"}),
    ("unschedule_workout", {"scheduled_workout_id": 7}),
    ("delete_workout", {"workout_id": 42}),
]


def mutated(fake) -> bool:
    return bool(fake.uploaded or fake.scheduled or fake.unscheduled or fake.deleted)


# ------------------------------------------------------- write authorization
@pytest.mark.risk("R05")
@pytest.mark.parametrize(("tool", "args"), WRITE_CALLS)
async def test_dt_rule1_write_enabled_and_granted(http, fake, tool, args):
    conn = await http.connect(allow_write=True)
    res = await http.call(conn.access_token, tool, args)
    assert not res.get("isError"), res
    assert mutated(fake)


@pytest.mark.risk("R05")
@pytest.mark.parametrize(("tool", "args"), WRITE_CALLS)
async def test_dt_rule2_write_enabled_but_read_only_grant(http, fake, tool, args):
    conn = await http.connect(allow_write=False)
    assert await http.tool_names(conn.access_token) >= WRITE_TOOLS
    res = await http.call(conn.access_token, tool, args)
    assert res["isError"] is True
    assert "read-only" in http.text(res)
    assert not mutated(fake)


@pytest.mark.risk("R05")
async def test_dt_rule3_write_disabled_even_with_forged_write_scope(make_settings, make_app, fake):
    app = make_app(make_settings(allow_write=False))
    async with asgi_client(app) as c:
        d = OAuthDriver(c)
        conn = await d.connect()
        # Simulate a token that somehow carries garmin:write (e.g. from an old config).
        app.provider._access[token_hash(conn.access_token)]["scopes"] = [SCOPE_READ, SCOPE_WRITE]
        names = await d.tool_names(conn.access_token)
        assert not (WRITE_TOOLS & names)
        for tool, args in WRITE_CALLS:
            res = await d.call(conn.access_token, tool, args)
            assert res["isError"] is True
        assert not mutated(fake)


@pytest.mark.risk("R05")
async def test_dt_rule4_write_disabled_read_only(make_settings, make_app, fake):
    async with asgi_client(make_app(make_settings(allow_write=False))) as c:
        d = OAuthDriver(c)
        conn = await d.connect()
        assert not (WRITE_TOOLS & await d.tool_names(conn.access_token))


@pytest.mark.risk("R05")
async def test_write_tools_carry_safety_annotations(http):
    conn = await http.connect(allow_write=True)
    tools = (await http.rpc(conn.access_token, "tools/list")).json()["result"]["tools"]
    ann = {t["name"]: t.get("annotations", {}) for t in tools}
    for name in ("delete_workout", "unschedule_workout"):
        assert ann[name]["destructiveHint"] is True
    for name in ("create_workout", "schedule_workout"):
        assert ann[name]["readOnlyHint"] is False
    for name, a in ann.items():
        if name not in WRITE_TOOLS:
            assert a["readOnlyHint"] is True, name


@pytest.mark.risk("R05")
async def test_read_tools_never_mutate(http, fake):
    conn = await http.connect(allow_write=True)
    names = await http.tool_names(conn.access_token)
    failures: list[str] = []
    for name in sorted(names - WRITE_TOOLS):
        args = {"start": "2026-11-01"} if name.endswith("_range") or name in {
            "get_body_battery", "get_body_composition", "get_endurance_score", "get_calendar"
        } else {"workout_id": 1} if name == "get_workout" else {
            "activity_id": 1} if name == "get_activity" else {}
        res = await http.call(conn.access_token, name, args)
        failures.append(name) if res.get("isError") else None
    assert not mutated(fake)
    assert failures == [], f"read tools failed against the fake: {failures}"


# ------------------------------------------------------------- raw API flag
@pytest.mark.risk("R10")
@pytest.mark.parametrize(("enabled", "listed"), [(False, False), (True, True)])
async def test_raw_api_flag(make_settings, make_app, enabled, listed):
    async with asgi_client(make_app(make_settings(enable_raw_api=enabled))) as c:
        d = OAuthDriver(c)
        conn = await d.connect()
        assert ("garmin_api_get" in await d.tool_names(conn.access_token)) is listed


@pytest.mark.risk("R10")
@pytest.mark.parametrize(("path", "ok"), [
    ("/usersummary-service/usersummary/daily/2026-11-09", True),
    ("//evil.example/x", False),
    ("/a/../b", False),
    ("/x\n", False),
])
async def test_raw_api_path_validation_end_to_end(make_settings, make_app, fake, path, ok):
    async with asgi_client(make_app(make_settings(enable_raw_api=True))) as c:
        d = OAuthDriver(c)
        conn = await d.connect()
        res = await d.call(conn.access_token, "garmin_api_get", {"path": path})
        assert bool(res.get("isError")) is not ok
        assert (fake.api_calls != []) is ok


@pytest.mark.risk("R07", "R10")
@pytest.mark.parametrize(("n", "ok"), [(20, True), (21, False)])
async def test_raw_api_param_count_boundary(make_settings, make_app, n, ok):
    async with asgi_client(make_app(make_settings(enable_raw_api=True))) as c:
        d = OAuthDriver(c)
        conn = await d.connect()
        res = await d.call(conn.access_token, "garmin_api_get",
                           {"path": "/a", "params": {f"k{i}": "v" for i in range(n)}})
        assert bool(res.get("isError")) is not ok


# ----------------------------------------------------------- input boundaries
@pytest.mark.risk("R10")
@pytest.mark.parametrize(("limit", "ok"), [(0, False), (1, True), (2, True), (99, True),
                                           (100, True), (101, False)])
async def test_list_activities_limit_boundary(http, limit, ok):
    conn = await http.connect()
    res = await http.call(conn.access_token, "list_activities", {"limit": limit})
    if ok:
        items = http.payload(res)
        assert len(items) == limit                 # regression: was silently capped at 60
        assert all(isinstance(i, dict) for i in items)
    else:
        assert res["isError"] is True


@pytest.mark.risk("R10")
@pytest.mark.parametrize(("wid", "ok"), [(0, False), (1, True), (2**63 - 1, True), (2**63, False),
                                         (-1, False), ("1; DROP", False)])
async def test_id_boundaries(http, wid, ok):
    conn = await http.connect()
    res = await http.call(conn.access_token, "get_workout", {"workout_id": wid})
    assert bool(res.get("isError")) is not ok


@pytest.mark.risk("R10")
@pytest.mark.parametrize(("end", "ok"), [
    ("2026-04-03", True),    # +92 days
    ("2026-04-04", True),    # +93 days (limit)
    ("2026-04-05", False),   # +94 days
])
async def test_range_boundary_through_protocol(http, end, ok):
    conn = await http.connect()
    res = await http.call(conn.access_token, "get_sleep_range",
                          {"start": "2026-01-01", "end": end})
    assert bool(res.get("isError")) is not ok


@pytest.mark.risk("R11")
@pytest.mark.parametrize(("name", "ok"), [("", False), ("a", True), ("a" * 80, True),
                                          ("a" * 81, False)])
async def test_workout_name_boundary(http, fake, name, ok):
    conn = await http.connect(allow_write=True)
    res = await http.call(conn.access_token, "create_workout", {**EASY_RUN, "name": name})
    assert bool(res.get("isError")) is not ok
    assert bool(fake.uploaded) is ok


@pytest.mark.risk("R11")
async def test_create_and_schedule(http, fake):
    conn = await http.connect(allow_write=True)
    res = await http.call(conn.access_token, "create_workout",
                          {**EASY_RUN, "schedule_date": "2026-11-10"})
    out = http.payload(res)
    assert out == {"workoutId": 42, "workoutName": "Easy 30",
                   "scheduled": {"date": "2026-11-10", "scheduledWorkoutId": 7}}
    step = fake.uploaded[0]["workoutSegments"][0]["workoutSteps"][0]
    assert step["zoneNumber"] == 2


@pytest.mark.risk("R11")
async def test_bad_schedule_date_creates_nothing(http, fake):
    conn = await http.connect(allow_write=True)
    res = await http.call(conn.access_token, "create_workout",
                          {**EASY_RUN, "schedule_date": "2026-02-30"})
    assert res["isError"] is True
    assert fake.uploaded == []          # validated before any write


@pytest.mark.risk("R11")
@pytest.mark.parametrize("sport", ["swimming", "strength_training"])
async def test_unsupported_sport_rejected_by_schema(http, fake, sport):
    conn = await http.connect(allow_write=True)
    res = await http.call(conn.access_token, "create_workout", {**EASY_RUN, "sport": sport})
    assert res["isError"] is True
    assert fake.uploaded == []


# --------------------------------------------------------------- redaction
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvd25lciIsImV4cCI6OTk5fQ.c2lnbmF0dXJlc2lnbmF0dXJlc2ln"


@pytest.mark.risk("R06")
@pytest.mark.parametrize("exc", [
    GarminConnectConnectionError(f"401 for https://connectapi.garmin.com/x Authorization: Bearer {JWT}"),
    GarminUnavailable(f'Garmin rejected the stored tokens. Detail: {{"di_refresh_token": "{JWT}"}}'),
    ValueError(f"bad response body: {JWT}"),
])
async def test_errors_never_leak_tokens(http, fake, exc):
    conn = await http.connect()
    fake.fail_with = exc
    res = await http.call(conn.access_token, "get_daily_summary")
    assert res["isError"] is True
    text = http.text(res)
    assert JWT not in text
    assert JWT.split(".")[2] not in text
    assert "[REDACTED]" in text


@pytest.mark.risk("R06")
async def test_error_length_capped(http, fake):
    conn = await http.connect()
    fake.fail_with = GarminConnectConnectionError("x " * 5000)
    res = await http.call(conn.access_token, "get_daily_summary")
    assert len(http.text(res)) <= 600


@pytest.mark.risk("R06")
async def test_audit_log_has_no_secrets(http, caplog):
    import logging

    with caplog.at_level(logging.DEBUG):
        conn = await http.connect()
        await http.refresh(conn.client_id, conn.refresh_token)
    assert "owner_approved" in caplog.text
    for secret in (conn.access_token, conn.refresh_token, "correct horse battery staple"):
        assert secret not in caplog.text


# ---------------------------------------------------------------- compaction
@pytest.mark.risk("R12")
async def test_sleep_compacted_by_default_raw_on_request(http):
    conn = await http.connect()
    small = http.payload(await http.call(conn.access_token, "get_sleep"))
    assert "sleepLevels" not in small
    assert small["dailySleepDTO"]["sleepTimeSeconds"] == 25200
    full = http.payload(await http.call(conn.access_token, "get_sleep", {"raw": True}))
    assert len(full["sleepLevels"]) == 500


@pytest.mark.risk("R12")
async def test_profile_and_default_date(http):
    conn = await http.connect()
    prof = http.payload(await http.call(conn.access_token, "get_profile"))
    assert prof["today"] == "2026-11-09"
    assert prof["devices"] == [{"productDisplayName": "Forerunner", "deviceId": 1}]
    summ = http.payload(await http.call(conn.access_token, "get_daily_summary"))
    assert summ == {"calendarDate": "2026-11-09", "totalSteps": 12345}


@pytest.mark.risk("R12")
async def test_hrv_compacted(http):
    conn = await http.connect()
    out = http.payload(await http.call(conn.access_token, "get_hrv"))
    assert out == {"hrvSummary": {"lastNightAvg": 55}}
    raw = json.loads(http.text(await http.call(conn.access_token, "get_hrv", {"raw": True})))
    assert len(raw["hrvReadings"]) == 300


@pytest.mark.risk("R10", "R12")
@pytest.mark.parametrize("args", [{"start": "2026-11-01"}, {"start": "2026-11-01", "end": "2026-11-09"}])
async def test_list_activities_by_date(http, args):
    conn = await http.connect()
    assert len(http.payload(await http.call(conn.access_token, "list_activities", args))) == 3


@pytest.mark.risk("R12")
@pytest.mark.parametrize("splits", [True, False])
async def test_get_activity_splits_toggle_and_missing_hr_zones(http, fake, splits):
    conn = await http.connect()

    def no_zones(aid):
        raise GarminConnectConnectionError("404")

    fake.get_activity_hr_in_timezones = no_zones
    out = http.payload(await http.call(conn.access_token, "get_activity",
                                       {"activity_id": 5, "include_splits": splits}))
    assert out["activity"]["activityId"] == 5
    assert ("laps" in out) is splits
    assert "hr_zones" not in out
