"""Acceptance tests (ATDD, JSTQB FL §4.5.3): owner user stories as Given/When/Then.

US-1 As the owner, I connect claude.ai read-only and ask about last night's sleep.
US-2 As the owner, I explicitly grant write access and Claude puts a workout on my watch.
US-3 As the owner, if my refresh token is stolen and used, every session in that grant dies.
US-4 As the owner, someone guessing my passphrase is locked out and cannot get a token.
US-5 As the owner, a read-only connection cannot be talked into deleting my workouts.
"""


import pytest

from ..conftest import PASSWORD


@pytest.mark.risk("R01", "R04", "R12")
async def test_us1_read_only_connection_reads_sleep(http, fake):
    # Given the owner connects claude.ai without ticking the write box
    conn = await http.connect(allow_write=False)
    # When Claude asks for last night's sleep
    res = await http.call(conn.access_token, "get_sleep", {"date": "2026-11-09"})
    # Then it gets a compact summary
    out = http.payload(res)
    assert out["dailySleepDTO"]["sleepTimeSeconds"] == 25200
    # And nothing in Garmin was changed
    assert fake.uploaded == []
    assert fake.deleted == []


@pytest.mark.risk("R05", "R11")
async def test_us2_write_grant_creates_scheduled_workout(http, fake):
    # Given the owner ticks "allow writes" on the consent page
    conn = await http.connect(allow_write=True)
    assert "garmin:write" in conn.scope
    # When Claude creates a 5x1km interval session for tomorrow
    res = await http.call(conn.access_token, "create_workout", {
        "name": "5x1km", "sport": "running", "schedule_date": "2026-11-10",
        "steps": [
            {"type": "warmup", "end": "time", "seconds": 600},
            {"type": "repeat", "iterations": 5, "steps": [
                {"type": "interval", "end": "distance", "meters": 1000,
                 "target": {"kind": "pace", "pace_fast": "3:50", "pace_slow": "4:00"}},
                {"type": "recovery", "end": "time", "seconds": 90}]},
            {"type": "cooldown", "end": "lap_button"},
        ]})
    # Then the workout exists in Garmin and is on the calendar
    assert http.payload(res)["scheduled"]["date"] == "2026-11-10"
    assert fake.scheduled == [(42, "2026-11-10")]
    steps = fake.uploaded[0]["workoutSegments"][0]["workoutSteps"]
    assert steps[1]["numberOfIterations"] == 5


@pytest.mark.risk("R03")
async def test_us3_stolen_refresh_token_kills_the_grant(http):
    # Given the owner is connected and a thief copied the refresh token
    conn = await http.connect()
    stolen = conn.refresh_token
    # When the owner's client refreshes normally
    owner = (await http.refresh(conn.client_id, conn.refresh_token)).json()
    # And the thief then tries the copied token
    thief = await http.refresh(conn.client_id, stolen)
    # Then the thief is refused
    assert thief.status_code == 400
    # And the owner's current session is revoked too, forcing a fresh consent
    assert (await http.rpc(owner["access_token"], "tools/list")).status_code == 401
    # And reconnecting with the passphrase works again
    again = await http.connect()
    assert (await http.rpc(again.access_token, "tools/list")).status_code == 200


@pytest.mark.risk("R01")
async def test_us4_password_guessing_is_locked_out(http):
    # Given an attacker started an authorization request
    cid = await http.client_id()
    auth, _ = await http.start(cid)
    rid = http.request_id(auth)
    # When they try five wrong passphrases
    for guess in ["password", "garmin", "123456", "letmein", "owner"]:
        assert (await http.consent(rid, guess)).status_code == 401
    # Then even the right passphrase is refused for now
    r = await http.consent(rid, PASSWORD)
    assert r.status_code == 429
    # And no authorization code was ever issued
    assert "code=" not in r.headers.get("location", "")


@pytest.mark.risk("R05")
async def test_us5_read_only_connection_cannot_delete(http, fake):
    # Given a read-only connection (e.g. a prompt-injected activity description tells
    # the model to clean up workouts)
    conn = await http.connect(allow_write=False)
    # When the model calls the destructive tool anyway
    res = await http.call(conn.access_token, "delete_workout", {"workout_id": 42})
    # Then the server refuses regardless of what the model was told
    assert res["isError"] is True
    assert fake.deleted == []
