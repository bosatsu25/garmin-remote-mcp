"""Component tests: Garmin token seeding and the GarminService wrapper."""

import base64
import json
import os
import stat

import pytest
from garminconnect import (
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)

from garmin_mcp import garmin_client as gc
from garmin_mcp.garmin_client import (
    MAX_SEED_LENGTH,
    GarminService,
    GarminUnavailable,
    decode_token_seed,
    seed_tokens,
    write_private_file,
)

TOKENS = {"di_token": "a", "di_refresh_token": "b", "di_client_id": "c"}


def b64(obj) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


# ---- seed decoding: EP + BVA ----------------------------------------------------
@pytest.mark.risk("R09")
@pytest.mark.parametrize("raw", [json.dumps(TOKENS), b64(TOKENS), f"  {b64(TOKENS)}\n"])
def test_seed_valid_partitions(raw):
    assert json.loads(decode_token_seed(raw))["di_refresh_token"] == "b"


@pytest.mark.risk("R09")
@pytest.mark.parametrize("raw", [
    "not base64 !!!", b64({"di_token": "a"}), b64({"di_refresh_token": 5}), b64([1, 2]),
    base64.b64encode(b"\xff\xfe").decode(), "{broken json", b64("str"),
])
def test_seed_invalid_partitions(raw):
    with pytest.raises(ValueError):
        decode_token_seed(raw)


@pytest.mark.risk("R07", "R09")
@pytest.mark.parametrize(("length", "ok"), [(MAX_SEED_LENGTH - 1, True), (MAX_SEED_LENGTH, True),
                                            (MAX_SEED_LENGTH + 1, False)])
def test_seed_length_boundary(length, ok):
    base = json.dumps({**TOKENS, "pad": ""})
    raw = base[:-2] + "x" * (length - len(base)) + '"}'
    assert len(raw) == length
    if ok:
        decode_token_seed(raw)
    else:
        with pytest.raises(ValueError, match="too large"):
            decode_token_seed(raw)


# ---- seeding to disk -------------------------------------------------------------
@pytest.mark.risk("R06")
def test_seed_written_0600_in_0700_dir(tmp_path):
    seed_tokens(tmp_path / "garmin", b64(TOKENS))
    f = tmp_path / "garmin" / "garmin_tokens.json"
    assert json.loads(f.read_text()) == TOKENS
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(f.parent).st_mode) == 0o700


@pytest.mark.risk("R06")
def test_private_file_never_world_readable_even_with_permissive_umask(tmp_path):
    old = os.umask(0)
    try:
        write_private_file(tmp_path / "x" / "f.json", "{}")
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(tmp_path / "x" / "f.json").st_mode) == 0o600


@pytest.mark.risk("R06")
def test_private_file_does_not_follow_symlink_target(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    link = tmp_path / "link.json"
    link.symlink_to(victim)
    write_private_file(link, "{}")         # replaces the link itself, atomically
    assert victim.read_text() == "keep"
    assert not link.is_symlink()


@pytest.mark.risk("R13")
def test_existing_tokens_win_over_seed(tmp_path):
    d = tmp_path / "garmin"
    seed_tokens(d, b64(TOKENS))
    (d / "garmin_tokens.json").write_text(json.dumps({**TOKENS, "di_token": "refreshed"}))
    seed_tokens(d, b64({**TOKENS, "di_token": "stale-seed"}))
    assert json.loads((d / "garmin_tokens.json").read_text())["di_token"] == "refreshed"


@pytest.mark.risk("R06")
def test_seed_refuses_dangling_symlink(tmp_path):
    d = tmp_path / "garmin"
    d.mkdir()
    (d / "garmin_tokens.json").symlink_to(tmp_path / "attacker-file")
    seed_tokens(d, b64(TOKENS))
    assert not (tmp_path / "attacker-file").exists()


@pytest.mark.risk("R09")
def test_no_seed_no_file(tmp_path):
    seed_tokens(tmp_path / "garmin", None)
    assert not (tmp_path / "garmin").exists()


# ---- GarminService ---------------------------------------------------------------
class StubGarmin:
    instances = 0

    def __init__(self, *a, **kw):
        StubGarmin.instances += 1
        self.calls = 0

    def login(self, tokenstore=None):
        if StubGarmin.login_error:
            raise StubGarmin.login_error


@pytest.fixture
def service(tmp_path, monkeypatch):
    StubGarmin.instances = 0
    StubGarmin.login_error = None
    monkeypatch.setattr(gc, "Garmin", StubGarmin)
    d = tmp_path / "garmin"
    seed_tokens(d, b64(TOKENS))
    return GarminService(d)


@pytest.mark.risk("R09")
def test_missing_tokens_is_actionable(tmp_path):
    with pytest.raises(GarminUnavailable, match="garmin-mcp-login"):
        GarminService(tmp_path / "none").call_sync(lambda g: 1)


@pytest.mark.risk("R06")
def test_login_is_token_only(service, monkeypatch):
    seen = {}

    class Spy(StubGarmin):
        def __init__(self, *a, **kw):
            seen["args"], seen["kw"] = a, kw
            super().__init__()

    monkeypatch.setattr(gc, "Garmin", Spy)
    service.call_sync(lambda g: None)
    assert seen == {"args": (), "kw": {}}        # never given email/password


@pytest.mark.risk("R10")
def test_client_is_reused(service):
    service.call_sync(lambda g: None)
    service.call_sync(lambda g: None)
    assert StubGarmin.instances == 1


@pytest.mark.risk("R10")
@pytest.mark.parametrize(("err", "match"), [
    (GarminConnectTooManyRequestsError("x"), "rate limiting"),
    (GarminConnectAuthenticationError("x"), "rejected the stored tokens"),
    (GarminConnectConnectionError("x"), "rejected the stored tokens"),
])
def test_login_failures_are_mapped(service, err, match):
    StubGarmin.login_error = err
    with pytest.raises(GarminUnavailable, match=match):
        service.call_sync(lambda g: None)


@pytest.mark.risk("R04")
def test_auth_error_during_call_retries_once_with_fresh_client(service):
    calls = []

    def fn(g):
        calls.append(g)
        if len(calls) == 1:
            raise GarminConnectAuthenticationError("expired")
        return "ok"

    assert service.call_sync(fn) == "ok"
    assert StubGarmin.instances == 2
    assert calls[0] is not calls[1]


@pytest.mark.risk("R04")
def test_auth_error_twice_gives_up(service):
    def fn(g):
        raise GarminConnectAuthenticationError("dead")

    with pytest.raises(GarminUnavailable, match="authentication failed"):
        service.call_sync(fn)
    assert StubGarmin.instances == 2              # exactly one retry, no loop


@pytest.mark.risk("R10")
def test_rate_limit_during_call(service):
    def fn(g):
        raise GarminConnectTooManyRequestsError("429")

    with pytest.raises(GarminUnavailable, match="429"):
        service.call_sync(fn)


@pytest.mark.risk("R10")
async def test_async_call_runs_in_thread(service):
    import threading

    main = threading.get_ident()
    tid = await service.call(lambda g: threading.get_ident())
    assert tid != main
