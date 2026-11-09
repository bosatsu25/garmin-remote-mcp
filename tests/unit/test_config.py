"""Component tests: configuration fails closed.

Techniques: equivalence partitioning (EP), 3-value boundary value analysis (BVA),
decision table (DT).
"""

import logging

import pytest

from garmin_mcp.config import (
    DEFAULT_REDIRECT_HOSTS,
    MAX_OWNER_PASSWORD_LENGTH,
    MIN_OWNER_PASSWORD_LENGTH,
    ConfigError,
    Settings,
    load_owner_secret,
    validate_public_url,
)
from garmin_mcp.security import hash_owner_password

pytestmark = pytest.mark.risk("R09")

GOOD_PW = "p" * MIN_OWNER_PASSWORD_LENGTH


def env(**kw):
    base = {"PUBLIC_URL": "https://x.example.com", "OWNER_PASSWORD": GOOD_PW}
    base.update({k: v for k, v in kw.items() if v is not None})
    return {k: v for k, v in base.items() if v != "<unset>"}


@pytest.fixture(autouse=True)
def _fast_scrypt(monkeypatch):
    # from_plaintext's default N is deliberately slow; unit tests do not need it.
    import garmin_mcp.security as sec

    real = sec.OwnerSecret.from_plaintext.__func__

    monkeypatch.setattr(
        sec.OwnerSecret, "from_plaintext",
        classmethod(lambda cls, pw, n=2**14: real(cls, pw, n=n)),
    )


# --- PUBLIC_URL: EP --------------------------------------------------------------
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://x.example.com", "https://x.example.com"),
        ("https://x.example.com/", "https://x.example.com"),
        ("  https://x.example.com  ", "https://x.example.com"),
        ("https://x.example.com:8443", "https://x.example.com:8443"),
        ("http://localhost:8000", "http://localhost:8000"),
        ("http://127.0.0.1", "http://127.0.0.1"),
    ],
)
def test_public_url_valid_partitions(raw, expected):
    assert validate_public_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",                                   # empty
        "x.example.com",                      # no scheme
        "http://x.example.com",               # plaintext to a public host
        "ftp://x.example.com",                # wrong scheme
        "https://",                           # no host
        "https://user:pw@x.example.com",      # credentials
        "https://x.example.com/mcp",          # path (resource URL would be wrong)
        "https://x.example.com?a=1",          # query
        "https://x.example.com#f",            # fragment
        "https://x.example.com:99999",        # invalid port
        "http://localhost.evil.com",          # looks local, is not
    ],
)
def test_public_url_invalid_partitions(raw):
    with pytest.raises(ConfigError):
        validate_public_url(raw)


# --- owner password: BVA on both ends -------------------------------------------
@pytest.mark.parametrize(
    ("length", "ok"),
    [
        (MIN_OWNER_PASSWORD_LENGTH - 1, False),
        (MIN_OWNER_PASSWORD_LENGTH, True),
        (MIN_OWNER_PASSWORD_LENGTH + 1, True),
        (MAX_OWNER_PASSWORD_LENGTH - 1, True),
        (MAX_OWNER_PASSWORD_LENGTH, True),
        (MAX_OWNER_PASSWORD_LENGTH + 1, False),
    ],
)
def test_owner_password_length_boundaries(length, ok):
    e = {"OWNER_PASSWORD": "a" * length}
    if ok:
        assert load_owner_secret(e).verify("a" * length)
    else:
        with pytest.raises(ConfigError):
            load_owner_secret(e)


# --- secret source: decision table ------------------------------------------------
#  hash set | plain set | outcome
#  T        | T         | error (ambiguous)
#  T        | F         | hash used
#  F        | T         | plain used + warning
#  F        | F         | error
def test_dt_both_hash_and_plain_is_rejected():
    with pytest.raises(ConfigError, match="only one"):
        load_owner_secret({"OWNER_PASSWORD_HASH": hash_owner_password(GOOD_PW, n=2**14),
                           "OWNER_PASSWORD": GOOD_PW})


def test_dt_hash_only_is_used():
    s = load_owner_secret({"OWNER_PASSWORD_HASH": hash_owner_password(GOOD_PW, n=2**14)})
    assert s.verify(GOOD_PW)
    assert not s.verify(GOOD_PW + "x")


def test_dt_plain_only_warns(caplog):
    with caplog.at_level(logging.WARNING):
        assert load_owner_secret({"OWNER_PASSWORD": GOOD_PW}).verify(GOOD_PW)
    assert "OWNER_PASSWORD_HASH" in caplog.text
    assert GOOD_PW not in caplog.text


def test_dt_neither_is_rejected():
    with pytest.raises(ConfigError, match="required"):
        load_owner_secret({})


def test_malformed_hash_is_a_config_error():
    with pytest.raises(ConfigError):
        load_owner_secret({"OWNER_PASSWORD_HASH": "bcrypt$nope"})


# --- booleans: EP ---------------------------------------------------------------
@pytest.mark.parametrize("raw", ["1", "true", "TRUE", " yes ", "on"])
def test_bool_true_partition(raw):
    assert Settings.from_env(env(GARMIN_ENABLE_RAW_API=raw)).enable_raw_api is True


@pytest.mark.parametrize("raw", ["0", "false", "No", "off"])
def test_bool_false_partition(raw):
    assert Settings.from_env(env(GARMIN_ALLOW_WRITE=raw)).allow_write is False


@pytest.mark.parametrize("raw", ["ture", "2", "enabled", "y"])
def test_bool_invalid_partition_fails_closed(raw):
    with pytest.raises(ConfigError):
        Settings.from_env(env(GARMIN_ALLOW_WRITE=raw))


def test_secure_defaults():
    s = Settings.from_env(env())
    assert s.enable_raw_api is False
    assert s.trust_fly_client_ip is False
    assert s.allowed_redirect_hosts == DEFAULT_REDIRECT_HOSTS
    assert s.access_token_ttl <= 3600


# --- PORT: BVA ---------------------------------------------------------------------
@pytest.mark.parametrize(("port", "ok"), [("0", False), ("1", True), ("2", True),
                                          ("65534", True), ("65535", True), ("65536", False),
                                          ("http", False), ("-1", False)])
def test_port_boundaries(port, ok):
    if ok:
        assert Settings.from_env(env(PORT=port)).port == int(port)
    else:
        with pytest.raises(ConfigError):
            Settings.from_env(env(PORT=port))


# --- Fly-Client-IP trust: decision table ------------------------------------------
@pytest.mark.parametrize(
    ("fly_app", "override", "expected"),
    [
        (None, None, False),        # not on Fly: header is attacker-controlled
        ("app", None, True),        # on Fly: proxy overwrites the header
        ("app", "false", False),    # explicit opt-out wins
        (None, "true", True),       # explicit opt-in wins
    ],
)
def test_dt_trust_fly_client_ip(fly_app, override, expected):
    s = Settings.from_env(env(FLY_APP_NAME=fly_app, TRUST_FLY_CLIENT_IP=override))
    assert s.trust_fly_client_ip is expected


# --- redirect allowlist ------------------------------------------------------------
@pytest.mark.parametrize("raw", ["*.claude.ai", "claude.ai:443", "https://claude.ai"])
def test_redirect_hosts_reject_patterns(raw):
    with pytest.raises(ConfigError):
        Settings.from_env(env(ALLOWED_REDIRECT_HOSTS=raw))


def test_redirect_hosts_custom_list_normalized():
    s = Settings.from_env(env(ALLOWED_REDIRECT_HOSTS=" Claude.AI , localhost ,"))
    assert s.allowed_redirect_hosts == ("claude.ai", "localhost")


@pytest.mark.risk("R06")
def test_settings_repr_hides_secrets():
    s = Settings.from_env(env(GARMIN_TOKENS='{"di_refresh_token":"SEKRIT"}'))
    text = repr(s)
    assert "SEKRIT" not in text
    assert GOOD_PW not in text
    assert "owner_secret" not in text


def test_password_with_control_chars_rejected():
    with pytest.raises(ConfigError, match="control"):
        load_owner_secret({"OWNER_PASSWORD": GOOD_PW + "\n"})
