"""Component tests: credential redaction (EP + property-based)."""

import json
import secrets

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from garmin_mcp.security import redact

pytestmark = pytest.mark.risk("R06")

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2lnbmF0dXJl"


@pytest.mark.parametrize(
    "text",
    [
        f"401 for url with token {JWT}",
        f"Authorization: Bearer {secrets.token_urlsafe(32)}",
        f"auth basic {secrets.token_urlsafe(16)}",
        json.dumps({"di_refresh_token": "abc123SECRET", "x": 1}),
        "access_token=abc123SECRET&scope=x",
        "password: hunter2hunter2",
        f"blob {secrets.token_hex(32)}",
    ],
)
def test_secret_partitions_are_redacted(text):
    out = redact(text)
    assert "[REDACTED]" in out
    for needle in ("abc123SECRET", "hunter2hunter2", JWT):
        assert needle not in out


@pytest.mark.parametrize(
    "text",
    [
        "Garmin rate limit hit (429). Retry later.",
        "date range is limited to 93 days per call",
        "Not found: /usersummary-service/usersummary/daily/2026-11-09",
        "",
    ],
)
def test_benign_partitions_untouched(text):
    assert redact(text) == text


@settings(max_examples=200, deadline=None)
@given(
    prefix=st.text(max_size=40),
    suffix=st.text(max_size=40),
    nbytes=st.integers(min_value=32, max_value=64),
)
def test_property_long_random_tokens_never_survive(prefix, suffix, nbytes):
    tok = secrets.token_urlsafe(nbytes)
    assert tok not in redact(f"{prefix} {tok} {suffix}")


def test_long_path_segments_survive():
    # Regression: the first blob pattern also ate whole API paths.
    p = "/userprofile-service/socialProfile/activities/search/2026-11-09"
    assert redact(f"404 {p}") == f"404 {p}"


def test_redaction_is_linear_time():
    import time

    big = "a" * 200_000 + "!"
    t = time.perf_counter()
    redact(big)
    assert time.perf_counter() - t < 1.0
