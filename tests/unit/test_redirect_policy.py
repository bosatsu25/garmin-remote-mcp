"""Component tests: OAuth redirect URI policy.

Decision table (scheme x host allowlisted x host is loopback):

  rule | scheme | allowlisted | loopback | result
  1    | https  | T           | F        | allow
  2    | https  | T           | T        | allow
  3    | https  | F           | -        | deny
  4    | http   | T           | T        | allow (native app callback)
  5    | http   | T           | F        | deny  (plaintext to public host)
  6    | http   | F           | -        | deny
  7    | other  | -           | -        | deny

Plus fault attacks (error guessing, §4.4.1) from known open-redirect bypasses, and a
property-based test that no accepted URI ever points outside the allowlist.
"""

from urllib.parse import urlsplit

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from garmin_mcp.security import MAX_REDIRECT_URI_LENGTH, redirect_uri_allowed

pytestmark = pytest.mark.risk("R02")

HOSTS = ("claude.ai", "claude.com", "localhost", "127.0.0.1")


@pytest.mark.parametrize(
    ("rule", "uri", "expected"),
    [
        (1, "https://claude.ai/api/mcp/auth_callback", True),
        (2, "https://localhost/cb", True),
        (3, "https://evil.example/cb", False),
        (4, "http://localhost:33418/callback", True),
        (4, "http://127.0.0.1:6274/oauth/callback", True),
        (5, "http://claude.ai/api/mcp/auth_callback", False),
        (6, "http://evil.example/cb", False),
        (7, "javascript://claude.ai/%0aalert(1)", False),
        (7, "claude://callback", False),
        (7, "file://claude.ai/etc/passwd", False),
    ],
)
def test_decision_table(rule, uri, expected):
    assert redirect_uri_allowed(uri, HOSTS) is expected, f"rule {rule}"


@pytest.mark.parametrize(
    "uri",
    [
        "https://claude.ai@evil.example/cb",          # userinfo makes evil the host
        "https://evil.example@claude.ai/cb",          # userinfo at all
        "https://claude.ai:x@claude.ai/cb",
        "https://claude.ai.evil.example/cb",          # suffix trick
        "https://evilclaude.ai/cb",                   # prefix trick
        "https://claude.ai%2eevil.example/cb",        # encoded dot
        "https://claude.ai\\@evil.example/cb",        # backslash parser differential
        "https://claude.ai/cb#@evil.example",         # fragment
        "https://claude.ai/cb#",
        "https://claude.ai\t.evil.example/cb",        # control characters
        "https://claude.ai\n/cb",
        "https://claude.ai /cb",
        "https://claude.ai:99999/cb",                 # bad port
        "https://[::1]/cb",                           # ip literal not on list
        "https:///claude.ai/cb",                      # empty host
        "//claude.ai/cb",                             # scheme-relative
        "https://claude.ai/" + "a" * MAX_REDIRECT_URI_LENGTH,  # overlong
    ],
)
def test_fault_attacks_rejected(uri):
    assert redirect_uri_allowed(uri, HOSTS) is False


@pytest.mark.parametrize(
    ("length", "ok"),
    [(MAX_REDIRECT_URI_LENGTH - 1, True), (MAX_REDIRECT_URI_LENGTH, True),
     (MAX_REDIRECT_URI_LENGTH + 1, False)],
)
def test_length_boundary(length, ok):
    prefix = "https://claude.ai/"
    uri = prefix + "a" * (length - len(prefix))
    assert len(uri) == length
    assert redirect_uri_allowed(uri, HOSTS) is ok


def test_host_comparison_is_case_insensitive():
    assert redirect_uri_allowed("https://CLAUDE.AI/cb", HOSTS)
    assert redirect_uri_allowed("https://claude.ai/cb", ("Claude.AI",))


def test_non_string_rejected():
    assert redirect_uri_allowed(None, HOSTS) is False  # type: ignore[arg-type]


@settings(max_examples=500, deadline=None)
@given(st.text(min_size=0, max_size=120))
def test_property_accepted_uris_stay_on_allowlist(uri):
    if redirect_uri_allowed(uri, HOSTS):
        parts = urlsplit(uri)
        assert parts.hostname in HOSTS
        assert parts.username is None
        assert not parts.fragment


@settings(max_examples=300, deadline=None)
@given(
    scheme=st.sampled_from(["https", "http", "ftp", "javascript", ""]),
    userinfo=st.sampled_from(["", "a@", "claude.ai@", "x:y@"]),
    host=st.sampled_from([*HOSTS, "evil.example", "claude.ai.evil", ""]),
    path=st.text(alphabet="abc/._-%?=&", max_size=30),
)
def test_property_structured(scheme, userinfo, host, path):
    uri = f"{scheme}://{userinfo}{host}/{path}"
    ok = redirect_uri_allowed(uri, HOSTS)
    if ok:
        assert userinfo == ""
        assert host in HOSTS
        assert scheme == "https" or (scheme == "http" and host in ("localhost", "127.0.0.1"))
