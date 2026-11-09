"""Component tests: tool input validators (dates, ranges, API paths).

EP + BVA on the date range (93 days) and API path length (256), fault attacks on paths.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from mcp.server.mcpserver.exceptions import ToolError

from garmin_mcp.server import MAX_API_PATH, MAX_RANGE_DAYS, _check_date, _range, check_api_path

pytestmark = pytest.mark.risk("R10")


@pytest.mark.parametrize("d", ["2026-11-09", "2028-02-29", "2026-12-31", "2026-01-01"])
def test_valid_dates(d):
    assert _check_date(d, "date") == d


@pytest.mark.parametrize("d", ["2026-02-29", "2026-13-01", "2026-00-10", "2026-11-31",
                               "26-11-09", "2026/11/09", "11/09/2026", "2026-11-9", "",
                               "2026-11-09T00:00", "2026-11-09\n", "２０２６-１１-０９", "2026-1１-09",
                               None, 20261109])
def test_invalid_dates(d):
    with pytest.raises(ToolError):
        _check_date(d, "date")


def test_error_does_not_echo_input():
    with pytest.raises(ToolError) as e:
        _check_date("<script>alert(1)</script>", "date")
    assert "<script>" not in str(e.value)


@pytest.mark.parametrize(("days", "ok"), [(MAX_RANGE_DAYS - 1, True), (MAX_RANGE_DAYS, True),
                                          (MAX_RANGE_DAYS + 1, False)])
def test_range_boundary(days, ok):
    from datetime import date, timedelta

    start = date(2026, 1, 1)
    end = (start + timedelta(days=days)).isoformat()
    if ok:
        assert _range(start.isoformat(), end) == (start.isoformat(), end)
    else:
        with pytest.raises(ToolError):
            _range(start.isoformat(), end)


@pytest.mark.parametrize(("start", "end", "ok"), [
    ("2026-01-02", "2026-01-01", False),   # end - 1
    ("2026-01-01", "2026-01-01", True),    # equal
    ("2026-01-01", "2026-01-02", True),    # end + 1
    ("2026-01-01", None, True),            # defaults to start
])
def test_range_order(start, end, ok):
    if ok:
        _range(start, end)
    else:
        with pytest.raises(ToolError):
            _range(start, end)


@pytest.mark.parametrize("path", [
    "/usersummary-service/usersummary/daily/2026-11-09",
    "/metrics-service/metrics/trainingreadiness/2026-01-01",
    "/hrv-service/hrv/",
    "/a",
    "/file.v2/x_y-z",
])
def test_api_path_valid(path):
    assert check_api_path(path) == path


@pytest.mark.parametrize("path", [
    "", "/", "usersummary-service/x",           # not absolute
    "//evil.example/x",                         # scheme-relative
    "/../x", "/a/../b", "/a/..", "/./a", "/a/.",  # traversal
    "/a//b",                                    # empty segment
    "/a?b=1", "/a#b", "/a b", "/a\tb", "/a\nb",  # query/fragment/whitespace
    "/a%2e%2e/b", "/%2F%2Fevil",                # encoding games
    "/a\\b", "/@evil.example", "/a:b", "/~user",
    "https://evil.example/x", "/ａ",            # full URL / non-ascii
    "/a/.hidden", "/a.",                        # dot segments edge
    "/usersummary-service/x\n",                 # regression: `$` matched before final \n
    "/x\r\nHost: evil", "/x\x00",
])
def test_api_path_fault_attacks(path):
    with pytest.raises(ToolError):
        check_api_path(path)


@pytest.mark.parametrize(("length", "ok"), [(MAX_API_PATH - 1, True), (MAX_API_PATH, True),
                                            (MAX_API_PATH + 1, False)])
def test_api_path_length_boundary(length, ok):
    path = "/" + "a" * (length - 1)
    if ok:
        check_api_path(path)
    else:
        with pytest.raises(ToolError):
            check_api_path(path)


@settings(max_examples=500, deadline=None)
@given(st.text(max_size=60))
def test_property_accepted_paths_are_plain(path):
    try:
        check_api_path(path)
    except ToolError:
        return
    assert path.startswith("/")
    assert ".." not in path
    assert "//" not in path
    assert all(c.isascii() and (c.isalnum() or c in "/._-") for c in path)
