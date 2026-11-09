"""Component tests: response compaction (EP, BVA)."""

import json

import pytest

from garmin_mcp.compact import (
    MAX_LIST_ITEMS,
    MAX_OUTPUT_CHARS,
    compact,
    pick,
    summarize_activity,
    to_text,
)

pytestmark = pytest.mark.risk("R12")


def test_drops_empty_values_recursively():
    assert compact({"a": None, "b": [], "c": {}, "d": {"e": None, "f": 1}, "g": 0, "h": ""}) == {
        "d": {"f": 1}, "g": 0, "h": ""}


@pytest.mark.parametrize(("n", "omitted"), [(MAX_LIST_ITEMS - 1, False), (MAX_LIST_ITEMS, False),
                                            (MAX_LIST_ITEMS + 1, True)])
def test_series_key_boundary(n, omitted):
    out = compact({"heartRateValues": list(range(n))})
    assert isinstance(out["heartRateValues"], str) is omitted
    if omitted:
        assert str(n) in out["heartRateValues"]


@pytest.mark.parametrize(("n", "extra"), [(MAX_LIST_ITEMS, 0), (MAX_LIST_ITEMS + 1, 1)])
def test_generic_list_boundary(n, extra):
    out = compact({"items": list(range(n))})
    assert len(out["items"]) == MAX_LIST_ITEMS + extra
    if extra:
        assert "1 more items truncated" in out["items"][-1]


def test_top_level_list_truncated():
    assert len(compact(list(range(500)))) == MAX_LIST_ITEMS + 1


def test_raw_bypasses_compaction():
    data = {"heartRateValues": list(range(100)), "x": None}
    assert json.loads(to_text(data, raw=True)) == data


@pytest.mark.parametrize(("size", "truncated"), [(MAX_OUTPUT_CHARS - 2, False),
                                                 (MAX_OUTPUT_CHARS - 1, True)])
def test_output_char_boundary(size, truncated):
    # json.dumps of a string adds 2 quote chars
    text = to_text("a" * size)
    assert ("<truncated" in text) is truncated
    assert len(text) <= MAX_OUTPUT_CHARS + 100


def test_non_ascii_preserved():
    assert "朝ラン" in to_text({"name": "朝ラン"})


def test_pick():
    assert pick({"a": 1, "b": None, "c": 3}, "a", "b", "z") == {"a": 1}


@pytest.mark.parametrize(("speed", "pace"), [(1000 / 300, "5:00"), (1000 / 299.5, "4:59"),
                                             (0, None), (None, None)])
def test_summarize_pace(speed, pace):
    out = summarize_activity({"activityId": 1, "averageSpeed": speed,
                              "activityType": {"typeKey": "running"}, "junk": 1})
    assert out.get("averagePacePerKm") == pace
    assert out["activityType"] == "running"
    assert "junk" not in out


def test_summarize_tolerates_non_dict_activity_type():
    assert summarize_activity({"activityId": 1, "activityType": "running"})["activityType"] == "running"
