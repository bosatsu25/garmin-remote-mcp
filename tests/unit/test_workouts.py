"""Component tests: workout spec -> Garmin JSON (EP, BVA, property-based)."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from garmin_mcp.workouts import SPORTS, Step, Target, build_workout, pace_to_mps

pytestmark = pytest.mark.risk("R11")


# ---- pace parsing: EP + BVA -------------------------------------------------------
@pytest.mark.parametrize(
    ("pace", "unit", "mps"),
    [
        ("5:00", "km", 1000 / 300),
        ("05:00", "km", 1000 / 300),
        ("0:01", "km", 1000.0),          # lower boundary of a positive pace
        ("59:59", "km", 1000 / 3599),    # upper boundary of the format
        ("8:00", "mi", 1609.344 / 480),
        (" 4:30 ", "km", 1000 / 270),
    ],
)
def test_pace_valid(pace, unit, mps):
    assert pace_to_mps(pace, unit) == pytest.approx(mps)


@pytest.mark.parametrize("pace", ["0:00", "4:60", "4:5", "100:00", "4.30", "abc", "", "-4:30",
                                  "4:30:00", "４:３０", "４:30", "4:３0"])
def test_pace_invalid(pace):
    with pytest.raises(ValueError):
        pace_to_mps(pace, "km")


# ---- Target: EP per kind + BVA on zone -----------------------------------------
@pytest.mark.parametrize(("zone", "ok"), [(0, False), (1, True), (2, True), (6, True), (7, True),
                                          (8, False)])
def test_zone_boundaries(zone, ok):
    if ok:
        assert Target(kind="hr_zone", zone=zone).to_garmin()["zoneNumber"] == zone
    else:
        with pytest.raises(ValidationError):
            Target(kind="hr_zone", zone=zone)


@pytest.mark.parametrize(
    ("kwargs", "key", "v1", "v2"),
    [
        ({"kind": "hr_range", "low": 140, "high": 150}, "heart.rate.zone", 140, 150),
        ({"kind": "power_range", "low": 200, "high": 250}, "power.zone", 200, 250),
        ({"kind": "cadence", "low": 170, "high": 180}, "cadence", 170, 180),
        ({"kind": "speed", "low": 36, "high": 72}, "speed.zone", 10.0, 20.0),
        ({"kind": "hr_range", "low": 150, "high": 150}, "heart.rate.zone", 150, 150),  # low == high
    ],
)
def test_range_targets(kwargs, key, v1, v2):
    g = Target(**kwargs).to_garmin()
    assert g["targetType"]["workoutTargetTypeKey"] == key
    assert g["targetValueOne"] == pytest.approx(v1)
    assert g["targetValueTwo"] == pytest.approx(v2)


def test_power_zone_target():
    g = Target(kind="power_zone", zone=4).to_garmin()
    assert g["targetType"]["workoutTargetTypeKey"] == "power.zone"
    assert g["zoneNumber"] == 4


def test_pace_target_orders_slow_first():
    g = Target(kind="pace", pace_fast="4:00", pace_slow="4:10").to_garmin()
    assert g["targetValueOne"] < g["targetValueTwo"]
    assert g["targetValueTwo"] == pytest.approx(1000 / 240, abs=1e-5)


def test_pace_target_equal_bounds_allowed():
    Target(kind="pace", pace_fast="4:00", pace_slow="4:00")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"kind": "hr_zone"},
        {"kind": "power_zone"},
        {"kind": "hr_range", "low": 150},
        {"kind": "hr_range", "high": 150},
        {"kind": "hr_range", "low": 151, "high": 150},
        {"kind": "speed", "low": 10},
        {"kind": "pace", "pace_fast": "4:00"},
        {"kind": "pace", "pace_fast": "4:10", "pace_slow": "4:00"},
        {"kind": "pace", "pace_fast": "x", "pace_slow": "4:00"},
        {"kind": "heart"},
    ],
)
def test_invalid_targets(kwargs):
    with pytest.raises((ValidationError, ValueError)):
        Target(**kwargs)


# ---- Step: decision table on type x end ----------------------------------------
@pytest.mark.parametrize(
    ("kwargs", "ok"),
    [
        ({"type": "interval", "end": "time", "seconds": 60}, True),
        ({"type": "interval", "end": "distance", "meters": 400}, True),
        ({"type": "interval", "end": "lap_button"}, True),
        ({"type": "interval"}, False),
        ({"type": "interval", "end": "time"}, False),
        ({"type": "interval", "end": "distance"}, False),
        ({"type": "interval", "end": "time", "seconds": 0}, False),
        ({"type": "interval", "end": "distance", "meters": -1}, False),
        ({"type": "repeat", "iterations": 2, "steps": [{"type": "rest", "end": "lap_button"}]}, True),
        ({"type": "repeat", "iterations": 2}, False),
        ({"type": "repeat", "steps": [{"type": "rest", "end": "lap_button"}]}, False),
        ({"type": "sprint", "end": "lap_button"}, False),
    ],
)
def test_step_decision_table(kwargs, ok):
    if ok:
        Step(**kwargs)
    else:
        with pytest.raises(ValidationError):
            Step(**kwargs)


@pytest.mark.parametrize(("n", "ok"), [(0, False), (1, True), (2, True), (99, True), (100, True),
                                       (101, False)])
def test_iterations_boundary(n, ok):
    child = [{"type": "interval", "end": "lap_button"}]
    if ok:
        Step(type="repeat", iterations=n, steps=child)
    else:
        with pytest.raises(ValidationError):
            Step(type="repeat", iterations=n, steps=child)


@pytest.mark.risk("R07")
@pytest.mark.parametrize(("length", "ok"), [(511, True), (512, True), (513, False)])
def test_description_length_boundary(length, ok):
    kwargs = {"type": "interval", "end": "lap_button", "description": "d" * length}
    if ok:
        Step(**kwargs)
    else:
        with pytest.raises(ValidationError):
            Step(**kwargs)


# ---- build_workout ----------------------------------------------------------------
def interval_session():
    return [
        Step(type="warmup", end="time", seconds=600),
        Step(type="repeat", iterations=5, steps=[
            Step(type="interval", end="distance", meters=1000,
                 target=Target(kind="pace", pace_fast="3:50", pace_slow="4:00")),
            Step(type="recovery", end="time", seconds=90),
        ]),
        Step(type="cooldown", end="lap_button"),
    ]


def test_structure_and_numbering():
    w = build_workout("5x1k", "running", interval_session(), description="d")
    assert w["description"] == "d"
    seg = w["workoutSegments"][0]
    assert seg["segmentOrder"] == 1
    steps = seg["workoutSteps"]
    assert [s["stepOrder"] for s in steps] == [1, 2, 5]
    assert [s["stepOrder"] for s in steps[1]["workoutSteps"]] == [3, 4]
    rep = steps[1]
    assert rep["type"] == "RepeatGroupDTO"
    assert rep["endCondition"]["conditionTypeKey"] == "iterations"
    assert rep["endCondition"]["displayable"] is False
    assert rep["endConditionValue"] == 5.0
    assert steps[2]["endCondition"]["conditionTypeKey"] == "lap.button"
    assert "endConditionValue" not in steps[2]
    assert steps[2]["targetType"]["workoutTargetTypeKey"] == "no.target"
    assert w["estimatedDurationInSecs"] == 600 + 5 * (360 + 90)


@pytest.mark.parametrize("sport", sorted(SPORTS))
def test_every_supported_sport(sport):
    w = build_workout("x", sport, [Step(type="other", end="lap_button")])
    sid, key = SPORTS[sport]
    assert w["sportType"] == {"sportTypeId": sid, "sportTypeKey": key, "displayOrder": 1}
    assert w["workoutSegments"][0]["sportType"] == w["sportType"]


@pytest.mark.parametrize("sport", ["swimming", "strength_training", "RUNNING", "", "yoga"])
def test_unsupported_sports(sport):
    with pytest.raises(ValueError):
        build_workout("x", sport, [Step(type="other", end="lap_button")])


def test_empty_steps_rejected():
    with pytest.raises(ValueError):
        build_workout("x", "running", [])


def test_step_description_carried():
    w = build_workout("x", "running", [Step(type="other", end="lap_button", description="hi")])
    assert w["workoutSegments"][0]["workoutSteps"][0]["description"] == "hi"


# ---- property: numbering is a depth-first 1..n sequence for any tree ----------
leaf = st.builds(
    lambda end, v: Step(type="interval", end=end,
                        **({"seconds": v} if end == "time" else
                           {"meters": v} if end == "distance" else {})),
    st.sampled_from(["time", "distance", "lap_button"]),
    st.floats(min_value=1, max_value=10_000, allow_nan=False),
)
tree = st.recursive(
    leaf,
    lambda children: st.builds(
        lambda kids, n: Step(type="repeat", iterations=n, steps=kids),
        st.lists(children, min_size=1, max_size=3), st.integers(1, 5),
    ),
    max_leaves=12,
)


def _orders(steps):
    for s in steps:
        yield s["stepOrder"]
        yield from _orders(s.get("workoutSteps", []))


@settings(max_examples=150, deadline=None)
@given(st.lists(tree, min_size=1, max_size=4))
def test_property_step_orders_are_sequential(steps):
    w = build_workout("p", "running", steps)
    orders = list(_orders(w["workoutSegments"][0]["workoutSteps"]))
    assert orders == list(range(1, len(orders) + 1))
    assert w["estimatedDurationInSecs"] >= 0
