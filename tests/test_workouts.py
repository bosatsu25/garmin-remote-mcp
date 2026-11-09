import pytest
from pydantic import ValidationError

from garmin_mcp.workouts import Step, Target, build_workout, pace_to_mps


def test_pace_to_mps():
    assert pace_to_mps("5:00", "km") == pytest.approx(1000 / 300)
    assert pace_to_mps("8:00", "mi") == pytest.approx(1609.344 / 480)
    with pytest.raises(ValueError):
        pace_to_mps("abc", "km")


def test_interval_workout_structure():
    steps = [
        Step(type="warmup", end="time", seconds=600),
        Step(
            type="repeat",
            iterations=5,
            steps=[
                Step(
                    type="interval",
                    end="distance",
                    meters=1000,
                    target=Target(kind="pace", pace_fast="3:50", pace_slow="4:00"),
                ),
                Step(type="recovery", end="time", seconds=90),
            ],
        ),
        Step(type="cooldown", end="lap_button"),
    ]
    w = build_workout("5x1k", "running", steps)
    assert w["sportType"]["sportTypeKey"] == "running"
    seg = w["workoutSegments"][0]["workoutSteps"]
    assert [s["stepOrder"] for s in seg] == [1, 2, 5]
    repeat = seg[1]
    assert repeat["type"] == "RepeatGroupDTO"
    assert repeat["numberOfIterations"] == 5
    interval = repeat["workoutSteps"][0]
    assert interval["stepOrder"] == 3
    assert interval["endCondition"]["conditionTypeKey"] == "distance"
    assert interval["endConditionValue"] == 1000.0
    assert interval["targetType"]["workoutTargetTypeKey"] == "pace.zone"
    # slower pace (lower m/s) first
    assert interval["targetValueOne"] < interval["targetValueTwo"]
    assert seg[2]["endCondition"]["conditionTypeKey"] == "lap.button"
    assert seg[2]["targetType"]["workoutTargetTypeKey"] == "no.target"
    # 600 + 5 * (360 + 90)
    assert w["estimatedDurationInSecs"] == 600 + 5 * 450


def test_hr_zone_and_power_range():
    hz = Target(kind="hr_zone", zone=2).to_garmin()
    assert hz["zoneNumber"] == 2
    assert hz["targetType"]["workoutTargetTypeKey"] == "heart.rate.zone"
    pr = Target(kind="power_range", low=200, high=250).to_garmin()
    assert (pr["targetValueOne"], pr["targetValueTwo"]) == (200, 250)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"type": "interval"},  # no end
        {"type": "interval", "end": "time"},  # no seconds
        {"type": "interval", "end": "distance"},  # no meters
        {"type": "repeat", "iterations": 3},  # no children
    ],
)
def test_invalid_steps(kwargs):
    with pytest.raises(ValidationError):
        Step(**kwargs)


def test_invalid_targets():
    with pytest.raises(ValidationError):
        Target(kind="hr_zone")
    with pytest.raises(ValidationError):
        Target(kind="pace", pace_fast="5:00", pace_slow="4:00")
    with pytest.raises(ValidationError):
        Target(kind="hr_range", low=160, high=140)


def test_unsupported_sport():
    with pytest.raises(ValueError):
        build_workout("x", "swimming", [Step(type="interval", end="lap_button")])
