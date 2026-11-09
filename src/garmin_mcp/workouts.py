"""LLM-friendly workout spec -> Garmin Connect workout JSON.

Garmin's native workout format is verbose and full of magic IDs. Tools accept
this compact spec instead and we translate it, mirroring the structure that
``garminconnect.workout`` produces.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

SPORTS: dict[str, tuple[int, str]] = {
    "running": (1, "running"),
    "cycling": (2, "cycling"),
    "other": (3, "other"),
    "cardio_training": (6, "cardio_training"),
    "walking": (17, "walking"),
    "hiking": (18, "hiking"),
}

STEP_TYPES: dict[str, int] = {
    "warmup": 1,
    "cooldown": 2,
    "interval": 3,
    "recovery": 4,
    "rest": 5,
    "repeat": 6,
    "other": 7,
}

_END = {
    "lap_button": (1, "lap.button"),
    "time": (2, "time"),
    "distance": (3, "distance"),
    "iterations": (7, "iterations"),
}

_TARGET = {
    "none": (1, "no.target"),
    "power": (2, "power.zone"),
    "cadence": (3, "cadence"),
    "heart_rate": (4, "heart.rate.zone"),
    "speed": (5, "speed.zone"),
    "pace": (6, "pace.zone"),
}

_PACE_RE = re.compile(r"^\s*(\d{1,2}):([0-5]\d)\s*$")


def pace_to_mps(pace: str, unit: Literal["km", "mi"]) -> float:
    m = _PACE_RE.match(pace)
    if not m:
        raise ValueError(f"pace must look like '4:30', got {pace!r}")
    secs = int(m.group(1)) * 60 + int(m.group(2))
    if secs <= 0:
        raise ValueError("pace must be positive")
    return (1609.344 if unit == "mi" else 1000.0) / secs


class Target(BaseModel):
    """Intensity target for a step. Use exactly one style per kind."""

    kind: Literal[
        "hr_zone", "hr_range", "pace", "speed", "power_zone", "power_range", "cadence"
    ] = Field(description="Target kind.")
    zone: int | None = Field(
        default=None, ge=1, le=7, description="Zone number for hr_zone / power_zone."
    )
    low: float | None = Field(
        default=None,
        description="Lower bound: bpm (hr_range), watts (power_range), rpm/spm (cadence), "
        "km/h (speed).",
    )
    high: float | None = Field(default=None, description="Upper bound, same units as low.")
    pace_fast: str | None = Field(
        default=None, description="Faster end of pace range as 'm:ss' per pace_unit, e.g. '4:20'."
    )
    pace_slow: str | None = Field(
        default=None, description="Slower end of pace range as 'm:ss' per pace_unit, e.g. '4:40'."
    )
    pace_unit: Literal["km", "mi"] = "km"

    @model_validator(mode="after")
    def _check(self) -> Target:
        k = self.kind
        if k in ("hr_zone", "power_zone") and self.zone is None:
            raise ValueError(f"{k} requires zone")
        if k in ("hr_range", "power_range", "cadence", "speed"):
            if self.low is None or self.high is None:
                raise ValueError(f"{k} requires low and high")
            if self.low > self.high:
                raise ValueError("low must be <= high")
        if k == "pace":
            if not self.pace_fast or not self.pace_slow:
                raise ValueError("pace requires pace_fast and pace_slow")
            if pace_to_mps(self.pace_slow, self.pace_unit) > pace_to_mps(
                self.pace_fast, self.pace_unit
            ):
                raise ValueError("pace_slow must be slower than pace_fast")
        return self

    def to_garmin(self) -> dict[str, Any]:
        def tt(key: str) -> dict[str, Any]:
            tid, tkey = _TARGET[key]
            return {"workoutTargetTypeId": tid, "workoutTargetTypeKey": tkey, "displayOrder": tid}

        k = self.kind
        if k == "hr_zone":
            return {"targetType": tt("heart_rate"), "zoneNumber": self.zone}
        if k == "power_zone":
            return {"targetType": tt("power"), "zoneNumber": self.zone}
        if k == "hr_range":
            return {"targetType": tt("heart_rate"), "targetValueOne": self.low,
                    "targetValueTwo": self.high}
        if k == "power_range":
            return {"targetType": tt("power"), "targetValueOne": self.low,
                    "targetValueTwo": self.high}
        if k == "cadence":
            return {"targetType": tt("cadence"), "targetValueOne": self.low,
                    "targetValueTwo": self.high}
        if k == "speed":
            assert self.low is not None and self.high is not None
            return {"targetType": tt("speed"), "targetValueOne": self.low / 3.6,
                    "targetValueTwo": self.high / 3.6}
        # pace: Garmin stores m/s, slower pace (= lower speed) first.
        assert self.pace_slow and self.pace_fast
        return {
            "targetType": tt("pace"),
            "targetValueOne": round(pace_to_mps(self.pace_slow, self.pace_unit), 6),
            "targetValueTwo": round(pace_to_mps(self.pace_fast, self.pace_unit), 6),
        }


class Step(BaseModel):
    """One workout step, or a repeat block when type == 'repeat'."""

    type: Literal["warmup", "interval", "recovery", "rest", "cooldown", "other", "repeat"]
    end: Literal["time", "distance", "lap_button"] | None = Field(
        default=None,
        description="How the step ends. Required for non-repeat steps.",
    )
    seconds: float | None = Field(default=None, gt=0, description="Duration when end='time'.")
    meters: float | None = Field(default=None, gt=0, description="Distance when end='distance'.")
    target: Target | None = None
    description: str | None = Field(default=None, max_length=512)
    iterations: int | None = Field(
        default=None, ge=1, le=100, description="Repeat count when type='repeat'."
    )
    steps: list[Step] | None = Field(default=None, description="Child steps when type='repeat'.")

    @model_validator(mode="after")
    def _check(self) -> Step:
        if self.type == "repeat":
            if not self.iterations or not self.steps:
                raise ValueError("repeat requires iterations and steps")
            return self
        if self.end is None:
            raise ValueError(f"{self.type} step requires end")
        if self.end == "time" and self.seconds is None:
            raise ValueError("end='time' requires seconds")
        if self.end == "distance" and self.meters is None:
            raise ValueError("end='distance' requires meters")
        return self


def _step_type(name: str) -> dict[str, Any]:
    sid = STEP_TYPES[name]
    return {"stepTypeId": sid, "stepTypeKey": name, "displayOrder": sid}


def _end_condition(name: str) -> dict[str, Any]:
    cid, ckey = _END[name]
    return {
        "conditionTypeId": cid,
        "conditionTypeKey": ckey,
        "displayOrder": cid,
        "displayable": name != "iterations",
    }


def _estimate_seconds(steps: list[Step]) -> int:
    total = 0.0
    for s in steps:
        if s.type == "repeat":
            total += (s.iterations or 1) * _estimate_seconds(s.steps or [])
        elif s.end == "time" and s.seconds:
            total += s.seconds
        elif s.end == "distance" and s.meters:
            total += s.meters / 1000 * 360  # rough: 6 min/km
    return int(total)


def build_workout(
    name: str, sport: str, steps: list[Step], description: str | None = None
) -> dict[str, Any]:
    if sport not in SPORTS:
        raise ValueError(f"unsupported sport {sport!r}; choose from {sorted(SPORTS)}")
    if not steps:
        raise ValueError("workout needs at least one step")
    sport_id, sport_key = SPORTS[sport]
    sport_type = {"sportTypeId": sport_id, "sportTypeKey": sport_key, "displayOrder": 1}
    counter = 0

    def convert(step: Step) -> dict[str, Any]:
        nonlocal counter
        counter += 1
        order = counter
        if step.type == "repeat":
            children = [convert(c) for c in step.steps or []]
            return {
                "type": "RepeatGroupDTO",
                "stepOrder": order,
                "stepType": _step_type("repeat"),
                "numberOfIterations": step.iterations,
                "endCondition": _end_condition("iterations"),
                "endConditionValue": float(step.iterations or 1),
                "smartRepeat": False,
                "workoutSteps": children,
            }
        assert step.end is not None
        out: dict[str, Any] = {
            "type": "ExecutableStepDTO",
            "stepOrder": order,
            "stepType": _step_type(step.type),
            "endCondition": _end_condition(step.end),
        }
        if step.end == "time":
            out["endConditionValue"] = float(step.seconds or 0)
        elif step.end == "distance":
            out["endConditionValue"] = float(step.meters or 0)
        if step.target:
            out.update(step.target.to_garmin())
        else:
            tid, tkey = _TARGET["none"]
            out["targetType"] = {
                "workoutTargetTypeId": tid, "workoutTargetTypeKey": tkey, "displayOrder": tid
            }
        if step.description:
            out["description"] = step.description
        return out

    workout: dict[str, Any] = {
        "workoutName": name,
        "sportType": sport_type,
        "estimatedDurationInSecs": _estimate_seconds(steps),
        "workoutSegments": [
            {
                "segmentOrder": 1,
                "sportType": sport_type,
                "workoutSteps": [convert(s) for s in steps],
            }
        ],
    }
    if description:
        workout["description"] = description
    return workout
