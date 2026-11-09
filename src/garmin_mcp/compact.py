"""Shrink Garmin responses so they fit comfortably in a model's context.

Garmin endpoints routinely return thousands of time-series samples (heart rate
every 2 minutes, sleep levels, polylines...). Unless a tool explicitly asks for
raw data we drop nulls and truncate long arrays.
"""

from __future__ import annotations

import json
from typing import Any

MAX_LIST_ITEMS = 60
MAX_OUTPUT_CHARS = 80_000

# Keys whose values are bulky series that are rarely useful to an LLM verbatim.
_SERIES_HINTS = ("Values", "Array", "Descriptors", "polyline", "geoPolyline", "Levels",
                 "Samples", "metrics", "chartData")


def compact(value: Any, *, max_items: int = MAX_LIST_ITEMS, _depth: int = 0) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if v is None or v == [] or v == {}:
                continue
            if isinstance(v, list) and len(v) > max_items and any(h in k for h in _SERIES_HINTS):
                out[k] = f"<{len(v)} samples omitted; call with raw=true to include>"
                continue
            out[k] = compact(v, max_items=max_items, _depth=_depth + 1)
        return out
    if isinstance(value, list):
        items = [compact(v, max_items=max_items, _depth=_depth + 1) for v in value[:max_items]]
        if len(value) > max_items:
            items.append(f"<{len(value) - max_items} more items truncated>")
        return items
    return value


def to_text(value: Any, *, raw: bool = False) -> str:
    data = value if raw else compact(value)
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)
    if len(text) > MAX_OUTPUT_CHARS:
        text = (
            text[:MAX_OUTPUT_CHARS]
            + f"... <truncated: {len(text) - MAX_OUTPUT_CHARS} more chars; narrow the query>"
        )
    return text


def pick(d: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: d[k] for k in keys if d.get(k) is not None}


ACTIVITY_SUMMARY_KEYS = (
    "activityId", "activityName", "startTimeLocal", "activityType", "distance", "duration",
    "movingDuration", "elapsedDuration", "elevationGain", "elevationLoss", "averageSpeed",
    "maxSpeed", "averageHR", "maxHR", "calories", "aerobicTrainingEffect",
    "anaerobicTrainingEffect", "trainingEffectLabel", "activityTrainingLoad", "vO2MaxValue",
    "averageRunningCadenceInStepsPerMinute", "avgPower", "normPower", "averageBikingCadenceInRevPerMinute",
    "avgStrideLength", "avgGroundContactTime", "avgVerticalOscillation", "locationName",
    "lapCount", "description",
)


def summarize_activity(a: dict[str, Any]) -> dict[str, Any]:
    out = pick(a, *ACTIVITY_SUMMARY_KEYS)
    at = a.get("activityType")
    if isinstance(at, dict):
        out["activityType"] = at.get("typeKey")
    if isinstance(out.get("averageSpeed"), (int, float)) and out["averageSpeed"] > 0:
        secs = 1000 / out["averageSpeed"]
        out["averagePacePerKm"] = f"{int(secs // 60)}:{int(secs % 60):02d}"
    return out
