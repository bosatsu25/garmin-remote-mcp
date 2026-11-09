"""Garmin Connect remote MCP server (Streamable HTTP + single-owner OAuth)."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from datetime import date
from typing import Annotated, Any, Literal, TypeVar
from urllib.parse import urlparse

from garminconnect import Garmin, GarminConnectConnectionError
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import Field
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import __version__
from .compact import summarize_activity, to_text
from .config import Settings
from .garmin_client import GarminService, GarminUnavailable, seed_tokens
from .oauth import SCOPE, OwnerOAuthProvider
from .workouts import SPORTS, Step, build_workout

logger = logging.getLogger(__name__)

T = TypeVar("T")

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_RANGE_DAYS = 93

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=True)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True)

DateArg = Annotated[
    str | None,
    Field(description="Date as YYYY-MM-DD in the user's local time. Defaults to today."),
]
StartArg = Annotated[str, Field(description="Start date YYYY-MM-DD (inclusive).")]
EndArg = Annotated[
    str | None, Field(description="End date YYYY-MM-DD (inclusive). Defaults to start date.")
]
RawArg = Annotated[
    bool,
    Field(description="Return Garmin's full response including long time series. "
                      "Large; only use when samples are really needed."),
]

INSTRUCTIONS = """\
Access to the owner's Garmin Connect account: activities, sleep, HRV, Body Battery, stress,
training readiness/status, VO2max, race predictions, body composition, workouts and calendar.
Dates are YYYY-MM-DD in the owner's local timezone; call get_profile if you need today's date.
Distances are meters, durations seconds, speeds m/s unless a field says otherwise.
Write tools create/schedule workouts in the owner's real Garmin account: confirm with the user
before calling them.
"""


def _check_date(value: str, name: str) -> str:
    if not DATE_RE.match(value):
        raise ToolError(f"{name} must be YYYY-MM-DD, got {value!r}")
    try:
        date.fromisoformat(value)
    except ValueError as e:
        raise ToolError(f"{name} is not a valid date: {value}") from e
    return value


def _range(start: str, end: str | None) -> tuple[str, str]:
    s = _check_date(start, "start")
    e = _check_date(end, "end") if end else s
    ds, de = date.fromisoformat(s), date.fromisoformat(e)
    if de < ds:
        raise ToolError("end must not be before start")
    if (de - ds).days > MAX_RANGE_DAYS:
        raise ToolError(f"date range is limited to {MAX_RANGE_DAYS} days per call")
    return s, e


def create_server(settings: Settings, garmin: GarminService) -> MCPServer:
    provider = OwnerOAuthProvider(settings)
    mcp = MCPServer(
        name="garmin",
        title="Garmin Connect",
        instructions=INSTRUCTIONS,
        version=__version__,
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=settings.public_url,
            resource_server_url=settings.resource_url,
            validate_token_resource=True,
            required_scopes=[SCOPE],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
            ),
            revocation_options=RevocationOptions(enabled=True),
        ),
    )

    async def run(fn: Callable[[Garmin], T]) -> T:
        try:
            return await garmin.call(fn)
        except GarminUnavailable as e:
            raise ToolError(str(e)) from e
        except (ValueError, GarminConnectConnectionError) as e:
            raise ToolError(f"Garmin request failed: {e}") from e

    async def day(cdate: str | None) -> str:
        if cdate:
            return _check_date(cdate, "date")
        return await run(lambda g: g.today().isoformat())

    # ------------------------------------------------------------ HTTP extras
    @mcp.custom_route("/oauth/login", methods=["GET", "POST"], include_in_schema=False)
    async def oauth_login(request: Request) -> Response:
        return await provider.login_page(request)

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok", "version": __version__})

    # ---------------------------------------------------------------- profile
    @mcp.tool(annotations=READ)
    async def get_profile() -> str:
        """Owner's name, unit system, timezone, today's local date and registered devices."""
        def _f(g: Garmin) -> dict[str, Any]:
            devices = [
                {k: d.get(k) for k in ("productDisplayName", "deviceId", "lastUsed")
                 if d.get(k) is not None}
                for d in (g.get_devices() or [])
            ]
            return {
                "full_name": g.get_full_name(),
                "unit_system": g.get_unit_system(),
                "timezone": g.get_user_timezone(),
                "today": g.today().isoformat(),
                "devices": devices,
            }
        return to_text(await run(_f))

    # ------------------------------------------------------------- wellness
    @mcp.tool(annotations=READ)
    async def get_daily_summary(date: DateArg = None) -> str:
        """Daily totals: steps, calories, distance, intensity minutes, resting HR, stress
        averages, Body Battery high/low, floors, SpO2."""
        d = await day(date)
        return to_text(await run(lambda g: g.get_user_summary(d)))

    @mcp.tool(annotations=READ)
    async def get_sleep(date: DateArg = None, raw: RawArg = False) -> str:
        """Sleep for the night ending on `date`: duration, stages, sleep score and feedback,
        overnight HRV/respiration/SpO2 averages."""
        d = await day(date)
        data = await run(lambda g: g.get_sleep_data(d))
        if not raw and isinstance(data, dict):
            dto = data.get("dailySleepDTO") or {}
            keep = {k: data[k] for k in (
                "avgOvernightHrv", "hrvStatus", "restingHeartRate", "bodyBatteryChange",
                "avgSleepStress", "sleepScoreFeedback") if data.get(k) is not None}
            return to_text({"dailySleepDTO": dto, **keep})
        return to_text(data, raw=raw)

    @mcp.tool(annotations=READ)
    async def get_sleep_range(start: StartArg, end: EndArg = None) -> str:
        """Sleep score and duration per night across a date range (for trends)."""
        s, e = _range(start, end)
        return to_text(await run(lambda g: g.get_sleep_daily(s, e)))

    @mcp.tool(annotations=READ)
    async def get_hrv(date: DateArg = None, raw: RawArg = False) -> str:
        """Overnight HRV summary: last-night average, 7-day average, baseline band, status."""
        d = await day(date)
        data = await run(lambda g: g.get_hrv_data(d))
        if not raw and isinstance(data, dict):
            return to_text({"hrvSummary": data.get("hrvSummary")})
        return to_text(data, raw=raw)

    @mcp.tool(annotations=READ)
    async def get_hrv_range(start: StartArg, end: EndArg = None) -> str:
        """HRV summaries for each day in a range."""
        s, e = _range(start, end)
        return to_text(await run(lambda g: g.get_hrv_data_range(s, e)))

    @mcp.tool(annotations=READ)
    async def get_body_battery(start: StartArg, end: EndArg = None, raw: RawArg = False) -> str:
        """Body Battery per day: charged, drained, highest/lowest values and events."""
        s, e = _range(start, end)
        return to_text(await run(lambda g: g.get_body_battery(s, e)), raw=raw)

    @mcp.tool(annotations=READ)
    async def get_stress(date: DateArg = None, raw: RawArg = False) -> str:
        """All-day stress: average and max stress level and time in each stress category."""
        d = await day(date)
        return to_text(await run(lambda g: g.get_stress_data(d)), raw=raw)

    @mcp.tool(annotations=READ)
    async def get_heart_rate(date: DateArg = None, raw: RawArg = False) -> str:
        """Heart rate for a day: resting, min, max, 7-day average resting HR."""
        d = await day(date)
        return to_text(await run(lambda g: g.get_heart_rates(d)), raw=raw)

    @mcp.tool(annotations=READ)
    async def get_steps_range(start: StartArg, end: EndArg = None) -> str:
        """Daily step totals and goals over a date range."""
        s, e = _range(start, end)
        return to_text(await run(lambda g: g.get_daily_steps(s, e)))

    @mcp.tool(annotations=READ)
    async def get_body_composition(start: StartArg, end: EndArg = None) -> str:
        """Weight, BMI, body fat %, muscle mass etc. from weigh-ins in a date range."""
        s, e = _range(start, end)
        return to_text(await run(lambda g: g.get_body_composition(s, e)))

    # ------------------------------------------------------------- training
    @mcp.tool(annotations=READ)
    async def get_training_readiness(date: DateArg = None) -> str:
        """Training readiness score and its contributing factors (sleep, recovery time,
        HRV, acute load, stress history)."""
        d = await day(date)
        return to_text(await run(lambda g: g.get_training_readiness(d)))

    @mcp.tool(annotations=READ)
    async def get_training_status(date: DateArg = None) -> str:
        """Training status (productive, maintaining, ...), acute/chronic load, load focus,
        VO2max trend."""
        d = await day(date)
        return to_text(await run(lambda g: g.get_training_status(d)))

    @mcp.tool(annotations=READ)
    async def get_vo2max(date: DateArg = None) -> str:
        """VO2max (running/cycling) and fitness age for a date."""
        d = await day(date)
        return to_text(await run(lambda g: g.get_max_metrics(d)))

    @mcp.tool(annotations=READ)
    async def get_race_predictions() -> str:
        """Predicted 5K / 10K / half marathon / marathon finish times (seconds)."""
        return to_text(await run(lambda g: g.get_race_predictions()))

    @mcp.tool(annotations=READ)
    async def get_endurance_score(start: StartArg, end: EndArg = None) -> str:
        """Endurance score over a date range (weekly aggregation)."""
        s, e = _range(start, end)
        return to_text(await run(lambda g: g.get_endurance_score(s, e)))

    # ----------------------------------------------------------- activities
    @mcp.tool(annotations=READ)
    async def list_activities(
        start: Annotated[str | None, Field(description="From date YYYY-MM-DD. If omitted, "
                                           "returns the most recent activities.")] = None,
        end: EndArg = None,
        activity_type: Annotated[str | None, Field(
            description="Filter by type key, e.g. running, cycling, swimming, "
                        "strength_training, walking, hiking.")] = None,
        limit: Annotated[int, Field(ge=1, le=100, description="Max activities when start is "
                                    "omitted.")] = 20,
    ) -> str:
        """List activities with key metrics (distance, duration, pace, HR, training effect,
        load). Use get_activity for laps/splits of a single activity."""
        if start:
            s, e = _range(start, end) if end else (_check_date(start, "start"), None)
            items = await run(lambda g: g.get_activities_by_date(s, e, activity_type))
        else:
            items = await run(lambda g: g.get_activities(0, limit, activity_type))
        items = items if isinstance(items, list) else []
        return to_text([summarize_activity(a) for a in items])

    @mcp.tool(annotations=READ)
    async def get_activity(
        activity_id: Annotated[int, Field(description="Activity ID from list_activities.")],
        include_splits: Annotated[bool, Field(description="Include per-lap splits.")] = True,
        raw: RawArg = False,
    ) -> str:
        """Details of one activity: summary metrics, HR zones and (optionally) lap splits."""
        aid = str(activity_id)

        def _f(g: Garmin) -> dict[str, Any]:
            out: dict[str, Any] = {"activity": g.get_activity(aid)}
            if include_splits:
                splits = g.get_activity_splits(aid) or {}
                out["laps"] = splits.get("lapDTOs", splits)
            try:
                out["hr_zones"] = g.get_activity_hr_in_timezones(aid)
            except GarminConnectConnectionError as e:  # not every activity has HR zones
                logger.debug("No HR zones for activity %s: %s", aid, e)
            return out

        return to_text(await run(_f), raw=raw)

    # ------------------------------------------------------- workouts (read)
    @mcp.tool(annotations=READ)
    async def list_workouts(
        limit: Annotated[int, Field(ge=1, le=100)] = 30,
    ) -> str:
        """Saved workouts in the owner's library (id, name, sport, last update)."""
        items = await run(lambda g: g.get_workouts(0, limit))
        keys = ("workoutId", "workoutName", "sportType", "updateDate", "estimatedDurationInSecs",
                "description")
        return to_text([
            {k: (w[k]["sportTypeKey"] if k == "sportType" and isinstance(w.get(k), dict)
                 else w.get(k)) for k in keys}
            for w in (items or [])
        ])

    @mcp.tool(annotations=READ)
    async def get_workout(
        workout_id: Annotated[int, Field(description="Workout ID from list_workouts.")],
    ) -> str:
        """Full step structure of a saved workout."""
        return to_text(await run(lambda g: g.get_workout_by_id(workout_id)))

    @mcp.tool(annotations=READ)
    async def get_calendar(start: StartArg, end: EndArg = None) -> str:
        """Scheduled workouts (including Garmin Coach / adaptive plan sessions) in a range.
        Each item has a scheduled id usable with unschedule_workout."""
        s, e = _range(start, end)
        return to_text(await run(lambda g: g.get_scheduled_workouts_by_period(s, e)))

    # ---------------------------------------------------------- escape hatch
    @mcp.tool(annotations=READ)
    async def garmin_api_get(
        path: Annotated[str, Field(description="Garmin Connect API path starting with '/', "
                                   "e.g. /metrics-service/metrics/trainingreadiness/2026-01-01")],
        params: Annotated[dict[str, str] | None, Field(description="Query parameters.")] = None,
        raw: RawArg = False,
    ) -> str:
        """Read-only GET against any Garmin Connect API path, for data no other tool covers."""
        if not path.startswith("/") or ".." in path or "://" in path:
            raise ToolError("path must be an absolute API path like /usersummary-service/...")
        return to_text(await run(lambda g: g.connectapi(path, params=params or None)), raw=raw)

    # ------------------------------------------------------------- write ops
    if settings.allow_write:
        @mcp.tool(annotations=WRITE)
        async def create_workout(
            name: Annotated[str, Field(min_length=1, max_length=80)],
            sport: Annotated[Literal["running", "cycling", "walking", "hiking",
                                     "cardio_training", "other"], Field()],
            steps: Annotated[list[Step], Field(min_length=1, description=(
                "Ordered steps. Example 5x1km intervals: "
                "[{type:'warmup',end:'time',seconds:600},"
                "{type:'repeat',iterations:5,steps:["
                "{type:'interval',end:'distance',meters:1000,"
                "target:{kind:'pace',pace_fast:'3:50',pace_slow:'4:00'}},"
                "{type:'recovery',end:'time',seconds:90}]},"
                "{type:'cooldown',end:'lap_button'}]"))],
            description: Annotated[str | None, Field(max_length=1024)] = None,
            schedule_date: Annotated[str | None, Field(
                description="Optionally also schedule it on this date (YYYY-MM-DD).")] = None,
        ) -> str:
            """Create a structured workout in the owner's Garmin library (synced to the watch),
            optionally scheduling it. Ask the user to confirm the plan before calling."""
            if sport not in SPORTS:
                raise ToolError(f"unsupported sport {sport}")
            if schedule_date:
                _check_date(schedule_date, "schedule_date")
            try:
                payload = build_workout(name, sport, steps, description)
            except ValueError as e:
                raise ToolError(str(e)) from e
            created = await run(lambda g: g.upload_workout(payload))
            wid = created.get("workoutId") if isinstance(created, dict) else None
            result: dict[str, Any] = {"workoutId": wid, "workoutName": name}
            if schedule_date and wid:
                sched = await run(lambda g: g.schedule_workout(wid, schedule_date))
                result["scheduled"] = {
                    "date": schedule_date,
                    "scheduledWorkoutId": (sched or {}).get("workoutScheduleId")
                    if isinstance(sched, dict) else None,
                }
            return to_text(result)

        @mcp.tool(annotations=WRITE)
        async def schedule_workout(
            workout_id: Annotated[int, Field(description="Workout ID from list_workouts.")],
            date: Annotated[str, Field(description="YYYY-MM-DD")],
        ) -> str:
            """Put an existing saved workout on the Garmin calendar for a date."""
            d = _check_date(date, "date")
            return to_text(await run(lambda g: g.schedule_workout(workout_id, d)))

        @mcp.tool(annotations=DESTRUCTIVE)
        async def unschedule_workout(
            scheduled_workout_id: Annotated[int, Field(
                description="Scheduled item id from get_calendar (not the workout id).")],
        ) -> str:
            """Remove a workout from the calendar. The workout stays in the library."""
            await run(lambda g: g.unschedule_workout(scheduled_workout_id))
            return to_text({"unscheduled": scheduled_workout_id})

        @mcp.tool(annotations=DESTRUCTIVE)
        async def delete_workout(
            workout_id: Annotated[int, Field(description="Workout ID from list_workouts.")],
        ) -> str:
            """Permanently delete a saved workout from the library. Confirm with the user first."""
            await run(lambda g: g.delete_workout(workout_id))
            return to_text({"deleted": workout_id})

    return mcp


def create_app(settings: Settings | None = None) -> Starlette:
    settings = settings or Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    seed_tokens(settings.garmin_token_dir, settings.garmin_tokens_seed)
    garmin = GarminService(settings.garmin_token_dir)
    mcp = create_server(settings, garmin)
    public_host = urlparse(settings.public_url).netloc
    return mcp.streamable_http_app(
        streamable_http_path=settings.mcp_path,
        stateless_http=True,
        json_response=True,
        host=settings.host,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[public_host, "localhost:*", "127.0.0.1:*"],
            allowed_origins=[settings.public_url, "https://claude.ai", "https://claude.com"],
        ),
    )


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings.from_env()
    app = create_app(settings)
    uvicorn.run(app, host=settings.host, port=settings.port, proxy_headers=True,
                forwarded_allow_ips="*")


if __name__ == "__main__":
    main()
