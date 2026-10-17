# 0001. Date-range filter on GET /api/alerts

- Status: **Accepted** — implemented in `689e718` (merged in #14). The `hours` upper bound was added afterwards by [ADR 0002](0002-bound-hours-get-api-alerts-api-alerts.md).
- Date: 2026-10-14
- Issue: cnds#5

## Context

`GET /api/alerts` (`src/api/routers/alerts.py`, `list_alerts`; line numbers below are as of the proposal) filters by `severity`, `acknowledged` and `src_ip`. It paginates with `limit`/`offset` and has no time filter. Analysts who want a time window have to download everything and filter on the client.

Other endpoints in the same router already filter by time:

- `GET /api/alerts/export` takes `hours: Optional[int] = Query(None, ge=1)` and applies `Alert.timestamp >= utcnow() - timedelta(hours=hours)` (`alerts.py:46`, `alerts.py:62-64`).
- `GET /api/alerts/trends` uses the same cutoff pattern (`alerts.py:121`, `alerts.py:127`).

`Alert.timestamp` is a timezone-naive `DateTime` column with an index (`src/api/models.py:33`). `src/timeutils.py:1-19` explains that asyncpg rejects tz-aware datetimes compared against naive columns, so every value bound to such a column has to be naive UTC.

## Decision drivers

- AC-1: `start`/`end` limit results to the given range.
- AC-2: `hours=24` shorthand, consistent with the export endpoint.
- AC-3: invalid datetime strings return HTTP 422.
- AC-4: the new filters combine with `severity`, `acknowledged` and `src_ip`.
- AC-5: unit tests cover date-range filtering.
- Must not break asyncpg (naive-UTC invariant). No new dependencies.

## Considered options

1. **Typed FastAPI query params (`start: Optional[datetime]`, `end: Optional[datetime]`, `hours: Optional[int]`) added inline to `list_alerts`.** Pydantic parses ISO 8601 and returns 422 on bad input without extra code. The change is small and follows the export endpoint's pattern. Downside: the time-filter logic is repeated next to export's (only a few lines).
2. **Accept `start`/`end` as `str` and parse them by hand with `datetime.fromisoformat`, raising `HTTPException(422)`.** This gives full control over error messages, but it duplicates what FastAPI already does, adds code paths that need tests, and produces a 422 body that differs from the framework's standard validation error.
3. **Extract a shared `TimeRange` dependency (`Depends`) used by `/alerts` and `/alerts/export`.** Less duplication, but it widens scope (it changes export's signature and behaviour), which the issue does not ask for.

## Decision

Option 1. In `list_alerts`:

- Add `start: Optional[datetime] = None`, `end: Optional[datetime] = None` and `hours: Optional[int] = Query(None, ge=1)` (the same constraint as export).
- Normalise `start`/`end` with a small private helper `_to_naive_utc(dt)`. If `dt.tzinfo` is set, it returns `dt.astimezone(timezone.utc).replace(tzinfo=None)`. Otherwise it returns `dt` unchanged and treats it as UTC.
- Semantics: `Alert.timestamp >= start` and `Alert.timestamp <= end` (both inclusive). `hours` adds `Alert.timestamp >= utcnow() - timedelta(hours=hours)`.
- All filters are combined with AND on the same `select`, before `offset`/`limit`. If `hours` and `start` are both supplied, both lower bounds apply (the later one wins). Nothing is rejected.
- If `start > end` after normalisation, raise `HTTPException(status_code=422)`. This is clearly a client error and costs one line.

## Consequences

Good:
- The change is backward compatible: all new parameters are optional, and the default behaviour stays the same.
- It reuses the indexed `timestamp` column, so the database does the filtering.
- 422 for malformed datetimes comes from FastAPI with no custom code.

Bad / trade-offs:
- The `hours` cutoff logic now lives in two places (export and list). Extracting a shared helper is left for later.
- Naive input datetimes are assumed to be UTC. Clients that send local times without an offset will get shifted windows. This will be documented in the parameter description.

Migration: none. No schema change.
Rollback: revert the commit. No data is affected.

## Verification

| AC | Test (tests/test_api.py) |
|---|---|
| AC-1 | `test_list_alerts_date_range`: insert alerts at naive-UTC T-48h, T-12h and T-1h. `?start=T-24h&end=T-30m` returns only T-12h and T-1h. Also covers the inclusive bound and a tz-aware `start` with a `+02:00` offset. |
| AC-2 | `test_list_alerts_hours`: with the same fixtures, `?hours=24` excludes T-48h. `?hours=0` returns 422. |
| AC-3 | `test_list_alerts_invalid_datetime`: `?start=not-a-date` and `?end=2026-13-45` return 422. `start > end` returns 422. |
| AC-4 | `test_list_alerts_date_range_composes`: alerts in and out of range with different severity, acknowledged and src_ip values. Combined query returns exactly the intersection. |
| AC-5 | All of the above live in `tests/test_api.py` and run under `pytest tests/test_api.py -v`. |
