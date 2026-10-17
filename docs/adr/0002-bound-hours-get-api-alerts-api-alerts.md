# 0002. Bound `hours` on GET /api/alerts and /api/alerts/export

- Status: **Accepted** — implemented in `f86a55f` (merged in #19).
- Date: 2026-10-14
- Issue: cnds#16

## Context

Both endpoints validate `hours` with `ge=1` only:

- `GET /api/alerts`: `hours: Optional[int] = Query(None, ge=1, ...)` (`src/api/routers/alerts.py:39-40`), used at `alerts.py:59-60`.
- `GET /api/alerts/export`: `hours: Optional[int] = Query(None, ge=1)` (`alerts.py:71`), used at `alerts.py:87-88`.

Both compute `utcnow() - timedelta(hours=hours)`. For about 10^8 hours and up, this raises `OverflowError` (`date value out of range`) and the API returns HTTP 500 instead of a validation error. `GET /api/alerts/trends` already has an upper bound (`le=168`, `alerts.py:146`) and is not affected. The existing test `test_list_alerts_hours_invalid_values` (`tests/test_api.py:468-471`) covers only the lower bound and malformed values.

## Decision drivers

- AC-1, AC-2: huge `hours` must return 422 on both endpoints.
- AC-3: in-bound behaviour is unchanged.
- AC-4: unit tests cover the upper bound on both endpoints.
- Smallest change, following the existing `Query(..., ge=, le=)` pattern. No new dependencies.

## Considered options

1. **Shared constant `MAX_HOURS = 24 * 365 * 10` (10 years) and `le=MAX_HOURS` on both `Query` declarations.** FastAPI returns the standard 422. One value, no duplication, no new code paths. Downside: a hard ceiling, but 10 years is far beyond any realistic retention.
2. **Catch `OverflowError` in the handlers and raise `HTTPException(422)`.** It accepts any value that does not overflow, but it adds try/except in two places, gives a non-standard error body and leaves a de facto bound near 10^8 that is hard to document.
3. **Clamp `hours` silently.** It never errors, but it hides a client mistake and changes semantics, which breaks AC-1.

## Decision

Option 1. Define `MAX_HOURS = 24 * 365 * 10` (87600) in `src/api/routers/alerts.py` and use `le=MAX_HOURS` on `hours` in `list_alerts` and `export_alerts`. The handler bodies are untouched. Update the `list_alerts` `hours` description to mention the maximum.

## Consequences

- Good: bad input now yields a 422 instead of a 500, on both endpoints. The OpenAPI schema documents the maximum.
- Bad: clients that sent `hours` above 87600 (these previously worked up to about 10^8) now get 422. This is unlikely to matter, since such a window already exceeds any practical data retention.
- Migration: none. Rollback: revert the commit.

## Verification

| AC | How it is tested |
|----|------------------|
| AC-1 | `tests/test_api.py`: `GET /api/alerts?hours=1000000000` returns 422 |
| AC-2 | `tests/test_api.py`: `GET /api/alerts/export?hours=1000000000` returns 422 |
| AC-3 | `tests/test_api.py`: `hours=87600` returns 200 on both endpoints, and the existing hours tests still pass |
| AC-4 | The tests above plus the `87601` boundary (422) on both endpoints |
