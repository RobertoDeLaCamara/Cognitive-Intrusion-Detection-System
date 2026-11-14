# 0004. Refuse to start the API when a migration fails on an Alembic-managed database

- Status: **Accepted**
- Date: 2026-11-11

## Context

`init_db()` (`src/api/database.py`) runs `alembic upgrade head` when the API starts. When that failed, it fell back to `Base.metadata.create_all` and the API started. Until PR #100 the fallback was silent; since then it logs an ERROR.

`create_all` only creates missing tables. It never alters an existing one. After a failed migration the API therefore served on a schema that could be behind the models, and the failure showed up later as HTTP 500 on whichever query touched a new column, far from the cause.

The fallback is not only an error path, though. A database whose tables were created by `create_all` has no Alembic revision, and `alembic upgrade head` fails on it with "table ... already exists". The detector creates tables that way (`_init_db` in `src/pipeline.py`) whenever it writes to a database the API has never initialised: a detector-only deployment that later adds the API, or `main.py --api` on a fresh SQLite file if the detector writes first. For those databases the fallback is what lets the API start at all.

## Decision drivers

- A failed migration must be visible at once, at the place it happens.
- Existing databases without a revision must keep working: breaking them would turn a safety change into an outage for anyone who ran the detector first.
- No new configuration switch. Smallest change.

## Considered options

1. **Always refuse to start on a failed migration.** Simplest and strictest, but it breaks every database born from `create_all`, which the project itself produces.
2. **Refuse only when the database carries an Alembic revision** (chosen). A database with a revision is managed by Alembic: a failure there means the schema is behind the code, so the API must not serve. A database without a revision keeps the old fallback, now with an error that explains how to adopt it.
3. **Stamp revision-less databases automatically.** `alembic stamp head` would silence the failure, but it asserts the schema matches `head` without checking. A database created by an older release would be marked current while missing columns.
4. **Keep starting, rely on the ERROR log.** This is the behaviour since #100. The log is easy to miss and the API still serves on a stale schema.

## Decision

Option 2.

- `init_db()` catches the migration failure and reads the current revision (`MigrationContext.get_current_revision()`).
  - Revision present: log CRITICAL with the traceback and raise `MigrationError`. The FastAPI lifespan fails and uvicorn exits non-zero.
  - No revision (including an empty `alembic_version` table, which Alembic leaves behind when the first migration fails): log ERROR, fall back to `create_all`, and tell the operator to run `alembic stamp <revision>` once the schema matches a revision.
  - The revision cannot be read (database unreachable): the exception propagates and the API does not start.
- A missing `alembic.ini` still means `create_all` with a WARNING. In-memory databases (tests) are unchanged.

## Consequences

- Good: on the deployments that matter (PostgreSQL initialised by the API), a broken migration stops the API at startup with the cause in the log, instead of surfacing later as scattered 500s.
- Bad: while the API is down, so are the dashboard's data, the WebSocket stream and the Guardian (it runs in the API lifespan), so there is no auto-blocking until the migration is fixed. The detector is a separate process and keeps capturing and writing alerts.
- Bad: under `restart: unless-stopped` the `api` container restart-loops until someone intervenes. That is the intended signal.
- `main.py --api` runs uvicorn in a daemon thread: there the API thread stops and capture continues without an API.
- The triage agent (`python -m src.triage`) calls `init_db()` too and now exits on the same condition.
- Rollback: revert the commit. There is no switch to bypass the check.

## Verification

`tests/test_init_db_migrations.py`: managed database refuses to start and no `create_all` runs behind the failure; `create_all`-born database still starts; an empty `alembic_version` table does not count as managed; an unreachable database refuses to start; the API lifespan does not reach the serving state.
