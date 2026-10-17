# 0003. Refuse to start the API unless an auth mode is configured

- Status: **Accepted**
- Date: 2026-10-16
- Issue: cnds#20 (CWE-306, OWASP A07)

## Context

Authentication is opt-in and silently off by default:

- `API_KEY = os.getenv("API_KEY", "")   # empty = no auth` (`src/config.py:166`) and `JWT_SECRET = os.getenv("JWT_SECRET", "")` (`src/config.py:170`).
- The API-key middleware is only registered `if API_KEY:` (`src/api/main.py:102-113`). JWT RBAC is active only when `JWT_SECRET` is non-empty (`src/api/auth.py:26`).
- Production `docker-compose.yml:31-33` runs `uvicorn ... --host 0.0.0.0` and publishes `8000:8000`. It loads `.env.example` first, then `.env` (`docker-compose.yml:36-42`), and `.env.example:82,88` ships both credentials empty. A deployment that forgets `.env` exposes every write route, `/api/alerts/export` and the user admin endpoints to the LAN.
- `.env.sandbox:65,69` deliberately leaves both empty for the sandbox (`docker-compose.sandbox.yml:65-81`).
- The API is started two ways: by uvicorn importing `src.api.main:app` (`Dockerfile:41`, both compose files), and in-process by `main.py --api`, which imports `src.api.main` in the main thread before starting uvicorn in a daemon thread (`main.py:64-71`).
- Config validation already fails fast at import for bad values (`src/config.py:15-58,313`), but `src.config` is also imported by the detector, the triage agent and the MCP server, none of which serve HTTP.
- `tests/test_auth.py:11` imports `src.api.main` at module level. `tests/conftest.py:5-15` already sets env defaults before any `src` import.

## Decision drivers

- AC-1: no credentials and no `AUTH_DISABLED=true` → non-zero exit at startup, and the message names `API_KEY`, `JWT_SECRET`, `AUTH_DISABLED`.
- AC-2: with `API_KEY` or `JWT_SECRET` set, behaviour is unchanged.
- AC-3: `AUTH_DISABLED=true` is the only way to run open, and it logs a warning.
- AC-4: sandbox opts in explicitly. Production compose does not. Documented in `.env.example` and the README.
- AC-5: tests for the four cases, and the existing suite keeps passing.
- Smallest change, no new dependencies, and only the HTTP API is affected.

## Considered options

1. **Module-level guard in `src/api/main.py`** (chosen). A small function checks the three settings and `raise SystemExit(msg)` when no auth mode is configured. It is called right after the logger is created and before `app` is built. If uvicorn cannot import the app, it exits non-zero. Under `main.py --api` the `SystemExit` happens in the main thread during `from src.api.main import app`, so the whole process stops before capture starts. Only the API is affected. Downside: anything that imports `src.api.main` needs a configured auth mode, including tests, which is handled in `conftest.py`.
2. **Guard in the FastAPI `lifespan`.** Uvicorn standalone exits with code 3 on a startup failure. But under `main.py --api` uvicorn runs in a daemon thread, so a lifespan failure only kills that thread and the detector keeps running headless. That does not "exit at startup". Tests that do not enter the lifespan would never exercise it.
3. **Add the check to `_validate_config()` in `src/config.py`.** It is the most central option, but it would also stop the detector, the triage agent and the MCP server, which import `src.config` and serve no HTTP. Production `detector` and the Jenkins triage job would break without any security gain.
4. **Bind to `127.0.0.1` when unauthenticated.** The issue rules this out: the container CMD hardcodes `--host 0.0.0.0`, and a localhost bind inside a container breaks the published port and the compose healthcheck path from other services.

## Decision

Option 1.

- `src/config.py`: next to `API_KEY`, add `AUTH_DISABLED = os.getenv("AUTH_DISABLED", "false").strip().lower() == "true"`. Only the literal `true` (any case) opts out, so typos fail closed.
- `src/api/main.py`: import `JWT_SECRET` and `AUTH_DISABLED` from config, and add `_enforce_auth_configured(api_key: str, jwt_secret: str, auth_disabled: bool) -> None`:
  - if `api_key` or `jwt_secret` is set: return (today's behaviour, and `AUTH_DISABLED` is ignored because credentials always win);
  - elif `auth_disabled`: `logger.warning(...)` saying authentication is disabled and every endpoint is open, then return;
  - else: `logger.critical(msg)` and `raise SystemExit(msg)`. The message names `API_KEY`, `JWT_SECRET` and `AUTH_DISABLED=true`. `SystemExit` with a string prints to stderr and exits with status 1.
  - Call it once at module level: `_enforce_auth_configured(API_KEY, JWT_SECRET, AUTH_DISABLED)`, placed before `app = FastAPI(...)`.
- `.env.sandbox`: add `AUTH_DISABLED=true` in the API block with a comment. `docker-compose.sandbox.yml`: add `AUTH_DISABLED: "true"` to the `api` service `environment:`.
- `.env.example`: add a commented `AUTH_DISABLED=false` line with an explanation. It must **not** be `true`, because production compose loads `.env.example`. Update the `API_KEY`/`JWT_SECRET` comments ("leave empty to disable" is no longer true on its own).
- `README.md`: add an `AUTH_DISABLED` row to the configuration table and fix the `API_KEY`/`JWT_SECRET` descriptions. Production `docker-compose.yml` is not changed.
- `tests/conftest.py`: `os.environ.setdefault("AUTH_DISABLED", "true")` next to the existing defaults, so the existing suite still imports `src.api.main`.
- `CHANGELOG.md`: add a breaking-change entry under Unreleased.

## Consequences

- Good: an unconfigured production API can no longer come up open on `0.0.0.0:8000`. Running open is now an explicit, logged choice. No new dependencies.
- Bad (breaking): any existing deployment without `API_KEY`/`JWT_SECRET` now fails at startup. Under `restart: unless-stopped` the `api` container will restart in a loop until `.env` is fixed. This is intended, but the deploy notes must say so. The detector and the dashboard depend on the API's health, so they will not come up healthy either.
- Bad: `main.py --api` without credentials now aborts the whole process, not just the API. This is consistent with AC-1.
- Migration: no DB change. Operators set `JWT_SECRET` (preferred) or `API_KEY` in `.env` before redeploying, or set `AUTH_DISABLED=true` on purpose for local or lab use.
- Rollback: revert the commit, or set `AUTH_DISABLED=true` as an immediate operational escape hatch.

## Verification

| AC | How it is tested |
|----|------------------|
| AC-1 | `tests/test_auth_startup_guard.py`: `_enforce_auth_configured("", "", False)` raises `SystemExit` whose message contains `API_KEY`, `JWT_SECRET`, `AUTH_DISABLED`. A subprocess test runs `python -c "import src.api.main"` with all three variables removed from the env and asserts a non-zero return code and the three names in stderr. |
| AC-2 | Same file: `_enforce_auth_configured("k", "", False)` and `("", "s", False)` return `None` with no warning logged. The existing `tests/test_auth.py` JWT tests still pass. |
| AC-3 | Same file: `_enforce_auth_configured("", "", True)` returns, and `caplog.text` contains the "authentication is disabled" warning. `AUTH_DISABLED` parsing: `"TRUE"`/`"true"` → True, `"1"`/`"yes"`/`""` → False (checked in a subprocess with `python -c "from src.config import AUTH_DISABLED; print(AUTH_DISABLED)"`, so `src.config` is never reloaded in the test process). |
| AC-4 | Same file: a static test reads `.env.sandbox` and `docker-compose.sandbox.yml` (the `AUTH_DISABLED=true` line, and `AUTH_DISABLED: "true"` under the `api` service), asserts that `docker-compose.yml` does not contain `AUTH_DISABLED`, that `.env.example` does not set it to `true`, and that `.env.example` and `README.md` mention `AUTH_DISABLED`. |
| AC-5 | The tests above plus the full suite: `pytest -q`. `conftest.py` supplies `AUTH_DISABLED=true`. |
