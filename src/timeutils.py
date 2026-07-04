"""Shared naive-UTC time helper.

Every DateTime column in src/api/models.py is a plain (timezone-naive)
column. asyncpg — used by every async session in this project — rejects
binding or comparing a timezone-aware datetime against a "timestamp
without time zone" column with a DataError ("can't subtract offset-naive
and offset-aware datetimes"). psycopg2 (the sync driver used by
src/pipeline.py) is lenient about this, which is why the bug only
surfaces on the async API paths.

Use utcnow() instead of datetime.now(timezone.utc) anywhere the result
is bound into or compared against one of these columns.
"""

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
