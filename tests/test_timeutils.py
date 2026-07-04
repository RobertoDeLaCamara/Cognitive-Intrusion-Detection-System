"""Regression test for the tz-aware-vs-naive datetime bug class.

asyncpg rejects binding a tz-aware datetime against this project's naive
DateTime columns. This bug hit production three times (guardian module,
predict.py, suppression.py) before all DateTime defaults/comparisons were
routed through src.timeutils.utcnow(). Guard against it reappearing.
"""

from src.timeutils import utcnow
from src.api.models import Alert, Incident, SuppressionRule, User, MitigationAction


def test_utcnow_is_naive():
    assert utcnow().tzinfo is None


def test_all_datetime_column_defaults_are_naive():
    for model in (Alert(), Incident(), SuppressionRule(), User(), MitigationAction()):
        for col in model.__table__.columns:
            if col.default is not None and col.default.is_callable:
                value = col.default.arg(None)
                if value is not None:
                    assert value.tzinfo is None, f"{model.__class__.__name__}.{col.name} default is tz-aware"
