"""Log a repeating failure once instead of on every occurrence.

Several code paths run once per flow or every few seconds (host features, the
baseline collector, the metrics scrape loop). Swallowing their errors hides a
broken engine; logging each one floods the log. A FailureStreak logs the first
failure of a streak at WARNING with the traceback, the following ones at DEBUG,
and the recovery at INFO.
"""

import logging


class FailureStreak:
    def __init__(self, logger: logging.Logger, what: str):
        self._logger = logger
        self._what = what
        self._failing = False

    @property
    def failing(self) -> bool:
        return self._failing

    def failed(self, exc: BaseException) -> None:
        """Record a failure. Call it from the `except` block."""
        if self._failing:
            self._logger.debug("%s still failing: %s", self._what, exc)
            return
        self._failing = True
        self._logger.warning(
            "%s failed (further failures are logged at DEBUG until it recovers): %s",
            self._what, exc, exc_info=exc,
        )

    def ok(self) -> None:
        """Record a success. Cheap enough for a per-flow path."""
        if self._failing:
            self._failing = False
            self._logger.info("%s recovered", self._what)
