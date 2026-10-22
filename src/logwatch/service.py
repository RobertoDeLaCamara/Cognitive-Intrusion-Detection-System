"""Build the watcher from configuration and run it (started from the API lifespan)."""

import logging
from pathlib import Path

from .. import config
from ..api.database import AsyncSessionLocal
from . import gitea
from .engine import LogRuleEngine, parse_networks
from .loki import LokiSource
from .rules import load_rules
from .watcher import LogWatcher, run

logger = logging.getLogger(__name__)

PARSERS = {gitea.SERVICE: gitea.parse_line}
DEFAULT_RULES_DIR = Path(__file__).parent / "rules"


def build_watcher() -> LogWatcher:
    unknown = set(config.LOGWATCH_STREAMS) - set(PARSERS)
    if unknown:
        raise ValueError(f"LOGWATCH_STREAMS has services without a parser: {sorted(unknown)}")
    rules = load_rules(config.LOGWATCH_RULES_DIR or DEFAULT_RULES_DIR)   # bad rules stop startup, loudly
    engine = LogRuleEngine(rules, trusted=parse_networks(config.LOGWATCH_TRUSTED_CIDRS))
    source = LokiSource(
        config.LOKI_URL, config.LOGWATCH_STREAMS, user=config.LOKI_USER, password=config.LOKI_PASSWORD,
        batch=config.LOGWATCH_BATCH, backfill_secs=config.LOGWATCH_BACKFILL_SECS, lag_secs=config.LOGWATCH_LAG_SECS)
    return LogWatcher(source, engine, {s: PARSERS[s] for s in config.LOGWATCH_STREAMS},
                      silent_polls=config.LOGWATCH_SILENT_POLLS)


async def logwatch_loop() -> None:
    watcher = build_watcher()
    try:
        await run(watcher, AsyncSessionLocal, config.LOGWATCH_POLL_SECS)
    finally:
        await watcher.source.aclose()
