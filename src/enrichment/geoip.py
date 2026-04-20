"""GeoIP enrichment using MaxMind GeoLite2 database."""

import logging
from typing import Optional, Dict
import os

from ..config import GEOIP_DB_PATH

logger = logging.getLogger(__name__)

_reader = None


def _init():
    global _reader
    if _reader is not None or not GEOIP_DB_PATH:
        return
    try:
        if os.path.exists(GEOIP_DB_PATH):
            import geoip2.database
            _reader = geoip2.database.Reader(GEOIP_DB_PATH)
            logger.info("GeoIP database loaded from %s", GEOIP_DB_PATH)
    except Exception as e:
        logger.warning("GeoIP database failed to load: %s", e)


def lookup(ip: str) -> Optional[Dict]:
    _init()
    if not _reader:
        return None
    try:
        r = _reader.city(ip)
        return {
            "country": r.country.iso_code,
            "city": r.city.name,
            "lat": float(r.location.latitude or 0),
            "lon": float(r.location.longitude or 0),
        }
    except Exception:
        return None


def is_enabled() -> bool:
    _init()
    return _reader is not None
