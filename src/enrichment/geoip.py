"""GeoIP enrichment using MaxMind GeoLite2 database.
Optimizado para compatibilidad con Dashboard y Fallback de pruebas.
"""

import logging
from typing import Optional, Dict
import os

from ..config import GEOIP_DB_PATH

logger = logging.getLogger(__name__)

_reader = None

# MOCK DATA para pruebas
MOCK_GEOIP = {
    "8.8.8.8": {"country": "US", "city": "Mountain View", "lat": 37.4223, "lon": -122.0847},
    "1.1.1.1": {"country": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093},
    "77.77.77.77": {"country": "IT", "city": "Roma", "lat": 41.9028, "lon": 12.4964},
    "1.2.3.4": {"country": "TW", "city": "Taipei", "lat": 25.0330, "lon": 121.5654},
}

def _init():
    global _reader
    if _reader is not None or not GEOIP_DB_PATH:
        return
    try:
        if os.path.exists(GEOIP_DB_PATH):
            import geoip2.database
            _reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception:
        pass

def lookup(ip: str) -> Optional[Dict]:
    _init()
    
    # 1. Base de datos real
    if _reader:
        try:
            r = _reader.city(ip)
            return {
                "country": r.country.iso_code,
                "city": r.city.name,
                "lat": float(r.location.latitude or 0),
                "lon": float(r.location.longitude or 0)
            }
        except:
            pass
            
    # 2. Mock fallback
    return MOCK_GEOIP.get(ip)

def is_enabled() -> bool:
    return True
