"""Threat Intelligence Feed integration for CNDS.

Fetches and caches external IOC feeds (IPs, JA3 hashes, domains)
from public threat intelligence sources. Provides runtime lookups
to enrich detection with known-bad indicators.

Supported feeds (configurable via env):
  - ABUSEIPDB_URL: AbuseIPDB blocklist (CSV of malicious IPs)
  - MALICIOUS_JA3_URL: URL to a raw JA3 hash list (one per line)
  - MISP_URL / MISP_API_KEY: MISP instance for custom IOC pulls

Feeds are refreshed every THREAT_INTEL_REFRESH_MINUTES (default: 60).
"""

import logging
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Set, Tuple

import requests

logger = logging.getLogger(__name__)


# ── Config from env ────────────────────────────────────────────────────────────
ABUSEIPDB_URL = os.getenv("ABUSEIPDB_URL", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
MALICIOUS_JA3_URL = os.getenv("MALICIOUS_JA3_URL", "")
MISP_URL = os.getenv("MISP_URL", "")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
REFRESH_MINUTES = int(os.getenv("THREAT_INTEL_REFRESH_MINUTES", "60"))


@dataclass
class ThreatIntelStore:
    """In-memory store of threat intelligence indicators with automatic refresh."""
    malicious_ips: Set[str] = field(default_factory=set)
    malicious_ja3: Set[str] = field(default_factory=set)
    malicious_domains: Set[str] = field(default_factory=set)
    last_refresh: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def is_ip_malicious(self, ip: str) -> bool:
        """Check if an IP is in the malicious set."""
        return ip in self.malicious_ips

    def is_ja3_malicious(self, ja3_hash: str) -> bool:
        """Check if a JA3 hash is in the malicious set."""
        return ja3_hash in self.malicious_ja3

    def is_domain_malicious(self, domain: str) -> bool:
        """Check if a domain suffix matches any known malicious domain (case-insensitive)."""
        domain = domain.lower().strip()
        for bad_domain in self.malicious_domains:
            bad = bad_domain.lower().strip()
            if domain == bad or domain.endswith("." + bad):
                return True
        return False

    def stale(self) -> bool:
        """Return True if the store needs a refresh."""
        if REFRESH_MINUTES <= 0:
            return False
        elapsed = time.time() - self.last_refresh
        return elapsed > REFRESH_MINUTES * 60

    def refresh(self) -> None:
        """Refresh all configured feeds."""
        with self._lock:
            logger.info("Refreshing threat intelligence feeds...")
            if ABUSEIPDB_URL:
                self._fetch_abuseipdb()
            if MALICIOUS_JA3_URL:
                self._fetch_ja3_feeds()
            if MISP_URL and MISP_API_KEY:
                self._fetch_misp()
            self.last_refresh = time.time()
            logger.info(
                "Threat intel refreshed: %d IPs, %d JA3 hashes, %d domains",
                len(self.malicious_ips), len(self.malicious_ja3), len(self.malicious_domains),
            )

    def _fetch_abuseipdb(self) -> None:
        """Fetch IP blocklist from AbuseIPDB blacklist CSV."""
        try:
            headers = {"Key": ABUSEIPDB_API_KEY} if ABUSEIPDB_API_KEY else {}
            resp = requests.get(ABUSEIPDB_URL, headers=headers, timeout=15)
            resp.raise_for_status()
            ips = set()
            for line in resp.text.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("IP"):
                    continue
                ip = line.split(",")[0].strip()
                if ip:
                    ips.add(ip)
            if ips:
                self.malicious_ips = ips
                logger.info("AbuseIPDB: loaded %d malicious IPs", len(ips))
            else:
                logger.warning("AbuseIPDB returned empty set — keeping previous data")
        except Exception as e:
            logger.warning("Failed to fetch AbuseIPDB feed: %s", e)

    def _fetch_ja3_feeds(self) -> None:
        """Fetch malicious JA3 hash list from URL."""
        try:
            resp = requests.get(MALICIOUS_JA3_URL, timeout=15)
            resp.raise_for_status()
            ja3_set = set()
            for line in resp.text.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ja3_set.add(line)
            if ja3_set:
                self.malicious_ja3 = ja3_set
                logger.info("JA3 feed: loaded %d malicious hashes", len(ja3_set))
        except Exception as e:
            logger.warning("Failed to fetch JA3 feed: %s", e)

    def _fetch_misp(self) -> None:
        """Fetch indicators from a MISP instance."""
        try:
            headers = {
                "Authorization": MISP_API_KEY,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            payload = {
                "returnFormat": "json",
                "type": {"OR": ["ip-src", "ip-dst", "domain", "domain|ip"]},
                "page": 1,
                "limit": 1000,
            }
            resp = requests.post(
                f"{MISP_URL.rstrip('/')}/attributes/restSearch",
                json=payload, headers=headers, timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            attributes = data.get("response", {}).get("Attribute", [])
            ips = set()
            domains = set()
            for attr in attributes:
                val = attr.get("value", "").strip()
                attr_type = attr.get("type", "")
                if attr_type in ("ip-src", "ip-dst") and val:
                    ips.add(val)
                elif attr_type in ("domain",) and val:
                    domains.add(val)
                elif attr_type == "domain|ip":
                    parts = val.split("|")
                    if parts[0].strip():
                        domains.add(parts[0].strip())
                    if len(parts) > 1 and parts[1].strip():
                        ips.add(parts[1].strip())
            if ips:
                self.malicious_ips.update(ips)
            if domains:
                self.malicious_domains.update(domains)
            logger.info("MISP: loaded %d IPs, %d domains", len(ips), len(domains))
        except Exception as e:
            logger.warning("Failed to fetch MISP feed: %s", e)


# ── Global singleton ───────────────────────────────────────────────────────────
_intel_store: Optional[ThreatIntelStore] = None
_intel_lock = threading.Lock()


def get_store() -> ThreatIntelStore:
    """Return the global ThreatIntelStore singleton."""
    global _intel_store
    with _intel_lock:
        if _intel_store is None:
            _intel_store = ThreatIntelStore()
            _intel_store.refresh()
        elif _intel_store.stale():
            # Background refresh — don't block the caller
            t = threading.Thread(target=_intel_store.refresh, daemon=True, name="threat-intel-refresh")
            t.start()
    return _intel_store


def check_ip(ip: str) -> Tuple[bool, str]:
    """Check IP against threat intel. Returns (is_malicious, source_label)."""
    store = get_store()
    if store.is_ip_malicious(ip):
        return True, "threat_intel_feed"
    return False, ""


def check_ja3(ja3_hash: str) -> Tuple[bool, str]:
    """Check JA3 hash against threat intel. Returns (is_malicious, source_label)."""
    store = get_store()
    if store.is_ja3_malicious(ja3_hash):
        return True, "threat_intel_feed"
    return False, ""


def check_domain(domain: str) -> Tuple[bool, str]:
    """Check domain against threat intel. Returns (is_malicious, source_label)."""
    store = get_store()
    if store.is_domain_malicious(domain):
        return True, "threat_intel_feed"
    return False, ""
