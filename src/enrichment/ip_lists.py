"""IP allowlist and blocklist (Phase 9).

Allowlisted IPs bypass detection entirely.
Blocklisted IPs are auto-flagged with score=1.0.

Supports both individual IPs and CIDR ranges (e.g. 10.0.0.0/8).
"""

import ipaddress

from ..config import IP_ALLOWLIST, IP_BLOCKLIST


def _matches(ip_str: str, raw_entries: set) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in raw_entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def is_allowlisted(ip: str) -> bool:
    return _matches(ip, IP_ALLOWLIST)


def is_blocklisted(ip: str) -> bool:
    return _matches(ip, IP_BLOCKLIST)
