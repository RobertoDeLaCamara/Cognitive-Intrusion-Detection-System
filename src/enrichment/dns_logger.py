"""DNS query logging from captured packets (Phase 8)."""

import logging
from collections import OrderedDict
from typing import Optional, Dict

from scapy.all import IP, UDP, DNS, DNSQR

from ..config import DNS_LOGGING_ENABLED, MAX_TRACKED_IPS

logger = logging.getLogger(__name__)

# Recent DNS queries: {src_ip: [domain, ...]}
_dns_log: OrderedDict = OrderedDict()
_MAX_PER_IP = 100
_MAX_IPS = MAX_TRACKED_IPS


def extract_dns_query(packet) -> Optional[Dict]:
    """Extract DNS query info from a packet. Returns None if not a DNS query."""
    if not DNS_LOGGING_ENABLED:
        return None
    if not (IP in packet and UDP in packet and DNS in packet):
        return None
    dns = packet[DNS]
    if dns.qr != 0 or not dns.qd:  # qr=0 means query
        return None

    src_ip = packet[IP].src
    domain = dns[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
    qtype = dns[DNSQR].qtype

    entry = {
        "src_ip": src_ip,
        "domain": domain,
        "qtype": qtype,
    }

    # Store in memory log with LRU eviction
    if src_ip in _dns_log:
        _dns_log.move_to_end(src_ip)
    elif len(_dns_log) >= _MAX_IPS:
        _dns_log.popitem(last=False)

    log = _dns_log.get(src_ip, [])
    log.append(domain)
    if len(log) > _MAX_PER_IP:
        log = log[-_MAX_PER_IP:]
    _dns_log[src_ip] = log

    return entry


def get_dns_log(ip: str) -> list:
    """Return recent DNS queries for an IP."""
    return list(_dns_log.get(ip, []))


def get_all_logs() -> dict:
    """Return all DNS logs."""
    return {ip: list(domains) for ip, domains in _dns_log.items()}
