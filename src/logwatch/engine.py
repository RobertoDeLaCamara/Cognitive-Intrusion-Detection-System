"""Sliding-window evaluation of logwatch rules."""

import ipaddress
from collections import deque
from typing import Deque, Dict, Iterable, List, Optional, Sequence, Tuple

from .events import LogAlert, LogEvent
from .rules import Rule

MAX_SAMPLES = 3
MAX_WINDOW_EVENTS = 10_000   # per (rule, key): bounds memory under a flood
MAX_KEYS_PER_RULE = 50_000


def parse_networks(cidrs: Iterable[str]) -> List[ipaddress._BaseNetwork]:
    """Parse comma-separated-config style CIDRs; a bare address means /32 (or /128)."""
    return [ipaddress.ip_network(c.strip(), strict=False) for c in cidrs if c and c.strip()]


class LogRuleEngine:
    """Feed it ``LogEvent``s in time order; it returns the alerts they trigger.

    Time comes from the events, never from the wall clock, so replaying an old log gives
    the same alerts as watching it live. After firing, a (rule, key) is silent for the
    rule's ``cooldown_secs``.
    """

    def __init__(self, rules: Sequence[Rule], trusted: Sequence = ()):
        self._by_service: Dict[str, List[Rule]] = {}
        for rule in rules:
            self._by_service.setdefault(rule.service, []).append(rule)
        self._trusted = list(trusted)
        self._hits: Dict[Tuple[str, str], Deque[Tuple[float, str]]] = {}
        self._last_alert: Dict[Tuple[str, str], float] = {}
        self._keys_per_rule: Dict[str, int] = {}

    def is_trusted(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._trusted)

    def feed(self, ev: LogEvent) -> List[LogAlert]:
        alerts: List[LogAlert] = []
        for rule in self._by_service.get(ev.service, ()):
            if not rule.matches(ev):
                continue
            if rule.untrusted_only and self.is_trusted(ev.ip):
                continue
            key = ev.ip if rule.group_by == "ip" else ev.user
            if not key:
                continue
            alert = self._observe(rule, key, ev)
            if alert:
                alerts.append(alert)
        return alerts

    def _observe(self, rule: Rule, key: str, ev: LogEvent) -> Optional[LogAlert]:
        slot = (rule.name, key)
        hits = self._hits.get(slot)
        if hits is None:
            self._evict_if_full(rule.name, ev.ts, rule.window_secs)
            hits = self._hits[slot] = deque(maxlen=MAX_WINDOW_EVENTS)
            self._keys_per_rule[rule.name] = self._keys_per_rule.get(rule.name, 0) + 1
        hits.append((ev.ts, ev.raw))
        while hits and hits[0][0] < ev.ts - rule.window_secs:
            hits.popleft()
        if len(hits) < rule.threshold:
            return None
        last = self._last_alert.get(slot)
        if last is not None and ev.ts - last < rule.cooldown_secs:
            return None
        self._last_alert[slot] = ev.ts
        return LogAlert(
            rule=rule.name, service=rule.service, description=rule.description,
            severity=rule.severity, key=key, ip=ev.ip, count=len(hits),
            window_secs=rule.window_secs, first_ts=hits[0][0], last_ts=ev.ts,
            mitre=[dict(t) for t in rule.mitre],
            samples=[raw for _, raw in list(hits)[-MAX_SAMPLES:] if raw],
        )

    def _evict_if_full(self, rule_name: str, now: float, window: int) -> None:
        """Keep memory bounded: drop expired keys first, then the oldest inserted ones."""
        if self._keys_per_rule.get(rule_name, 0) < MAX_KEYS_PER_RULE:
            return
        slots = [s for s in self._hits if s[0] == rule_name]
        for slot in slots:
            hits = self._hits[slot]
            if not hits or hits[-1][0] < now - window:
                self._drop(slot)
        for slot in slots:
            if self._keys_per_rule.get(rule_name, 0) < MAX_KEYS_PER_RULE:
                break
            if slot in self._hits:
                self._drop(slot)

    def _drop(self, slot: Tuple[str, str]) -> None:
        self._hits.pop(slot, None)
        self._last_alert.pop(slot, None)
        self._keys_per_rule[slot[0]] = max(self._keys_per_rule.get(slot[0], 1) - 1, 0)
