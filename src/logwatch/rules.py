"""Declarative logwatch rules, loaded from YAML and validated up front.

A rule counts the events that match it per key (source IP or user) inside a sliding window
and fires when the count reaches ``threshold``. Example::

    - name: gitea_login_bruteforce
      service: gitea
      description: Gitea login brute force
      match: {method: POST, path: '^/user/login$', status: 200}
      group_by: ip
      threshold: 5
      window_secs: 600
      cooldown_secs: 3600
      severity: high
      mitre: [{id: T1110, name: Brute Force, tactic: Credential Access}]

``match`` is one condition or a list of conditions (any may match). A condition may set
``method`` (string or list), ``path`` (regex searched in the path, query excluded) and
``status`` (int or list). ``untrusted_only: true`` ignores events from trusted networks.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Sequence, Union

import yaml

from .events import LogEvent

SEVERITIES = ("low", "medium", "high", "critical")
GROUP_BY = ("ip", "user")


class RuleError(ValueError):
    """A rules file is malformed. The message names the file and the rule."""


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


@dataclass(frozen=True)
class Condition:
    methods: Optional[frozenset] = None
    path: Optional[Pattern] = None
    statuses: Optional[frozenset] = None

    def matches(self, ev: LogEvent) -> bool:
        if self.methods is not None and (ev.method or "").upper() not in self.methods:
            return False
        if self.path is not None and not self.path.search(ev.path or ""):
            return False
        if self.statuses is not None and ev.status not in self.statuses:
            return False
        return True


@dataclass(frozen=True)
class Rule:
    name: str
    service: str
    description: str
    conditions: Sequence[Condition]
    group_by: str
    threshold: int
    window_secs: int
    cooldown_secs: int
    severity: str
    untrusted_only: bool = False
    mitre: List[Dict[str, str]] = field(default_factory=list)

    def matches(self, ev: LogEvent) -> bool:
        return ev.service == self.service and any(c.matches(ev) for c in self.conditions)


def _condition(raw: Any, where: str) -> Condition:
    if not isinstance(raw, dict) or not raw:
        raise RuleError(f"{where}: each match condition must be a non-empty mapping")
    unknown = set(raw) - {"method", "path", "status"}
    if unknown:
        raise RuleError(f"{where}: unknown match keys {sorted(unknown)}")
    path = None
    if "path" in raw:
        try:
            path = re.compile(str(raw["path"]))
        except re.error as exc:
            raise RuleError(f"{where}: invalid path regex {raw['path']!r}: {exc}") from exc
    statuses = None
    if "status" in raw:
        try:
            statuses = frozenset(int(s) for s in _as_list(raw["status"]))
        except (TypeError, ValueError) as exc:
            raise RuleError(f"{where}: status must be an int or a list of ints") from exc
    methods = frozenset(str(m).upper() for m in _as_list(raw["method"])) if "method" in raw else None
    return Condition(methods=methods, path=path, statuses=statuses)


def _rule(raw: Dict[str, Any], source: str) -> Rule:
    name = raw.get("name")
    where = f"{source}: rule {name!r}"
    if not name or not isinstance(name, str):
        raise RuleError(f"{source}: every rule needs a string 'name'")
    for key in ("service", "match", "threshold", "window_secs", "severity"):
        if key not in raw:
            raise RuleError(f"{where}: missing '{key}'")
    if raw["severity"] not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {SEVERITIES}")
    group_by = raw.get("group_by", "ip")
    if group_by not in GROUP_BY:
        raise RuleError(f"{where}: group_by must be one of {GROUP_BY}")
    for key in ("threshold", "window_secs"):
        if not isinstance(raw[key], int) or raw[key] < 1:
            raise RuleError(f"{where}: '{key}' must be a positive integer")
    cooldown = raw.get("cooldown_secs", raw["window_secs"])
    if not isinstance(cooldown, int) or cooldown < 0:
        raise RuleError(f"{where}: 'cooldown_secs' must be a non-negative integer")
    if not raw["match"]:
        raise RuleError(f"{where}: 'match' must have at least one condition (an empty match never fires)")
    conditions = tuple(_condition(c, where) for c in _as_list(raw["match"]))
    return Rule(
        name=name, service=str(raw["service"]), description=str(raw.get("description") or name),
        conditions=conditions, group_by=group_by, threshold=raw["threshold"],
        window_secs=raw["window_secs"], cooldown_secs=cooldown, severity=raw["severity"],
        untrusted_only=bool(raw.get("untrusted_only", False)),
        mitre=[dict(t) for t in raw.get("mitre", [])],
    )


def load_rules(path: Union[str, Path]) -> List[Rule]:
    """Load every ``*.yaml`` rules file under ``path`` (or the single file ``path``).

    Raises ``RuleError`` on the first problem and on duplicate rule names, so a typo never
    silently disables a detection.
    """
    path = Path(path)
    files = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
    if not files:
        raise RuleError(f"{path}: no rules files found")
    rules: List[Rule] = []
    seen: Dict[str, str] = {}
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text()) or {}
        except yaml.YAMLError as exc:
            raise RuleError(f"{f}: invalid YAML: {exc}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
            raise RuleError(f"{f}: expected a top-level 'rules:' list")
        for raw in doc["rules"]:
            rule = _rule(raw, str(f))
            if rule.name in seen:
                raise RuleError(f"{f}: duplicate rule name {rule.name!r} (also in {seen[rule.name]})")
            seen[rule.name] = str(f)
            rules.append(rule)
    return rules
