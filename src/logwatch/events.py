"""Data types shared by the log parsers, the rule engine and the persistence layer."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class LogEvent:
    """One parsed log line. ``ts`` is epoch seconds (UTC)."""
    ts: float
    service: str
    ip: Optional[str] = None
    user: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    raw: str = ""


@dataclass
class LogAlert:
    """A rule fired for one key (usually a source IP)."""
    rule: str
    service: str
    description: str
    severity: str
    key: str
    ip: Optional[str]
    count: int
    window_secs: int
    first_ts: float
    last_ts: float
    cooldown_secs: int = 0
    mitre: List[Dict[str, str]] = field(default_factory=list)
    samples: List[str] = field(default_factory=list)
