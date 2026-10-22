"""Parser for Gitea's HTTP access log lines.

    2026/10/22 17:13:02 HTTPRequest [I] router: completed POST /user/sign_up for 31.56.209.86:33978, 403 Forbidden in 1.1ms @ auth/auth.go:538(auth.SignUpPost)

Gitea writes the timestamp in the container's local time; pass ``ts`` (e.g. the Loki entry
timestamp) to skip that and avoid timezone guesses.
"""

import re
from datetime import datetime, timezone, tzinfo
from typing import Optional

from .events import LogEvent

SERVICE = "gitea"

_LINE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) HTTPRequest \[\w\] router: "
    r"completed (?P<method>[A-Z]+) (?P<target>\S+) for (?P<addr>\S+), (?P<status>\d{3}) "
)


def _split_addr(addr: str) -> str:
    """'1.2.3.4:55' -> '1.2.3.4'; '[2001:db8::1]:55' -> '2001:db8::1'."""
    host = addr.rsplit(":", 1)[0] if ":" in addr else addr
    return host.strip("[]")


def parse_line(line: str, ts: Optional[float] = None, tz: tzinfo = timezone.utc) -> Optional[LogEvent]:
    """Return a ``LogEvent`` for an access-log line, or ``None`` for anything else."""
    m = _LINE.match(line)
    if not m:
        return None
    if ts is None:
        local = datetime.strptime(f"{m['date']} {m['time']}", "%Y/%m/%d %H:%M:%S")
        ts = local.replace(tzinfo=tz).timestamp()
    return LogEvent(
        ts=ts, service=SERVICE, ip=_split_addr(m["addr"]), method=m["method"],
        path=m["target"].split("?", 1)[0], status=int(m["status"]), raw=line.rstrip("\n"),
    )
