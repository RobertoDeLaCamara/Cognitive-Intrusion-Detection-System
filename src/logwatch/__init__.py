"""logwatch: detect attacks on exposed services from their application logs.

The capture pipeline only sees packets; sign-up floods, login brute force or admin access
from unknown IPs show up in service logs. logwatch turns log lines into ``LogEvent``s,
runs them through declarative sliding-window rules and produces alerts with
``source="logwatch"``.

It is read-only by design: the Guardian only acts on the sources listed in
``GUARDIAN_ALERT_SOURCES`` (``detector`` by default), so logwatch alerts never block anything.
"""
