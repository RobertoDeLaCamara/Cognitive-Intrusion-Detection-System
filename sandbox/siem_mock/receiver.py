"""Mock SIEM syslog receiver for the CNDS sandbox.

Listens on UDP for CEF-formatted syslog messages from the CNDS forwarder
and validates their structure.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# CEF format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
_CEF_PATTERN = re.compile(
    r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)"
)

_REQUIRED_EXTENSIONS = ["src=", "dst=", "cn1=", "externalId="]


@dataclass
class CEFMessage:
    raw: str
    version: int = 0
    vendor: str = ""
    product: str = ""
    device_version: str = ""
    signature_id: str = ""
    name: str = ""
    severity: int = 0
    extensions: str = ""
    valid: bool = False
    validation_errors: List[str] = field(default_factory=list)


@dataclass
class ReceiverStats:
    messages_received: int = 0
    valid_cef: int = 0
    invalid_cef: int = 0
    messages: List[CEFMessage] = field(default_factory=list)


def validate_cef(raw: str) -> CEFMessage:
    """Parse and validate a CEF syslog message."""
    msg = CEFMessage(raw=raw)

    # Strip syslog header (everything before "CEF:")
    cef_start = raw.find("CEF:")
    if cef_start == -1:
        msg.validation_errors.append("No CEF: prefix found")
        return msg

    cef_part = raw[cef_start:]
    match = _CEF_PATTERN.match(cef_part)
    if not match:
        msg.validation_errors.append("CEF format does not match expected pattern")
        return msg

    msg.version = int(match.group(1))
    msg.vendor = match.group(2)
    msg.product = match.group(3)
    msg.device_version = match.group(4)
    msg.signature_id = match.group(5)
    msg.name = match.group(6)
    msg.severity = int(match.group(7))
    msg.extensions = match.group(8)

    # Validate required fields
    if not msg.vendor:
        msg.validation_errors.append("Empty vendor field")
    if not msg.product:
        msg.validation_errors.append("Empty product field")
    if msg.severity < 0 or msg.severity > 10:
        msg.validation_errors.append(f"Severity {msg.severity} out of range 0-10")

    # Check required extensions
    for ext in _REQUIRED_EXTENSIONS:
        if ext not in msg.extensions:
            msg.validation_errors.append(f"Missing extension: {ext}")

    msg.valid = len(msg.validation_errors) == 0
    return msg


class SyslogReceiver:
    """Async UDP syslog receiver that validates CEF messages."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5514):
        self.host = host
        self.port = port
        self.stats = ReceiverStats()
        self._transport: Optional[asyncio.DatagramTransport] = None

    async def start(self) -> int:
        """Start listening. Returns the actual bound port."""
        loop = asyncio.get_event_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(self),
            local_addr=(self.host, self.port),
        )
        actual_port = self._transport.get_extra_info("sockname")[1]
        self.port = actual_port
        logger.info("SIEM mock receiver listening on %s:%d", self.host, self.port)
        return actual_port

    async def stop(self) -> ReceiverStats:
        """Stop the receiver and return stats."""
        if self._transport:
            self._transport.close()
        logger.info(
            "SIEM mock: %d received, %d valid, %d invalid",
            self.stats.messages_received, self.stats.valid_cef, self.stats.invalid_cef,
        )
        return self.stats

    def _handle_message(self, data: bytes) -> None:
        raw = data.decode("utf-8", errors="replace")
        self.stats.messages_received += 1
        msg = validate_cef(raw)
        self.stats.messages.append(msg)
        if msg.valid:
            self.stats.valid_cef += 1
        else:
            self.stats.invalid_cef += 1
            logger.debug("Invalid CEF: %s", msg.validation_errors)


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: SyslogReceiver):
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._receiver._handle_message(data)
