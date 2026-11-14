"""JA3 TLS fingerprint extraction from Scapy packets.

Computes the JA3 hash from TLS ClientHello messages. The hash is an MD5
of: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

Known-malicious JA3 hashes can be loaded from a file or set via config.
"""

import hashlib
import struct
import logging
from typing import Dict, List, Optional, Tuple

from scapy.all import TCP, Raw

logger = logging.getLogger(__name__)

# TLS record type 22 = Handshake, handshake type 1 = ClientHello
_TLS_HANDSHAKE = 22
_CLIENT_HELLO = 1
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_EC_POINT_FORMATS = 0x000B

# GREASE values to filter out (RFC 8701)
_GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# Known-malicious JA3 hashes (extend via MALICIOUS_JA3_FILE config)
_MALICIOUS_JA3: set = set()


def load_malicious_ja3(path: str) -> None:
    """Load known-bad JA3 hashes from a file (one hash per line)."""
    try:
        with open(path) as f:
            for line in f:
                h = line.strip()
                if h and not h.startswith("#"):
                    _MALICIOUS_JA3.add(h)
        logger.info("Loaded %d malicious JA3 hashes from %s", len(_MALICIOUS_JA3), path)
    except FileNotFoundError:
        logger.debug("JA3 malicious hash file not found: %s", path)


def _client_hello_body(data: bytes) -> Optional[bytes]:
    """Body of the ClientHello inside a TLS handshake record, or None if `data` is not one."""
    if len(data) < 5 or data[0] != _TLS_HANDSHAKE:
        return None
    record_len = struct.unpack("!H", data[3:5])[0]
    payload = data[5:5 + record_len]

    if len(payload) < 4 or payload[0] != _CLIENT_HELLO:
        return None
    hs_len = struct.unpack("!I", b'\x00' + payload[1:4])[0]
    hs = payload[4:4 + hs_len]
    # version (2) + random (32) + session id length (1) + cipher suites length (2) + one byte more
    return hs if len(hs) >= 38 else None


def _u16_values(buf: bytes, start: int, length: int) -> List[int]:
    """Big-endian 16-bit values in buf[start:start + length], truncated at the end of buf, without GREASE."""
    values = []
    for i in range(start, start + length, 2):
        if i + 2 > len(buf):
            break
        value = struct.unpack("!H", buf[i:i + 2])[0]
        if value not in _GREASE:
            values.append(value)
    return values


def _parse_extensions(hs: bytes, pos: int) -> Tuple[List[int], List[int], List[int]]:
    """(extension types, supported groups, EC point formats) from the extensions block at `pos`."""
    extensions: List[int] = []
    elliptic_curves: List[int] = []
    ec_point_formats: List[int] = []
    if pos + 2 > len(hs):
        return extensions, elliptic_curves, ec_point_formats

    ext_end = pos + 2 + struct.unpack("!H", hs[pos:pos + 2])[0]
    pos += 2
    while pos + 4 <= ext_end and pos + 4 <= len(hs):
        ext_type, ext_len = struct.unpack("!HH", hs[pos:pos + 4])
        pos += 4
        if ext_type not in _GREASE:
            extensions.append(ext_type)
        ext_data = hs[pos:pos + ext_len]

        if ext_type == _EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
            groups_len = struct.unpack("!H", ext_data[0:2])[0]
            elliptic_curves.extend(_u16_values(ext_data, 2, groups_len))
        elif ext_type == _EXT_EC_POINT_FORMATS and len(ext_data) >= 1:
            ec_point_formats.extend(ext_data[1:1 + ext_data[0]])

        pos += ext_len
    return extensions, elliptic_curves, ec_point_formats


def _parse_client_hello(data: bytes) -> Optional[Dict]:
    """Parse a TLS ClientHello and return JA3 components, or None."""
    hs = _client_hello_body(data)
    if hs is None:
        return None

    ch_version = struct.unpack("!H", hs[0:2])[0]
    # Skip random (32 bytes), then the session ID
    pos = 34
    pos += 1 + hs[pos]

    # Cipher suites
    if pos + 2 > len(hs):
        return None
    cs_len = struct.unpack("!H", hs[pos:pos + 2])[0]
    pos += 2
    ciphers = _u16_values(hs, pos, cs_len)
    pos += cs_len

    # Compression methods
    if pos >= len(hs):
        return None
    pos += 1 + hs[pos]

    extensions, elliptic_curves, ec_point_formats = _parse_extensions(hs, pos)
    return {
        "version": ch_version,
        "ciphers": ciphers,
        "extensions": extensions,
        "elliptic_curves": elliptic_curves,
        "ec_point_formats": ec_point_formats,
    }


def extract_ja3(packet) -> Optional[Tuple[str, str]]:
    """Extract JA3 hash and raw string from a packet.

    Returns (ja3_hash, ja3_string) or None if not a ClientHello.
    """
    if TCP not in packet or Raw not in packet:
        return None

    data = bytes(packet[Raw].load)
    parsed = _parse_client_hello(data)
    if parsed is None:
        return None

    ja3_str = ",".join([
        str(parsed["version"]),
        "-".join(str(c) for c in parsed["ciphers"]),
        "-".join(str(e) for e in parsed["extensions"]),
        "-".join(str(g) for g in parsed["elliptic_curves"]),
        "-".join(str(f) for f in parsed["ec_point_formats"]),
    ])

    ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
    return ja3_hash, ja3_str


def is_malicious_ja3(ja3_hash: str) -> bool:
    """Check if a JA3 hash is in the known-malicious set."""
    return ja3_hash in _MALICIOUS_JA3
