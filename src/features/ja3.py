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


def _parse_client_hello(data: bytes) -> Optional[Dict]:
    """Parse a TLS ClientHello and return JA3 components, or None."""
    if len(data) < 5:
        return None
    content_type = data[0]
    if content_type != _TLS_HANDSHAKE:
        return None

    tls_version = struct.unpack("!H", data[1:3])[0]
    record_len = struct.unpack("!H", data[3:5])[0]
    payload = data[5:5 + record_len]

    if len(payload) < 4:
        return None
    hs_type = payload[0]
    if hs_type != _CLIENT_HELLO:
        return None

    hs_len = struct.unpack("!I", b'\x00' + payload[1:4])[0]
    hs = payload[4:4 + hs_len]
    if len(hs) < 38:
        return None

    ch_version = struct.unpack("!H", hs[0:2])[0]
    # Skip random (32 bytes)
    pos = 34

    # Session ID
    if pos >= len(hs):
        return None
    sid_len = hs[pos]
    pos += 1 + sid_len

    # Cipher suites
    if pos + 2 > len(hs):
        return None
    cs_len = struct.unpack("!H", hs[pos:pos + 2])[0]
    pos += 2
    ciphers = []
    for i in range(0, cs_len, 2):
        if pos + i + 2 > len(hs):
            break
        c = struct.unpack("!H", hs[pos + i:pos + i + 2])[0]
        if c not in _GREASE:
            ciphers.append(c)
    pos += cs_len

    # Compression methods
    if pos >= len(hs):
        return None
    comp_len = hs[pos]
    pos += 1 + comp_len

    # Extensions
    extensions = []
    elliptic_curves = []
    ec_point_formats = []

    if pos + 2 <= len(hs):
        ext_total = struct.unpack("!H", hs[pos:pos + 2])[0]
        pos += 2
        ext_end = pos + ext_total

        while pos + 4 <= ext_end and pos + 4 <= len(hs):
            ext_type = struct.unpack("!H", hs[pos:pos + 2])[0]
            ext_len = struct.unpack("!H", hs[pos + 2:pos + 4])[0]
            pos += 4

            if ext_type not in _GREASE:
                extensions.append(ext_type)

            ext_data = hs[pos:pos + ext_len]

            # Supported groups (0x000A)
            if ext_type == 0x000A and len(ext_data) >= 2:
                gl = struct.unpack("!H", ext_data[0:2])[0]
                for i in range(2, min(2 + gl, len(ext_data)), 2):
                    if i + 2 <= len(ext_data):
                        g = struct.unpack("!H", ext_data[i:i + 2])[0]
                        if g not in _GREASE:
                            elliptic_curves.append(g)

            # EC point formats (0x000B)
            if ext_type == 0x000B and len(ext_data) >= 1:
                fl = ext_data[0]
                for i in range(1, min(1 + fl, len(ext_data))):
                    ec_point_formats.append(ext_data[i])

            pos += ext_len

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
