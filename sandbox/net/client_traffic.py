#!/usr/bin/env python3
"""client_traffic.py — Simulates realistic home network traffic.

Behavior depends on CLIENT_ROLE env var:
  - laptop:   Web browsing (HTTP/HTTPS), DNS queries, SSH, occasional large downloads
  - phone:    DNS queries, HTTPS, mDNS, short-lived connections
  - smart-tv: DNS queries, high-bandwidth UDP streams (simulates video), NTP

All traffic is real TCP/UDP/ICMP flowing through the Docker network,
captured by the CNDS detector via scapy.
"""

import asyncio
import logging
import os
import random
import socket
import struct
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("client")

ROLE = os.getenv("CLIENT_ROLE", "laptop")
DNS_SERVER = os.getenv("DNS_SERVER", "172.20.0.2")
TARGETS = os.getenv("TARGETS", "172.20.0.2").split(",")

# Domains to query — mix of common sites
DOMAINS = [
    "google.com", "youtube.com", "github.com", "stackoverflow.com",
    "reddit.com", "amazon.com", "netflix.com", "spotify.com",
    "wikipedia.org", "cloudflare.com", "microsoft.com", "apple.com",
    "twitter.com", "facebook.com", "linkedin.com", "docker.com",
    "python.org", "mozilla.org", "ubuntu.com", "archlinux.org",
]

# ─── DNS query helper ──────────────────────────────────────────────────────────

def dns_query(domain: str, server: str = DNS_SERVER, port: int = 53) -> None:
    """Send a real DNS A query via UDP."""
    # Build a minimal DNS query packet
    tx_id = random.randint(0, 65535)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack(">HHHHHH", tx_id, flags, 1, 0, 0, 0)

    # Encode domain name
    question = b""
    for label in domain.split("."):
        question += struct.pack("B", len(label)) + label.encode()
    question += b"\x00"  # null terminator
    question += struct.pack(">HH", 1, 1)  # Type A, Class IN

    packet = header + question

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(packet, (server, port))
        sock.recv(512)
        sock.close()
    except (socket.timeout, OSError):
        pass  # DNS timeout is fine — we just need the traffic on the wire


# ─── TCP connection helper ─────────────────────────────────────────────────────

def tcp_connect(host: str, port: int, data: bytes = b"", timeout: float = 2.0) -> bool:
    """Establish a TCP connection, optionally send data, then close."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if data:
            sock.sendall(data)
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
        sock.close()
        return True
    except (OSError, ConnectionRefusedError):
        return False


# ─── UDP stream helper ─────────────────────────────────────────────────────────

def udp_stream(host: str, port: int, packets: int = 50, size: int = 1200) -> None:
    """Send a burst of UDP packets (simulates video/audio streaming)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(packets):
            sock.sendto(os.urandom(size), (host, port))
            time.sleep(0.02)  # ~50 pps
        sock.close()
    except OSError:
        pass


# ─── ICMP ping helper ──────────────────────────────────────────────────────────

def ping(host: str) -> None:
    """Send ICMP echo via system ping (1 packet)."""
    os.system(f"ping -c 1 -W 1 {host} > /dev/null 2>&1")


# ─── Role-specific traffic profiles ───────────────────────────────────────────

async def laptop_loop():
    """Simulate a laptop: browsing, DNS, SSH, occasional downloads."""
    log.info("Starting laptop traffic profile")
    while True:
        action = random.choices(
            ["dns", "http", "https", "ssh", "ping", "download"],
            weights=[30, 20, 25, 5, 10, 10],
        )[0]

        if action == "dns":
            domain = random.choice(DOMAINS)
            dns_query(domain)
            log.debug("DNS query: %s", domain)

        elif action == "http":
            target = random.choice(TARGETS)
            http_req = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            tcp_connect(target, 80, http_req.encode())

        elif action == "https":
            target = random.choice(TARGETS)
            # TLS ClientHello-like bytes (won't complete handshake, but creates TCP flow)
            tcp_connect(target, 443, b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00")

        elif action == "ssh":
            target = random.choice(TARGETS)
            tcp_connect(target, 22, b"SSH-2.0-OpenSSH_8.9\r\n")

        elif action == "ping":
            target = random.choice(TARGETS)
            ping(target)

        elif action == "download":
            # Simulate large download — many TCP segments
            target = random.choice(TARGETS)
            req = f"GET /large-file HTTP/1.1\r\nHost: {target}\r\n\r\n"
            tcp_connect(target, 80, req.encode())

        # Random delay: 0.5s to 5s (bursty human behavior)
        await asyncio.sleep(random.uniform(0.5, 5.0))


async def phone_loop():
    """Simulate a phone: mostly DNS + HTTPS, short sessions."""
    log.info("Starting phone traffic profile")
    while True:
        action = random.choices(
            ["dns", "https", "ping", "idle"],
            weights=[35, 40, 5, 20],
        )[0]

        if action == "dns":
            domain = random.choice(DOMAINS)
            dns_query(domain)

        elif action == "https":
            target = random.choice(TARGETS)
            tcp_connect(target, 443, b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00")

        elif action == "ping":
            ping(random.choice(TARGETS))

        # Phones: frequent short bursts then idle
        await asyncio.sleep(random.uniform(1.0, 8.0))


async def smart_tv_loop():
    """Simulate a smart TV: DNS, video streaming (UDP), NTP."""
    log.info("Starting smart-tv traffic profile")
    while True:
        action = random.choices(
            ["dns", "stream", "ntp", "https", "idle"],
            weights=[15, 40, 10, 15, 20],
        )[0]

        if action == "dns":
            # TVs query streaming service domains
            tv_domains = ["netflix.com", "youtube.com", "hbomax.com", "disney.com",
                          "hulu.com", "ntp.ubuntu.com", "time.google.com"]
            dns_query(random.choice(tv_domains))

        elif action == "stream":
            # High-bandwidth UDP burst (simulates video chunks)
            target = random.choice(TARGETS)
            udp_stream(target, port=random.choice([1935, 5004, 8554, 9000]),
                       packets=random.randint(30, 100),
                       size=random.randint(800, 1400))

        elif action == "ntp":
            # NTP query (UDP 123)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.0)
                # Minimal NTP request
                ntp_data = b"\x1b" + 47 * b"\x00"
                sock.sendto(ntp_data, (DNS_SERVER, 123))
                sock.close()
            except OSError:
                pass

        elif action == "https":
            target = random.choice(TARGETS)
            tcp_connect(target, 443, b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00")

        # TV: longer intervals between actions, but streams are bursty
        await asyncio.sleep(random.uniform(2.0, 10.0))


# ─── Main ──────────────────────────────────────────────────────────────────────

async def main():
    log.info("Client starting: role=%s, dns=%s, targets=%s", ROLE, DNS_SERVER, TARGETS)

    # Initial delay to let the network stabilize
    await asyncio.sleep(random.uniform(3.0, 8.0))

    if ROLE == "laptop":
        await laptop_loop()
    elif ROLE == "phone":
        await phone_loop()
    elif ROLE == "smart-tv":
        await smart_tv_loop()
    else:
        log.warning("Unknown role %s, defaulting to laptop", ROLE)
        await laptop_loop()


if __name__ == "__main__":
    asyncio.run(main())
