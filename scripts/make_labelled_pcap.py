#!/usr/bin/env python3
"""Generate a small labelled PCAP (benign background + scripted attacks) for pcap_replay.py.

IMPORTANT: this traffic is synthetic and written by the same people who wrote the rules.
It answers "does CNDS recognise its textbook signatures end to end?" (a coverage
smoke test that found real rule bugs), NOT "what is the recall on real attacks?".
For that, replay a labelled capture you did not write (see doc/evaluation.md).

Usage:
    python scripts/make_labelled_pcap.py --out /tmp/synth.pcap --attacks /tmp/synth_attacks.csv
    python scripts/pcap_replay.py /tmp/synth.pcap --attacks /tmp/synth_attacks.csv --report /tmp/report.md
"""

import argparse
import csv
import random
from typing import List, Tuple

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, wrpcap

ATTACKER = "192.168.1.66"
TARGET = "192.168.1.189"
DNS_SERVER = "192.168.1.1"
T0 = 1_700_000_000.0  # arbitrary fixed epoch so the output is reproducible

SQLI = b"GET /index.php?id=1' UNION SELECT username,password FROM users-- HTTP/1.1\r\nHost: t\r\n\r\n"
XSS = b"GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: t\r\n\r\n"
BENIGN_HTTP = b"GET /index.html HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Mozilla/5.0\r\n\r\n"


def _stamp(pkts: List, start: float, gaps) -> List:
    """Assign increasing capture times to *pkts*."""
    t = start
    for p, g in zip(pkts, gaps):
        t += g
        p.time = t
    return pkts


def tcp_session(src, dst, sport, dport, start, payload=b"", rtt=0.02, replies=2, rng=None):
    """Handshake, optional request payload, a few reply packets, FIN."""
    rng = rng or random
    c = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=100)
    s = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=500, ack=101)
    a = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=501)
    pk = [c, s, a]
    seq = 101
    if payload:
        pk.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=501) / Raw(payload))
        seq += len(payload)
    for i in range(replies):
        size = rng.randint(200, 1200)
        pk.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=501 + i * size, ack=seq) / Raw(b"x" * size))
    pk.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=seq, ack=501))
    return _stamp(pk, start, [rtt * (1 + rng.random()) for _ in pk])


def benign(rng, duration: float) -> List:
    pkts: List = []
    clients = [f"192.168.1.{n}" for n in range(50, 56)]
    servers = ["93.184.216.34", "151.101.1.69", "142.250.185.14"]
    t = 0.0
    while t < duration:
        t += rng.expovariate(1 / 1.5)
        c = rng.choice(clients)
        if rng.random() < 0.7:
            pkts += tcp_session(c, rng.choice(servers), rng.randint(32768, 60999),
                                rng.choice([80, 443, 443]), T0 + t, BENIGN_HTTP,
                                replies=rng.randint(2, 6), rng=rng)
        else:
            q = IP(src=c, dst=DNS_SERVER) / UDP(sport=rng.randint(32768, 60999), dport=53) / DNS(rd=1, qd=DNSQR(qname="example.org"))
            r = IP(src=DNS_SERVER, dst=c) / UDP(sport=53, dport=q[UDP].sport) / DNS(qr=1, qd=DNSQR(qname="example.org"))
            pkts += _stamp([q, r], T0 + t, [0.01, 0.02])
    return pkts


def generate(seed: int = 7, duration: float = 600.0) -> Tuple[List, List[dict]]:
    rng = random.Random(seed)
    pkts = benign(rng, duration)
    attacks: List[dict] = []

    def add(label, start, end, dst_port: object = ""):
        attacks.append({"label": label, "src_ip": ATTACKER, "dst_ip": TARGET,
                        "dst_port": dst_port, "start": f"+{start}", "end": f"+{end}"})

    # port scan: one SYN (+ RST) per port, each its own flow
    t = 60.0
    for port in range(1, 201):
        syn = IP(src=ATTACKER, dst=TARGET) / TCP(sport=rng.randint(32768, 60999), dport=port, flags="S")
        rst = IP(src=TARGET, dst=ATTACKER) / TCP(sport=port, dport=syn[TCP].sport, flags="RA")
        pkts += _stamp([syn, rst], T0 + t, [0.0, 0.002])
        t += 0.01
    add("port_scan", 59, 63)

    # SYN flood: one 5-tuple, many SYNs (what the syn_scan rule is meant to catch)
    flood = [IP(src=ATTACKER, dst=TARGET) / TCP(sport=44444, dport=80, flags="S", seq=i) for i in range(60)]
    pkts += _stamp(flood, T0 + 120.0, [0.05] * len(flood))
    add("syn_flood", 119, 125, 80)

    # web attacks with a normal handshake
    pkts += tcp_session(ATTACKER, TARGET, 50001, 80, T0 + 180.0, SQLI, rng=rng)
    add("sql_injection", 179, 182, 80)
    pkts += tcp_session(ATTACKER, TARGET, 50002, 80, T0 + 240.0, XSS, rng=rng)
    add("xss", 239, 242, 80)

    # SSH brute force: many short connections to port 22
    t = 300.0
    for i in range(40):
        pkts += tcp_session(ATTACKER, TARGET, 51000 + i, 22, T0 + t, b"SSH-2.0-libssh\r\n", replies=1, rng=rng)
        t += 0.5
    add("ssh_bruteforce", 299, 325, 22)

    # DNS query burst against the resolver
    t = 400.0
    for i in range(300):
        q = IP(src=ATTACKER, dst=DNS_SERVER) / UDP(sport=52000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=f"r{i}.example.org"))
        r = IP(src=DNS_SERVER, dst=ATTACKER) / UDP(sport=53, dport=52000 + i) / DNS(qr=1, qd=DNSQR(qname=f"r{i}.example.org"))
        pkts += _stamp([q, r], T0 + t, [0.0, 0.005])
        t += 0.02
    attacks.append({"label": "dns_burst", "src_ip": ATTACKER, "dst_ip": DNS_SERVER,
                    "dst_port": "53", "start": "+399", "end": "+407"})

    pkts.sort(key=lambda p: p.time)
    return pkts, attacks


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="PCAP to write")
    ap.add_argument("--attacks", required=True, help="attack-window CSV to write")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--duration", type=float, default=600.0, help="seconds of benign background")
    args = ap.parse_args()
    pkts, attacks = generate(args.seed, args.duration)
    wrpcap(args.out, pkts)
    with open(args.attacks, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["label", "src_ip", "dst_ip", "dst_port", "start", "end"])
        w.writeheader()
        w.writerows(attacks)
    print(f"{len(pkts)} packets -> {args.out}; {len(attacks)} attack windows -> {args.attacks}")


if __name__ == "__main__":
    main()
