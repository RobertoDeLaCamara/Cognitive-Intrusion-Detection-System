"""Benign background traffic generator for the CNDS sandbox.

Generates feature vectors from 20+ distinct IPs with high destination-port
entropy, designed to satisfy the unsupervised baseline training trigger
conditions (50k vectors, 20 IPs, port entropy > 2.5 bits).
"""

import asyncio
import logging
import math
import random
import time
from dataclasses import dataclass, field
from typing import List

import httpx

logger = logging.getLogger(__name__)

# 25 distinct source IPs
SRC_IPS = [f"192.168.1.{i}" for i in range(10, 35)]

# High-entropy destination ports (common + ephemeral)
DST_PORTS = [
    22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    3000, 3306, 5000, 5432, 5900, 6379, 8000, 8080, 8443, 9200,
    *range(10000, 10050), *range(49152, 49200),
]

DST_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "172.16.0.1", "172.16.0.2"]
PROTOCOLS = [6, 6, 6, 6, 17, 1]  # Weighted toward TCP


@dataclass
class BackgroundStats:
    vectors_sent: int = 0
    errors: int = 0
    unique_ips: set = field(default_factory=set)
    port_counts: dict = field(default_factory=dict)

    @property
    def port_entropy(self) -> float:
        total = sum(self.port_counts.values())
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in self.port_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


def _random_host_features() -> List[float]:
    """Generate 18 realistic benign host features."""
    return [
        random.uniform(1, 50),       # pkt_rate
        random.uniform(100, 5000),   # byte_rate
        random.uniform(50, 200),     # avg_pkt_size
        random.uniform(100, 1500),   # max_pkt_size
        random.randint(1, 100),      # fwd_pkts
        random.randint(100, 10000),  # fwd_bytes
        random.uniform(0.001, 0.05), # fwd_iat_mean
        random.uniform(0.0001, 0.01),# fwd_iat_std
        random.uniform(1, 20),       # bwd_pkts
        random.uniform(1, 15),       # bwd_bytes_ratio
        random.uniform(0.5, 1.0),    # tcp_ratio
        random.uniform(0.0, 0.3),    # udp_ratio
        random.uniform(0.0, 0.05),   # icmp_ratio
        random.uniform(1, 5),        # unique_dst_ports
        random.uniform(0.01, 0.2),   # syn_ratio
        random.uniform(1, 4),        # port_entropy
        random.uniform(80, 443),     # most_common_port
        random.uniform(50, 500),     # flow_duration_avg
    ]


async def generate_background(
    base_url: str = "http://localhost:8000",
    total_vectors: int = 50000,
    batch_size: int = 50,
    delay: float = 0.05,
    ci_mode: bool = False,
) -> BackgroundStats:
    """Send benign traffic vectors to the CNDS /api/predict endpoint.

    Args:
        base_url: CNDS API URL.
        total_vectors: Total vectors to send.
        batch_size: Concurrent requests per batch.
        delay: Seconds between batches.
        ci_mode: If True, use reduced volume (5k vectors, 10 IPs).
    """
    if ci_mode:
        total_vectors = min(total_vectors, 200)
        ips = SRC_IPS[:10]
        delay = max(delay, 0.01)
    else:
        ips = SRC_IPS

    stats = BackgroundStats()
    logger.info("Background traffic: sending %d vectors from %d IPs", total_vectors, len(ips))

    async with httpx.AsyncClient(base_url=base_url, timeout=10) as client:
        while stats.vectors_sent < total_vectors:
            src_ip = random.choice(ips)
            dst_port = random.choice(DST_PORTS)
            payload = {
                "src_ip": src_ip,
                "dst_ip": random.choice(DST_IPS),
                "dst_port": dst_port,
                "protocol": random.choice(PROTOCOLS),
                "host_features": _random_host_features(),
            }
            stats.unique_ips.add(src_ip)
            stats.port_counts[dst_port] = stats.port_counts.get(dst_port, 0) + 1

            try:
                resp = await client.post("/api/predict", json=payload)
                if resp.status_code == 429:
                    await asyncio.sleep(1.0)
                    continue
                stats.vectors_sent += 1
            except Exception:
                stats.errors += 1

            if stats.vectors_sent % 500 == 0 and stats.vectors_sent > 0:
                logger.info(
                    "Background: %d/%d sent (entropy=%.2f, IPs=%d)",
                    stats.vectors_sent, total_vectors,
                    stats.port_entropy, len(stats.unique_ips),
                )
            await asyncio.sleep(delay)

    logger.info(
        "Background traffic complete: %d vectors, %d IPs, entropy=%.2f, errors=%d",
        stats.vectors_sent, len(stats.unique_ips), stats.port_entropy, stats.errors,
    )
    return stats
