"""Attack scenario traffic for the CNDS sandbox.

Extends demo/generate_traffic.py scenarios by sending attack vectors
directly to the /api/predict endpoint with features that trigger
detection engines and rules.
"""

import asyncio
import logging
import random
from dataclasses import dataclass, field
from typing import List, Dict

import httpx

logger = logging.getLogger(__name__)

ATTACKER_IPS = [f"10.0.0.{i}" for i in range(1, 11)]
TARGET_IPS = ["192.168.1.1", "192.168.1.60", "192.168.1.62", "192.168.1.100"]


@dataclass
class ScenarioResult:
    name: str
    vectors_sent: int = 0
    alerts_triggered: int = 0
    attack_types_seen: List[str] = field(default_factory=list)
    errors: int = 0


def _aggressive_host_features() -> List[float]:
    """Host features typical of scanning/flooding."""
    return [
        random.uniform(200, 1000),   # pkt_rate (high)
        random.uniform(50000, 200000), # byte_rate (high)
        random.uniform(40, 60),      # avg_pkt_size (small - scan)
        random.uniform(60, 100),     # max_pkt_size
        random.randint(500, 2000),   # fwd_pkts (high)
        random.randint(20000, 100000), # fwd_bytes
        random.uniform(0.0001, 0.001), # fwd_iat_mean (fast)
        random.uniform(0.00001, 0.0005), # fwd_iat_std
        random.uniform(0, 2),        # bwd_pkts (low - asymmetric)
        random.uniform(0.01, 0.05),  # bwd_bytes_ratio (low)
        random.uniform(0.9, 1.0),    # tcp_ratio
        random.uniform(0.0, 0.05),   # udp_ratio
        random.uniform(0.0, 0.05),   # icmp_ratio
        random.uniform(20, 100),     # unique_dst_ports (high)
        random.uniform(0.8, 1.0),    # syn_ratio (high - scan)
        random.uniform(5, 7),        # port_entropy (high)
        random.uniform(0, 1024),     # most_common_port
        random.uniform(0.1, 2),      # flow_duration_avg (short)
    ]


def _exfil_host_features() -> List[float]:
    """Host features typical of data exfiltration."""
    return [
        random.uniform(50, 150),     # pkt_rate
        random.uniform(100000, 500000), # byte_rate (very high)
        random.uniform(1000, 1500),  # avg_pkt_size (large)
        random.uniform(1400, 1500),  # max_pkt_size (MTU)
        random.randint(100, 500),    # fwd_pkts
        random.randint(100000, 500000), # fwd_bytes (high)
        random.uniform(0.005, 0.02), # fwd_iat_mean
        random.uniform(0.001, 0.005), # fwd_iat_std
        random.uniform(1, 5),        # bwd_pkts (very low)
        random.uniform(0.001, 0.01), # bwd_bytes_ratio (asymmetric)
        random.uniform(0.9, 1.0),    # tcp_ratio
        0.0, 0.0,                    # udp/icmp
        random.uniform(1, 3),        # unique_dst_ports (low)
        random.uniform(0.1, 0.3),    # syn_ratio
        random.uniform(0.5, 1.5),    # port_entropy (low)
        443.0,                       # most_common_port
        random.uniform(30, 300),     # flow_duration_avg
    ]


async def _run_scenario(
    client: httpx.AsyncClient,
    name: str,
    vectors: List[dict],
    delay: float = 0.1,
) -> ScenarioResult:
    """Send a batch of attack vectors and collect results."""
    result = ScenarioResult(name=name)
    for vec in vectors:
        try:
            resp = await client.post("/api/predict", json=vec)
            result.vectors_sent += 1
            if resp.status_code == 200:
                data = resp.json()
                if data.get("is_anomaly"):
                    result.alerts_triggered += 1
                    if data.get("attack_type"):
                        result.attack_types_seen.append(data["attack_type"])
            else:
                result.errors += 1
        except Exception:
            result.errors += 1
        await asyncio.sleep(delay)
    return result


async def scenario_icmp_flood(client: httpx.AsyncClient) -> ScenarioResult:
    """ICMP flood from single attacker — triggers icmp_flood rule."""
    attacker = random.choice(ATTACKER_IPS)
    vectors = []
    for _ in range(60):
        vectors.append({
            "src_ip": attacker,
            "dst_ip": "192.168.1.1",
            "dst_port": 0,
            "protocol": 1,  # ICMP
            "host_features": _aggressive_host_features(),
            "payload_matches": ["icmp_flood"],
        })
    return await _run_scenario(client, "icmp_flood", vectors, delay=0.02)


async def scenario_syn_scan(client: httpx.AsyncClient) -> ScenarioResult:
    """SYN scan across many ports — triggers port_scan rule."""
    attacker = random.choice(ATTACKER_IPS)
    vectors = []
    for port in random.sample(range(1, 65535), 30):
        vectors.append({
            "src_ip": attacker,
            "dst_ip": random.choice(TARGET_IPS),
            "dst_port": port,
            "protocol": 6,
            "host_features": _aggressive_host_features(),
            "payload_matches": ["port_scan"],
        })
    return await _run_scenario(client, "syn_scan", vectors, delay=0.02)


async def scenario_sql_injection(client: httpx.AsyncClient) -> ScenarioResult:
    """SQL injection attempts — triggers sql_injection rule."""
    attacker = random.choice(ATTACKER_IPS)
    vectors = []
    for _ in range(10):
        vectors.append({
            "src_ip": attacker,
            "dst_ip": "192.168.1.60",
            "dst_port": 5000,
            "protocol": 6,
            "host_features": _aggressive_host_features(),
            "payload_matches": ["sql_injection"],
        })
    return await _run_scenario(client, "sql_injection", vectors)


async def scenario_xss(client: httpx.AsyncClient) -> ScenarioResult:
    """XSS attacks — triggers xss rule."""
    attacker = random.choice(ATTACKER_IPS)
    vectors = []
    for _ in range(8):
        vectors.append({
            "src_ip": attacker,
            "dst_ip": "192.168.1.62",
            "dst_port": 80,
            "protocol": 6,
            "host_features": _aggressive_host_features(),
            "payload_matches": ["xss"],
        })
    return await _run_scenario(client, "xss", vectors)


async def scenario_exfiltration(client: httpx.AsyncClient) -> ScenarioResult:
    """Data exfiltration — triggers large_payload + asymmetric_upload."""
    src = "192.168.1.60"  # NAS exfiltrating
    vectors = []
    for _ in range(15):
        vectors.append({
            "src_ip": src,
            "dst_ip": random.choice(ATTACKER_IPS),
            "dst_port": 443,
            "protocol": 6,
            "host_features": _exfil_host_features(),
            "payload_matches": ["large_payload", "asymmetric_upload"],
        })
    return await _run_scenario(client, "exfiltration", vectors)


async def scenario_command_injection(client: httpx.AsyncClient) -> ScenarioResult:
    """Command injection — triggers command_injection rule."""
    attacker = random.choice(ATTACKER_IPS)
    vectors = []
    for _ in range(5):
        vectors.append({
            "src_ip": attacker,
            "dst_ip": "192.168.1.62",
            "dst_port": 80,
            "protocol": 6,
            "host_features": _aggressive_host_features(),
            "payload_matches": ["command_injection"],
        })
    return await _run_scenario(client, "command_injection", vectors)


async def scenario_log4shell(client: httpx.AsyncClient) -> ScenarioResult:
    """Log4Shell probe — triggers log4j rule."""
    attacker = random.choice(ATTACKER_IPS)
    vectors = []
    for _ in range(5):
        vectors.append({
            "src_ip": attacker,
            "dst_ip": "192.168.1.62",
            "dst_port": 8080,
            "protocol": 6,
            "host_features": _aggressive_host_features(),
            "payload_matches": ["log4j"],
        })
    return await _run_scenario(client, "log4shell", vectors)


# Registry of all attack scenarios
SCENARIOS = [
    ("icmp_flood", scenario_icmp_flood),
    ("syn_scan", scenario_syn_scan),
    ("sql_injection", scenario_sql_injection),
    ("xss", scenario_xss),
    ("exfiltration", scenario_exfiltration),
    ("command_injection", scenario_command_injection),
    ("log4shell", scenario_log4shell),
]


async def run_all_scenarios(
    base_url: str = "http://localhost:8000",
    ci_mode: bool = False,
) -> Dict[str, ScenarioResult]:
    """Execute all attack scenarios against the CNDS API."""
    scenarios = SCENARIOS[:4] if ci_mode else SCENARIOS
    results = {}

    async with httpx.AsyncClient(base_url=base_url, timeout=10) as client:
        for name, fn in scenarios:
            logger.info("Running scenario: %s", name)
            result = await fn(client)
            results[name] = result
            logger.info(
                "  %s: %d sent, %d alerts, %d errors",
                name, result.vectors_sent, result.alerts_triggered, result.errors,
            )

    return results
