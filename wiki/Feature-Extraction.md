# Feature Extraction

CNDS extracts four categories of features from captured traffic. The dispatcher feeds every packet to the extractors and, when a flow expires, hands the finished flow, host and payload features to the pipeline callback.

## Flow Features (76 features)

**File:** `src/features/flow_extractor.py`

CICFlowMeter-compatible bidirectional flow features, computed when a flow expires after `FLOW_TIMEOUT` seconds of inactivity. These include:

- Duration, total packets/bytes (forward + backward)
- Packet length statistics (min, max, mean, std) per direction
- Inter-arrival time statistics per direction
- Flag counts (SYN, FIN, RST, PSH, ACK, URG, CWE, ECE)
- Flow bytes/s, flow packets/s
- Bulk transfer features (consecutive-packet segments)
- Subflow counts and averages
- Active/idle time statistics
- Window size, segment size, header length

Flow expiry uses a min-heap for O(k) performance (k = expired flows) instead of scanning all active flows.

## Host Features (18 features)

**File:** `src/features/host_extractor.py`

Per-IP behavioural features computed over a sliding window of `HOST_WINDOW_SIZE` packets (default 100):

The 18 features, in order: `packets_per_sec`, `bytes_per_sec`, `avg_packet_size`, `packet_size_var`, `total_packets`, `total_bytes`, `iat_mean`, `iat_std`, `burst_rate`, `session_duration`, `tcp_ratio`, `udp_ratio`, `icmp_ratio`, `unique_ports`, `uncommon_port_ratio`, `avg_payload_entropy`, `avg_payload_size`, `payload_size_var`.

Features are returned once an IP has seen at least 3 packets.

Eviction targets the IP with the oldest last-seen timestamp (preserving low-and-slow attack patterns). Bounded by `MAX_TRACKED_IPS`.

## Payload Features (10 numeric + pattern matches)

**File:** `src/features/payload_analyzer.py`

Regex-based pattern matching on raw payload bytes, plus 10 numeric features:

- Pattern matches (6 signatures): `sql_injection`, `xss`, `command_injection`, `path_traversal`, `log4j`, `shellshock`. They surface as `payload:<name>` rules.
- Numeric features (10): `has_sqli`, `has_xss`, `has_cmdi`, `has_traversal`, `has_log4j`, `has_shellshock`, `pattern_match_count`, `max_payload_entropy`, `mean_payload_length`, `suspicious_char_ratio`.

Matching is applied directly to the first 4 KB of each packet after a cheap combined pre-screen regex (there are no per-pattern timeout threads). Hits are attributed to the flow they came from. Payload samples are bounded by `MAX_PAYLOAD_SAMPLES` (default 50) and `PAYLOAD_SAMPLE_BYTES` (default 4096) per sample.

UDP payloads are captured alongside TCP, enabling payload feature extraction for DNS tunneling and UDP-based attacks.

## JA3 TLS Fingerprinting

**File:** `src/features/ja3.py`

Extracts [JA3](https://github.com/salesforce/ja3) fingerprints from TLS ClientHello messages in real time:

1. Parses TLS record layer → ClientHello handshake
2. Extracts: TLS version, cipher suites, extensions, elliptic curves, EC point formats
3. Filters GREASE values (RFC 8701)
4. Produces `ja3_string` (comma-separated fields) and `ja3_hash` (MD5 of the string)

JA3 data is:
- Stored on every alert (`ja3_hash`, `ja3_string` columns)
- Checked against a configurable list of known-malicious hashes (`MALICIOUS_JA3_FILE`)
- Flagged by the rules engine as `malicious_ja3` → mapped to MITRE T1071 + T1573

Enable/disable with `JA3_ENABLED` (default `true`).

## Shared Utilities

**File:** `src/features/utils.py`

Common helpers shared across extractors (e.g., `byte_entropy`) to avoid code duplication.
