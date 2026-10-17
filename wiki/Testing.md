# Testing

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=src --cov-report=term-missing

# Single module
pytest tests/test_flow_extractor.py -v
```

## Test Modules

| File | Covers |
|---|---|
| `test_api.py` | API integration tests (end-to-end endpoint testing with in-memory SQLite) |
| `test_auth.py` | JWT authentication and RBAC enforcement |
| `test_config.py` | Configuration validation (weight sums, threshold ranges) |
| `test_engines.py` | Engine unit tests (supervised, isolation forest, LSTM, rules) |
| `test_enrichment.py` | Enrichment modules (correlation, suppression, decay, notifications, IP lists, DNS) |
| `test_ensemble.py` | Ensemble scorer (weight redistribution, calibration, thresholds) |
| `test_flow_extractor.py` | CICFlowMeter flow feature extraction |
| `test_host_extractor.py` | Per-IP host feature extraction |
| `test_ja3.py` | JA3 TLS fingerprint extraction |
| `test_mitre.py` | MITRE ATT&CK technique mapping |
| `test_payload_features.py` | Payload pattern matching and numeric features |
| `test_rules_engine.py` | Rule-based engine triggers |
| `test_siem.py` | CEF syslog forwarder |
| `test_pipeline.py`, `test_predict.py`, `test_dispatcher.py` | Capture pipeline callback, `/api/predict`, dispatcher |
| `test_correlation.py`, `test_suppression.py`, `test_ip_lists.py`, `test_threat_intel.py` | Incident correlation, suppression rules, IP lists, threat-intel feeds |
| `test_guardian.py` | Guardian: AdGuard backend, whitelist, circuit breaker |
| `test_mcp_server.py` | Read-only MCP server (queries, sanitisation, read-only guarantees) |
| `test_triage.py` | Triage agent schema, guards, runner |
| `test_ft_transformer_engine.py` | FT-Transformer engine (skipped without `torch`) |
| `test_timeutils.py` | Naive-UTC invariant for `DateTime` columns |
| `engines/test_baseline_engine.py`, `unsupervised/` | Baseline engine, collector/trigger, window stability (`slow`, needs `torch`) |

`pytest --collect-only -q` reports the current count (about 580 tests without `torch`; it changes with every PR, so it is not pinned here).

## Shared Fixtures

`tests/conftest.py` provides shared fixtures including:
- In-memory SQLite database sessions
- Mock feature vectors
- Test configuration overrides

## Writing New Tests

- All new code should include tests
- `pytest.ini` sets `asyncio_mode = auto`, so async tests need no marker (`pytest-asyncio`)
- Use `pytest-mock` for mocking external dependencies
- Aim to maintain or improve coverage
- The suite uses an in-memory SQLite database and needs no running services
