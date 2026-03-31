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

## Shared Fixtures

`tests/conftest.py` provides shared fixtures including:
- In-memory SQLite database sessions
- Mock feature vectors
- Test configuration overrides

## Writing New Tests

- All new code should include tests
- Use `pytest-asyncio` for async test functions
- Use `pytest-mock` for mocking external dependencies
- Aim to maintain or improve coverage
- For integration tests, ensure Docker Compose services are running
