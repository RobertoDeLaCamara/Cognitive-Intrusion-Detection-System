# Testing

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=src --cov-report=term-missing

# Single module
pytest tests/test_flow_extractor.py -v

# Lint, as CI runs it
ruff check src/ tests/
```

## Test Modules

Grouped by area. `ls tests/` is the authoritative list; a module added later belongs in one of these rows.

| Area | Files | Covers |
|---|---|---|
| API | `test_api.py`, `test_predict.py`, `test_incident_patch.py`, `test_engines_endpoint.py`, `test_feedback.py`, `test_assets.py`, `test_version.py` | Endpoints against an in-memory SQLite database: alerts, filters, export, `/api/predict`, incident status machine, `/api/engines`, tp/fp labels and export, asset inventory |
| Auth | `test_auth.py`, `test_auth_startup_guard.py`, `test_api_key_auth_routes.py`, `test_rbac_routes.py`, `test_ws_auth.py`, `test_metrics_token.py`, `test_telegram_callback_auth.py` | JWT and roles, refusal to start without auth, API-key middleware, role matrix per route, `/ws/alerts` in each auth mode, `METRICS_TOKEN`, Telegram Confirm/Undo allow-list |
| Configuration and startup | `test_config.py`, `test_init_db_migrations.py`, `test_model_integrity.py`, `test_lock_split.py` | Config validation, refusal to start on a failed migration, SHA-256 manifest for pickle models, hashed lock files in sync with the Dockerfile |
| Capture and features | `test_packet_capture.py`, `test_dispatcher.py`, `test_flow_extractor.py`, `test_host_extractor.py`, `test_payload_features.py`, `test_ja3.py`, `test_ethernet_padding.py` | Worker pool and sniff wrapper, flow tracking, the 76 / 18 / 10 feature vectors, JA3, Ethernet padding not counted as data |
| Engines and ensemble | `test_engines.py`, `test_rules_engine.py`, `test_ft_transformer_engine.py` (skipped without `torch` or the unified checkpoint; its two dataset tests also need `CNDS_TEST_DATA_DIR`), `test_ensemble.py`, `test_labels.py`, `test_feature_drift.py` | Supervised, Isolation Forest, LSTM and rules engines, weight redistribution and calibration, benign-label helper, input drift monitor |
| Pipeline | `test_pipeline.py`, `test_pipeline_suppression.py`, `test_background_failures_are_logged.py`, `test_failure_streak.py` | `on_flow_complete`, suppression of detector-written alerts, background failures leaving a log trace |
| Enrichment | `test_enrichment.py`, `test_correlation.py`, `test_suppression.py`, `test_ip_lists.py`, `test_threat_intel.py`, `test_mitre.py`, `test_ntfy.py`, `test_timeutils.py` | Correlation, suppression rules, decay, IP lists, threat-intel feeds, MITRE mapping, notification channels, naive-UTC invariant |
| Guardian | `test_guardian.py`, `test_guardian_loops.py` | AdGuard backend, whitelist, circuit breaker, block and expiry loops |
| Logwatch | `test_logwatch.py`, `test_logwatch_persist.py` | Rule loading, sliding-window engine, Gitea parser, alerts stored with `source="logwatch"` |
| Baseline | `engines/test_baseline_engine.py`, `unsupervised/` | Baseline engine, collector and trigger, training sequences, threshold gate, MLflow registration, evaluation bench, window stability (`slow`, needs `torch`) |
| MCP and triage | `test_mcp_server.py`, `test_triage.py` | Read-only MCP server, triage agent schema, guards and runner |
| Dashboard | `test_dashboard_api_client.py`, `test_dashboard_data.py`, `test_dashboard_views.py` | API client authentication, overview helpers, each view rendering against a fake API |
| Tooling | `test_siem.py`, `test_pcap_replay.py`, `test_replay_timestamps.py` | CEF syslog forwarder, pcap replay and labelling, capture time instead of wall clock in replay |

`pytest --collect-only -q` reports the current count (about 1,060 tests; without `torch` a dozen are skipped). It changes with every PR, so it is not pinned here. CI runs the suite inside the image, with `torch`, and fails below 75 % coverage of `src` (see [CI/CD Pipeline](CI-CD-Pipeline.md)).

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
