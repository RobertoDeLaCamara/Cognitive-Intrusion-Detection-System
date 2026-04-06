"""Unit tests for src/pipeline.py — the detection pipeline callback.

Covers:
- _resolve_hostname: caching and error handling
- _is_trusted_outbound: TRUSTED_OUTBOUND config matching
- on_flow_complete: engine dispatch, dedup, alert persistence
- _persist_alert: queue-full drop
"""

import queue
import socket
import time
import logging
import numpy as np
import pytest
from unittest.mock import MagicMock, patch

from src.features.flow_extractor import FlowRecord
from src.ensemble.scorer import EngineScores, EnsembleResult


# ── Helpers ────────────────────────────────────────────────────────────────

def _flow(src_ip="1.2.3.4", dst_ip="8.8.8.8"):
    return FlowRecord(key=(src_ip, dst_ip, 12345, 80, 6))


def _ens_result(score=0.9, is_anomaly=True, active_engines=None):
    return EnsembleResult(
        score=score,
        is_anomaly=is_anomaly,
        engine_scores=EngineScores(),
        active_engines=active_engines or ["rules"],
        calibrated_score=score,
    )


def _mock_engines(
    sup_available=False, sup_result=None,
    ifo_available=False, ifo_score=0.0,
    lstm_available=False, lstm_score=0.0,
    rule_result=(0.0, []),
    ens_result=None,
):
    sup = MagicMock()
    sup.is_available = sup_available
    sup.predict.return_value = sup_result

    ifo = MagicMock()
    ifo.is_available = ifo_available
    ifo.anomaly_score.return_value = ifo_score

    lm = MagicMock()
    lm.is_available = lstm_available
    lm.anomaly_score.return_value = lstm_score

    rl = MagicMock()
    rl.evaluate.return_value = rule_result

    ens = MagicMock()
    ens.score.return_value = ens_result or _ens_result(score=0.1, is_anomaly=False)

    return sup, ifo, lm, rl, ens


@pytest.fixture(autouse=True)
def reset_pipeline_state():
    """Clear module-level dedup and DNS caches before each test."""
    import src.pipeline as pipeline
    pipeline._dedup_cache.clear()
    pipeline._dns_cache.clear()
    yield


# ── _resolve_hostname ──────────────────────────────────────────────────────

class TestResolveHostname:
    def test_returns_hostname_on_success(self):
        import src.pipeline as pipeline
        with patch("socket.gethostbyaddr", return_value=("example.com", [], ["1.2.3.4"])):
            assert pipeline._resolve_hostname("1.2.3.4") == "example.com"

    def test_caches_result_avoids_second_lookup(self):
        import src.pipeline as pipeline
        with patch("socket.gethostbyaddr", return_value=("cached.host", [], [])) as mock_dns:
            pipeline._resolve_hostname("2.2.2.2")
            pipeline._resolve_hostname("2.2.2.2")
        mock_dns.assert_called_once()

    def test_returns_empty_string_on_herror(self):
        import src.pipeline as pipeline
        with patch("socket.gethostbyaddr", side_effect=socket.herror):
            assert pipeline._resolve_hostname("0.0.0.0") == ""

    def test_returns_empty_string_on_gaierror(self):
        import src.pipeline as pipeline
        with patch("socket.gethostbyaddr", side_effect=socket.gaierror):
            assert pipeline._resolve_hostname("0.0.0.1") == ""

    def test_expired_entry_triggers_new_lookup(self):
        import src.pipeline as pipeline
        pipeline._dns_cache["3.3.3.3"] = ("old.host", time.time() - 9999)
        with patch("socket.gethostbyaddr", return_value=("new.host", [], [])):
            result = pipeline._resolve_hostname("3.3.3.3")
        assert result == "new.host"


# ── _is_trusted_outbound ───────────────────────────────────────────────────

class TestIsTrustedOutbound:
    def test_returns_false_when_config_empty(self):
        import src.pipeline as pipeline
        with patch.object(pipeline, "TRUSTED_OUTBOUND", {}):
            assert pipeline._is_trusted_outbound("192.168.1.1", "8.8.8.8") is False

    def test_returns_false_when_src_ip_not_in_config(self):
        import src.pipeline as pipeline
        with patch.object(pipeline, "TRUSTED_OUTBOUND", {"10.0.0.1": [".google.com"]}):
            assert pipeline._is_trusted_outbound("192.168.1.99", "8.8.8.8") is False

    def test_matches_trusted_domain_suffix(self):
        import src.pipeline as pipeline
        with patch.object(pipeline, "TRUSTED_OUTBOUND", {"192.168.1.1": [".google.com"]}):
            with patch("socket.gethostbyaddr", return_value=("dns.google.com", [], [])):
                assert pipeline._is_trusted_outbound("192.168.1.1", "8.8.8.8") is True

    def test_no_match_wrong_domain(self):
        import src.pipeline as pipeline
        with patch.object(pipeline, "TRUSTED_OUTBOUND", {"192.168.1.1": [".cloudflare.com"]}):
            with patch("socket.gethostbyaddr", return_value=("evil.attacker.com", [], [])):
                assert pipeline._is_trusted_outbound("192.168.1.1", "8.8.8.8") is False

    def test_returns_false_when_hostname_empty(self):
        import src.pipeline as pipeline
        with patch.object(pipeline, "TRUSTED_OUTBOUND", {"192.168.1.1": [".google.com"]}):
            with patch("socket.gethostbyaddr", side_effect=socket.herror):
                assert pipeline._is_trusted_outbound("192.168.1.1", "8.8.8.8") is False


# ── on_flow_complete ───────────────────────────────────────────────────────

class TestOnFlowComplete:

    def _run(self, pipeline, engines, flow=None, flow_vec=None, host_vec=None,
             payload=None, ja3_info=None, trusted_outbound=None):
        sup, ifo, lm, rl, ens = engines
        flow = flow or _flow()
        flow_vec = flow_vec if flow_vec is not None else np.zeros(76, dtype=np.float32)
        payload = payload or []

        with patch.object(pipeline, "TRUSTED_OUTBOUND", trusted_outbound or {}):
            with patch.object(pipeline, "supervised", sup):
                with patch.object(pipeline, "iforest", ifo):
                    with patch.object(pipeline, "lstm", lm):
                        with patch.object(pipeline, "rules", rl):
                            with patch.object(pipeline, "ensemble", ens):
                                with patch.object(pipeline, "_persist_alert") as mock_persist:
                                    pipeline.on_flow_complete(
                                        flow, flow_vec, host_vec, payload, ja3_info=ja3_info
                                    )
                                    return mock_persist

    def test_skips_trusted_outbound(self):
        import src.pipeline as pipeline
        engines = _mock_engines()
        flow = _flow(src_ip="192.168.1.1", dst_ip="8.8.8.8")

        with patch.object(pipeline, "TRUSTED_OUTBOUND", {"192.168.1.1": [".google.com"]}):
            with patch("socket.gethostbyaddr", return_value=("dns.google.com", [], [])):
                with patch.object(pipeline, "_persist_alert") as mock_persist:
                    pipeline.on_flow_complete(flow, np.zeros(76, dtype=np.float32), None, [])
        mock_persist.assert_not_called()

    def test_no_alert_below_threshold(self):
        import src.pipeline as pipeline
        engines = _mock_engines(ens_result=_ens_result(score=0.1, is_anomaly=False))
        mock_persist = self._run(pipeline, engines)
        mock_persist.assert_not_called()

    def test_alert_fired_above_threshold(self):
        import src.pipeline as pipeline
        engines = _mock_engines(
            rule_result=(0.9, ["icmp_flood"]),
            ens_result=_ens_result(score=0.9, is_anomaly=True),
        )
        mock_persist = self._run(pipeline, engines, flow=_flow(src_ip="10.0.0.10"))
        mock_persist.assert_called_once()

    def test_dedup_suppresses_second_alert(self):
        import src.pipeline as pipeline
        engines = _mock_engines(
            rule_result=(0.9, ["syn_scan"]),
            ens_result=_ens_result(score=0.9, is_anomaly=True),
        )
        flow = _flow(src_ip="10.0.0.11")
        vec = np.zeros(76, dtype=np.float32)

        with patch.object(pipeline, "TRUSTED_OUTBOUND", {}):
            with patch.object(pipeline, "DEDUP_WINDOW_SECS", 300):
                with patch.object(pipeline, "supervised", engines[0]):
                    with patch.object(pipeline, "iforest", engines[1]):
                        with patch.object(pipeline, "lstm", engines[2]):
                            with patch.object(pipeline, "rules", engines[3]):
                                with patch.object(pipeline, "ensemble", engines[4]):
                                    with patch.object(pipeline, "_persist_alert") as mock_persist:
                                        pipeline.on_flow_complete(flow, vec, None, [])
                                        pipeline.on_flow_complete(flow, vec, None, [])
        assert mock_persist.call_count == 1

    def test_dedup_allows_after_window_expires(self):
        import src.pipeline as pipeline
        engines = _mock_engines(
            rule_result=(0.9, ["icmp_flood"]),
            ens_result=_ens_result(score=0.9, is_anomaly=True),
        )
        flow = _flow(src_ip="10.0.0.12")
        vec = np.zeros(76, dtype=np.float32)

        # Pre-populate cache with an old timestamp (window already expired)
        pipeline._dedup_cache[("10.0.0.12", "unknown")] = time.time() - 9999

        mock_persist = self._run(pipeline, engines, flow=flow, flow_vec=vec)
        mock_persist.assert_called_once()

    def test_supervised_engine_called_when_available(self):
        import src.pipeline as pipeline
        sup, ifo, lm, rl, ens = _mock_engines(
            sup_available=True,
            sup_result=("DoS Hulk", 0.92),
            ens_result=_ens_result(score=0.92, is_anomaly=True),
        )
        flow = _flow(src_ip="10.0.0.13")
        self._run(pipeline, (sup, ifo, lm, rl, ens), flow=flow)
        sup.predict.assert_called_once()

    def test_supervised_not_called_when_unavailable(self):
        import src.pipeline as pipeline
        sup, ifo, lm, rl, ens = _mock_engines(sup_available=False)
        self._run(pipeline, (sup, ifo, lm, rl, ens))
        sup.predict.assert_not_called()

    def test_host_features_fed_to_iforest_and_lstm(self):
        import src.pipeline as pipeline
        host_vec = np.ones(18, dtype=np.float32)
        sup, ifo, lm, rl, ens = _mock_engines(
            ifo_available=True,
            lstm_available=True,
            ens_result=_ens_result(score=0.1, is_anomaly=False),
        )
        flow = _flow(src_ip="10.0.0.14")

        with patch.object(pipeline, "TRUSTED_OUTBOUND", {}):
            with patch.object(pipeline, "supervised", sup):
                with patch.object(pipeline, "iforest", ifo):
                    with patch.object(pipeline, "lstm", lm):
                        with patch.object(pipeline, "rules", rl):
                            with patch.object(pipeline, "ensemble", ens):
                                pipeline.on_flow_complete(flow, np.zeros(76), host_vec, [])

        ifo.anomaly_score.assert_called_once_with(host_vec)
        lm.update.assert_called_once()
        lm.anomaly_score.assert_called_once()

    def test_iforest_and_lstm_skipped_without_host_vec(self):
        import src.pipeline as pipeline
        sup, ifo, lm, rl, ens = _mock_engines(ifo_available=True, lstm_available=True)
        self._run(pipeline, (sup, ifo, lm, rl, ens), host_vec=None)
        ifo.anomaly_score.assert_not_called()
        lm.update.assert_not_called()

    def test_rules_always_called(self):
        import src.pipeline as pipeline
        sup, ifo, lm, rl, ens = _mock_engines()
        self._run(pipeline, (sup, ifo, lm, rl, ens))
        rl.evaluate.assert_called_once()

    def test_ja3_info_passed_to_persist(self):
        import src.pipeline as pipeline
        ja3 = {"hash": "abc123def456", "string": "771,4865-4867,0-23"}
        sup, ifo, lm, rl, ens = _mock_engines(
            rule_result=(0.9, ["malicious_ja3"]),
            ens_result=_ens_result(score=0.9, is_anomaly=True),
        )
        flow = _flow(src_ip="10.0.0.15")

        with patch.object(pipeline, "TRUSTED_OUTBOUND", {}):
            with patch.object(pipeline, "supervised", sup):
                with patch.object(pipeline, "iforest", ifo):
                    with patch.object(pipeline, "lstm", lm):
                        with patch.object(pipeline, "rules", rl):
                            with patch.object(pipeline, "ensemble", ens):
                                with patch.object(pipeline, "_persist_alert") as mock_persist:
                                    pipeline.on_flow_complete(flow, np.zeros(76), None, [], ja3_info=ja3)

        _, _, _, _, _, ja3_arg = mock_persist.call_args[0]
        assert ja3_arg == ja3

    def test_benign_supervised_label_zeroes_score(self):
        """BENIGN supervised label must not raise the ensemble supervised score."""
        import src.pipeline as pipeline
        sup, ifo, lm, rl, ens = _mock_engines(
            sup_available=True,
            sup_result=("BENIGN", 0.95),
            ens_result=_ens_result(score=0.05, is_anomaly=False),
        )
        flow = _flow(src_ip="10.0.0.16")

        captured_scores = []

        def capture_score(scores_obj):
            captured_scores.append(scores_obj.supervised)
            return _ens_result(score=0.05, is_anomaly=False)

        ens.score.side_effect = capture_score

        with patch.object(pipeline, "TRUSTED_OUTBOUND", {}):
            with patch.object(pipeline, "supervised", sup):
                with patch.object(pipeline, "iforest", ifo):
                    with patch.object(pipeline, "lstm", lm):
                        with patch.object(pipeline, "rules", rl):
                            with patch.object(pipeline, "ensemble", ens):
                                pipeline.on_flow_complete(flow, np.zeros(76), None, [])

        assert captured_scores[0] == 0.0


# ── _persist_alert ─────────────────────────────────────────────────────────

class TestPersistAlert:
    def test_drops_when_queue_full(self, caplog):
        import src.pipeline as pipeline

        full_q = MagicMock()
        full_q.put_nowait.side_effect = queue.Full

        flow = _flow()
        scores = EngineScores()
        result = _ens_result()

        with patch.object(pipeline, "_alert_queue", full_q):
            with patch.object(pipeline, "_start_writer"):
                with caplog.at_level(logging.WARNING, logger="src.pipeline"):
                    pipeline._persist_alert(flow, scores, result, "high", [])

        assert "Alert queue full" in caplog.text

    def test_enqueues_item_when_space_available(self):
        import src.pipeline as pipeline

        mock_q = MagicMock()
        flow = _flow()
        scores = EngineScores()
        result = _ens_result()

        with patch.object(pipeline, "_alert_queue", mock_q):
            with patch.object(pipeline, "_start_writer"):
                pipeline._persist_alert(flow, scores, result, "high", ["rule1"])

        mock_q.put_nowait.assert_called_once()
        item = mock_q.put_nowait.call_args[0][0]
        assert item[0] is flow
        assert item[3] == "high"
        assert item[4] == ["rule1"]
