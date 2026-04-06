"""Tests for detection engine wrappers with mocked models."""

import pytest
import numpy as np
from unittest.mock import MagicMock, patch


class TestSupervisedEngine:
    @patch("src.engines.supervised.mlflow_registry.load_latest", return_value=None)
    @patch("os.path.exists", return_value=False)
    def test_unavailable_when_no_model(self, mock_exists, mock_mlflow):
        from src.engines.supervised import SupervisedEngine
        engine = SupervisedEngine(model_path="/nonexistent/model.joblib")
        assert not engine.is_available
        assert engine.predict(np.zeros(76)) is None

    def test_predict_with_mock_model(self):
        from src.engines.supervised import SupervisedEngine

        mock_model = MagicMock()
        mock_model.predict.return_value = ["DoS"]
        mock_model.predict_proba.return_value = np.array([[0.1, 0.9]])
        mock_model.n_features_in_ = 76

        with patch("src.engines.supervised.mlflow_registry.load_latest", return_value=mock_model):
            engine = SupervisedEngine()
            assert engine.is_available

            result = engine.predict(np.zeros(76))
            assert result is not None
            label, conf = result
            assert label == "DoS"
            assert conf == pytest.approx(0.9)

    def test_anomaly_score_benign(self):
        from src.engines.supervised import SupervisedEngine

        mock_model = MagicMock()
        mock_model.classes_ = ["Benign", "PortScan"]
        mock_model.predict_proba.return_value = np.array([[0.95, 0.05]])  # 1-0.95=0.05 < threshold
        mock_model.n_features_in_ = 76

        with patch("src.engines.supervised.mlflow_registry.load_latest", return_value=mock_model):
            engine = SupervisedEngine()
            score = engine.anomaly_score(np.zeros(76))
            assert score == 0.0

    def test_anomaly_score_attack(self):
        from src.engines.supervised import SupervisedEngine

        mock_model = MagicMock()
        mock_model.classes_ = ["Benign", "PortScan"]
        mock_model.predict_proba.return_value = np.array([[0.05, 0.95]])  # 1-0.05=0.95 >= threshold
        mock_model.n_features_in_ = 76

        with patch("src.engines.supervised.mlflow_registry.load_latest", return_value=mock_model):
            engine = SupervisedEngine()
            score = engine.anomaly_score(np.zeros(76))
            assert score == pytest.approx(0.95)


class TestIsolationForestEngine:
    @patch("src.engines.isolation_forest.mlflow_registry.load_latest", return_value=None)
    @patch("os.path.exists", return_value=False)
    def test_unavailable_when_no_model(self, mock_exists, mock_mlflow):
        from src.engines.isolation_forest import IsolationForestEngine
        engine = IsolationForestEngine(model_path="/nonexistent", scaler_path="/nonexistent")
        assert not engine.is_available
        assert engine.anomaly_score(np.zeros(18)) == 0.0

    def test_anomaly_score_with_mock_model(self):
        from src.engines.isolation_forest import IsolationForestEngine

        mock_model = MagicMock()
        mock_model.decision_function.return_value = np.array([-0.5])  # Negative = anomaly

        with patch("src.engines.isolation_forest.mlflow_registry.load_latest", return_value=mock_model), \
             patch("os.path.exists", return_value=False):
            engine = IsolationForestEngine()
            assert engine.is_available

            score = engine.anomaly_score(np.zeros(18))
            assert 0.0 < score < 1.0  # Should be anomalous

    def test_normal_traffic_low_score(self):
        from src.engines.isolation_forest import IsolationForestEngine

        mock_model = MagicMock()
        mock_model.decision_function.return_value = np.array([0.5])  # Positive = normal

        with patch("src.engines.isolation_forest.mlflow_registry.load_latest", return_value=mock_model), \
             patch("os.path.exists", return_value=False):
            engine = IsolationForestEngine()
            score = engine.anomaly_score(np.zeros(18))
            assert score < 0.5  # Should be normal


class TestRulesEngine:
    def test_no_rules_triggered(self):
        from src.engines.rules import RulesEngine
        from src.features.flow_extractor import FlowRecord

        engine = RulesEngine()
        record = FlowRecord(key=("1.1.1.1", "2.2.2.2", 12345, 80, 6))
        record.fwd_lengths = [100, 200]
        record.bwd_lengths = [150]
        record.start_time = 0.0
        record.last_time = 1.0

        flow_vec = np.zeros(76)
        score, triggered = engine.evaluate(record, flow_vec, [])
        assert score == 0.0
        assert triggered == []

    def test_icmp_flood_detection(self):
        from src.engines.rules import RulesEngine
        from src.features.flow_extractor import FlowRecord

        engine = RulesEngine()
        record = FlowRecord(key=("1.1.1.1", "2.2.2.2", 0, 0, 1))  # ICMP
        record.fwd_lengths = [64] * 100  # 100 ICMP packets
        record.bwd_lengths = []
        record.start_time = 0.0
        record.last_time = 1.0

        score, triggered = engine.evaluate(record, np.zeros(76), [])
        assert score == 1.0
        assert "icmp_flood" in triggered

    def test_large_payload_detection(self):
        from src.engines.rules import RulesEngine
        from src.features.flow_extractor import FlowRecord

        engine = RulesEngine()
        record = FlowRecord(key=("1.1.1.1", "2.2.2.2", 12345, 80, 6))
        record.fwd_lengths = [15000]  # Large payload
        record.bwd_lengths = [100]
        record.start_time = 0.0
        record.last_time = 1.0

        score, triggered = engine.evaluate(record, np.zeros(76), [])
        assert score == 1.0
        assert "large_payload" in triggered

    def test_payload_signature_detection(self):
        from src.engines.rules import RulesEngine
        from src.features.flow_extractor import FlowRecord

        engine = RulesEngine()
        record = FlowRecord(key=("1.1.1.1", "2.2.2.2", 12345, 80, 6))
        record.fwd_lengths = [500]
        record.bwd_lengths = [200]
        record.start_time = 0.0
        record.last_time = 1.0

        score, triggered = engine.evaluate(record, np.zeros(76), ["sqli", "xss"])
        assert score == 1.0
        assert "payload:sqli" in triggered
        assert "payload:xss" in triggered

    def test_asymmetric_upload_detection(self):
        from src.engines.rules import RulesEngine
        from src.features.flow_extractor import FlowRecord

        engine = RulesEngine()
        record = FlowRecord(key=("1.1.1.1", "2.2.2.2", 12345, 80, 6))
        record.fwd_lengths = [1000] * 20  # 20KB upload
        record.bwd_lengths = [100]  # 100B download
        record.start_time = 0.0
        record.last_time = 1.0

        score, triggered = engine.evaluate(record, np.zeros(76), [])
        assert score == 1.0
        assert "asymmetric_upload" in triggered


class TestLSTMEngine:
    @patch("src.engines.lstm_autoencoder.os.path.exists", return_value=False)
    def test_unavailable_when_no_model(self, mock_exists):
        from src.engines.lstm_autoencoder import LSTMAutoencoderEngine
        engine = LSTMAutoencoderEngine()
        assert not engine.is_available
        assert engine.anomaly_score("1.1.1.1") == 0.0
