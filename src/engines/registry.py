"""Shared engine singletons — single source of truth for all entry points."""

from .. import mlflow_registry
mlflow_registry.init()

from .supervised import SupervisedEngine
from .isolation_forest import IsolationForestEngine
from .lstm_autoencoder import LSTMAutoencoderEngine
from .baseline_engine import BaselineEngine
from .rules import RulesEngine
from ..ensemble.scorer import EnsembleScorer
from .protocol import DetectionEngine

supervised = SupervisedEngine()
iforest = IsolationForestEngine()
lstm = LSTMAutoencoderEngine()
baseline = BaselineEngine()
rules = RulesEngine()
ensemble = EnsembleScorer()

# Verify ML engines conform to the protocol
assert isinstance(supervised, DetectionEngine), "SupervisedEngine does not implement DetectionEngine"
assert isinstance(iforest, DetectionEngine), "IsolationForestEngine does not implement DetectionEngine"
assert isinstance(lstm, DetectionEngine), "LSTMAutoencoderEngine does not implement DetectionEngine"
assert isinstance(baseline, DetectionEngine), "BaselineEngine does not implement DetectionEngine"
