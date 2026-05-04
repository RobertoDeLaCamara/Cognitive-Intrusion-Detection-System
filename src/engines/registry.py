"""Shared engine singletons — single source of truth for all entry points."""

from .. import mlflow_registry
mlflow_registry.init()

from .supervised import SupervisedEngine
from .ft_transformer_engine import FTTransformerEngine
from .isolation_forest import IsolationForestEngine
from .lstm_autoencoder import LSTMAutoencoderEngine
from .baseline_engine import BaselineEngine
from .rules import RulesEngine
from ..ensemble.scorer import EnsembleScorer
from .protocol import DetectionEngine

# Prefer the unified FT-Transformer when its checkpoint is present;
# otherwise fall back to the legacy Random Forest SupervisedEngine.
# Both implement the same predict / anomaly_score interface, so pipeline.py
# does not need to know which one is active.
_ft_engine = FTTransformerEngine()
supervised = _ft_engine if _ft_engine.is_available else SupervisedEngine()
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
