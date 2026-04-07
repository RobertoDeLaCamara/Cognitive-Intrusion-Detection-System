"""Engine protocol — defines the interface all detection engines must implement.

All ML engines must expose:
  - is_available: bool property indicating readiness
  - anomaly_score: returns a normalised [0, 1] score

Note: argument types vary by engine (np.ndarray for supervised/iforest,
str IP for lstm). The protocol checks structural conformance only.
The RulesEngine has a different interface (evaluate) and is excluded.
"""

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class DetectionEngine(Protocol):
    """Structural interface for CNDS ML detection engines."""

    @property
    def is_available(self) -> bool: ...

    def anomaly_score(self, *args, **kwargs) -> Optional[float]: ...
