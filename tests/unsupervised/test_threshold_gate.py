"""Stability gate: an outlier LSTM threshold must not replace the live baseline."""
from unittest.mock import patch

import pytest

from src.unsupervised import window_trainer as wt


class TestThresholdIsStable:
    def test_no_reference_or_disabled_accepts_everything(self):
        assert wt._threshold_is_stable(99.0, [], 3.0)
        assert wt._threshold_is_stable(99.0, [0.5], 0)

    @pytest.mark.parametrize("value, ok", [(0.5, True), (1.4, True), (0.18, True), (1.6, False), (0.16, False), (8.9, False)])
    def test_within_factor_three_of_median(self, value, ok):
        assert wt._threshold_is_stable(value, [0.5, 0.5, 0.5], 3.0) is ok

    def test_uses_the_median_so_one_outlier_in_the_reference_does_not_move_it(self):
        assert not wt._threshold_is_stable(8.9, [0.4, 0.5, 8.9, 0.45, 0.5], 3.0)

    def test_non_positive_median_does_not_block(self):
        assert wt._threshold_is_stable(0.3, [0.0, 0.0], 3.0)


@pytest.fixture
def trainer():
    with patch.object(wt.mlflow_registry, "init"):
        return wt.WindowTrainer()


class TestAcceptThreshold:
    def test_first_window_is_accepted(self, trainer):
        assert trainer._accept_threshold(8.9) is True

    def test_outlier_is_rejected_and_reference_unchanged(self, trainer):
        for t in (0.5, 0.45, 0.55):
            assert trainer._accept_threshold(t)
        assert trainer._accept_threshold(8.9) is False
        assert list(trainer._accepted_thresholds) == [0.5, 0.45, 0.55]
        assert trainer._consecutive_rejects == 1

    def test_a_normal_window_resets_the_reject_counter(self, trainer):
        trainer._accept_threshold(0.5)
        assert not trainer._accept_threshold(9.0)
        assert trainer._accept_threshold(0.6)
        assert trainer._consecutive_rejects == 0

    def test_regime_change_is_accepted_after_max_consecutive_rejects(self, trainer):
        trainer._accept_threshold(0.5)
        for _ in range(wt.BASELINE_MAX_CONSECUTIVE_REJECTS):
            assert not trainer._accept_threshold(9.0)
        assert trainer._accept_threshold(9.0) is True
        assert list(trainer._accepted_thresholds) == [9.0]   # new reference level
        assert trainer._consecutive_rejects == 0

    def test_gate_disabled_by_ratio_zero(self, trainer):
        trainer._accept_threshold(0.5)
        with patch.object(wt, "BASELINE_THRESHOLD_MAX_RATIO", 0):
            assert trainer._accept_threshold(50.0) is True
