"""Tests for the benign-label helper."""

import pytest

from src.labels import is_benign


@pytest.mark.parametrize("label", ["Benign", "BENIGN", "benign", " Benign ", None, ""])
def test_benign_spellings_and_missing(label):
    assert is_benign(label)


@pytest.mark.parametrize("label", ["DoS Hulk", "PortScan", "Web Attack", "Benign-ish"])
def test_attack_labels_are_not_benign(label):
    assert not is_benign(label)
