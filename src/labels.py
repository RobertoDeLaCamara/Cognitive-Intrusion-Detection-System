"""Helpers for the class labels the supervised models emit."""

from typing import Optional


def is_benign(label: Optional[str]) -> bool:
    """True for a missing label or the normal-traffic class, whatever its casing.

    The engines emit "Benign" (the CIC-UNSW-NB15 class name) while older call
    sites and tests use "BENIGN"; comparing against one spelling silently
    treats the other as an attack type.
    """
    return not label or label.strip().upper() == "BENIGN"
