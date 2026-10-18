#!/usr/bin/env python3
"""Write or check the SHA-256 manifest that guards pickle-based model artifacts.

    python scripts/model_manifest.py write   # (re)generate models/MANIFEST.sha256
    python scripts/model_manifest.py check   # verify every listed file; exit 1 on mismatch

Covers *.joblib and *.pkl under MODELS_DIR. Run `write` after training or deploying new
models, and review the diff of the manifest like any other code change.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from src.config import MODELS_DIR, MODEL_MANIFEST_PATH  # noqa: E402
from src.model_integrity import read_manifest, sha256_file  # noqa: E402

SUFFIXES = (".joblib", ".pkl")


def _artifacts():
    for root, _, files in os.walk(MODELS_DIR):
        for name in sorted(files):
            if name.endswith(SUFFIXES):
                full = os.path.join(root, name)
                yield os.path.relpath(full, MODELS_DIR).replace(os.sep, "/"), full


def write() -> int:
    lines = [f"{sha256_file(full)}  {rel}" for rel, full in sorted(_artifacts())]
    with open(MODEL_MANIFEST_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} entries to {MODEL_MANIFEST_PATH}")
    return 0


def check() -> int:
    entries = read_manifest(MODEL_MANIFEST_PATH)
    bad = 0
    for rel, digest in entries.items():
        full = os.path.join(MODELS_DIR, rel)
        if not os.path.exists(full):
            print(f"MISSING   {rel}")
            bad += 1
        elif sha256_file(full) != digest:
            print(f"MISMATCH  {rel}")
            bad += 1
    for rel, _ in _artifacts():
        if rel not in entries:
            print(f"UNLISTED  {rel}")
            bad += 1
    print("OK" if not bad else f"{bad} problem(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=("write", "check"))
    sys.exit(write() if ap.parse_args().command == "write" else check())
