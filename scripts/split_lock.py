#!/usr/bin/env python3
"""Split a hashed lock file into per-layer parts so no single Docker layer is huge.

The registry on Magua cannot finalise a ~400 MB layer inside the Docker client's 30 s
response-header timeout, so `pip install -r requirements-lock-<arch>.txt` (one 390 MB
compressed layer) failed to push. Three parts keep every layer small, and torch, which
almost never changes, sits in its own layer so it is pushed once and then cached.

    requirements-lock-<arch>.txt  ->  requirements-lock-{torch,sci,rest}-<arch>.txt

Usage: split_lock.py [arch ...]   (default: amd64 arm64). Run by lock_requirements.sh.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TORCH = {"torch"}
# numeric stack + torch's own pure-python dependencies
SCI = {
    "numpy", "scipy", "pandas", "scikit-learn", "joblib", "threadpoolctl",
    "sympy", "mpmath", "networkx", "jinja2", "markupsafe", "fsspec", "filelock",
    "typing-extensions",
}
PARTS = ("torch", "sci", "rest")

_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==")


def parse(text: str):
    """Return (header_lines, [(name, block_lines)]). A block is a pin plus its --hash lines."""
    header, blocks = [], []
    for line in text.splitlines():
        m = _REQ.match(line)
        if m:
            blocks.append((m.group(1).lower().replace("_", "-"), [line]))
        elif blocks and line[:1].isspace():
            blocks[-1][1].append(line)
        elif not blocks:
            header.append(line)
        else:
            raise ValueError(f"unexpected line after first requirement: {line!r}")
    return header, blocks


def part_of(name: str) -> str:
    return "torch" if name in TORCH else "sci" if name in SCI else "rest"


def split(text: str) -> dict:
    header, blocks = parse(text)
    if not any(n in TORCH for n, _ in blocks):
        raise ValueError("no torch pin in the lock file")
    out = {p: list(header) for p in PARTS}
    for name, lines in blocks:
        out[part_of(name)].extend(lines)
    return {p: "\n".join(v) + "\n" for p, v in out.items()}


def main(argv):
    for arch in argv or ["amd64", "arm64"]:
        parts = split((ROOT / f"requirements-lock-{arch}.txt").read_text())
        for part, body in parts.items():
            (ROOT / f"requirements-lock-{part}-{arch}.txt").write_text(body)
        print(f"{arch}: " + ", ".join(f"{p}={body.count('==')}" for p, body in parts.items()))


if __name__ == "__main__":
    main(sys.argv[1:])
