"""The per-layer lock parts used by the Dockerfile must stay in sync with the full lock."""

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("split_lock", ROOT / "scripts" / "split_lock.py")
split_lock = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(split_lock)

ARCHES = ["amd64", "arm64"]


def _blocks(text):
    """name -> full block text (pin line + hash lines)."""
    _, blocks = split_lock.parse(text)
    return {name: "\n".join(lines) for name, lines in blocks}


@pytest.mark.parametrize("arch", ARCHES)
def test_parts_are_committed_and_match_the_full_lock(arch):
    full = _blocks((ROOT / f"requirements-lock-{arch}.txt").read_text())
    seen = {}
    for part in split_lock.PARTS:
        text = (ROOT / f"requirements-lock-{part}-{arch}.txt").read_text()
        for name, block in _blocks(text).items():
            assert name not in seen, f"{name} is in both {seen[name]} and {part}"
            seen[name] = part
            assert full[name] == block, f"{name} differs from the full lock: rerun scripts/split_lock.py"
    assert set(seen) == set(full), "parts do not cover the full lock: rerun scripts/split_lock.py"


@pytest.mark.parametrize("arch", ARCHES)
def test_torch_has_its_own_layer_and_every_part_keeps_the_index_header(arch):
    torch_part = (ROOT / f"requirements-lock-torch-{arch}.txt").read_text()
    assert list(_blocks(torch_part)) == ["torch"]
    full_header = split_lock.parse((ROOT / f"requirements-lock-{arch}.txt").read_text())[0]
    for part in split_lock.PARTS:
        assert split_lock.parse((ROOT / f"requirements-lock-{part}-{arch}.txt").read_text())[0] == full_header


@pytest.mark.parametrize("arch", ARCHES)
def test_every_pin_is_hashed(arch):
    for part in split_lock.PARTS:
        text = (ROOT / f"requirements-lock-{part}-{arch}.txt").read_text()
        for name, block in _blocks(text).items():
            assert re.search(r"--hash=sha256:[0-9a-f]{64}", block), f"{name} has no hash in {part}"


def test_split_requires_a_torch_pin():
    with pytest.raises(ValueError):
        split_lock.split("--index-url https://x\nrequests==2.0.0 \\\n    --hash=sha256:" + "0" * 64 + "\n")


def test_dockerfile_installs_each_part_from_its_own_copy():
    df = (ROOT / "Dockerfile").read_text()
    for part in split_lock.PARTS:
        assert f"requirements-lock-{part}-*.txt" in df and f"requirements-lock-{part}-${{TARGETARCH}}.txt" in df


# ── Dashboard lock ───────────────────────────────────────────────────────────
DASHBOARD_LOCK = ROOT / "requirements-lock-dashboard.txt"


def _pins(text):
    """name -> version, names normalised the way pip compares them."""
    return {
        re.sub(r"[-_.]+", "-", name).lower(): version
        for name, version in re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", text, flags=re.M)
    }


def test_dashboard_lock_covers_the_dashboard_requirements_and_is_hashed():
    blocks = _blocks(DASHBOARD_LOCK.read_text())
    assert blocks
    for name, block in blocks.items():
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", block), f"{name} has no hash"
    wanted = re.findall(r"^([A-Za-z0-9_.-]+)", (ROOT / "requirements-dashboard.txt").read_text(), flags=re.M)
    assert wanted
    locked = _pins(DASHBOARD_LOCK.read_text())
    for name in wanted:
        assert name.lower() in locked, f"{name} is missing: rerun scripts/lock_requirements.sh"


@pytest.mark.parametrize("arch", ARCHES)
def test_dashboard_lock_keeps_the_versions_of_the_base_image(arch):
    """The dashboard stage installs on top of the base stage with --no-deps: a different
    version of a shared package would replace the one the API lock was resolved with."""
    base = _pins((ROOT / f"requirements-lock-{arch}.txt").read_text())
    dashboard = _pins(DASHBOARD_LOCK.read_text())
    shared = set(base) & set(dashboard)
    assert shared, "expected the dashboard to share packages with the base image"
    for name in shared:
        assert dashboard[name] == base[name], (
            f"{name}: dashboard {dashboard[name]} != base {base[name]}: rerun scripts/lock_requirements.sh"
        )


def test_dockerfile_installs_the_dashboard_from_its_hashed_lock():
    stage = (ROOT / "Dockerfile").read_text().split("AS dashboard", 1)[1]
    assert "ARG TARGETARCH" in stage, "build args are not inherited from the base stage"
    assert re.search(r"--require-hashes --no-deps \\\n\s+-r requirements-lock-dashboard\.txt", stage)
