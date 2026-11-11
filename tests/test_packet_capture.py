"""Tests for src/capture/packet_capture.py (worker pool and Scapy sniff wrapper).

No packet is captured: PacketProcessor is fed plain objects, and PacketCapture
runs with scapy's `sniff` replaced by a fake.
"""

import threading
import time

import pytest

from src.capture import packet_capture
from src.capture.packet_capture import PacketCapture, PacketProcessor


def _wait_for(condition, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def started():
    """Start processors through this so a failing test still stops its threads."""
    processors = []

    def _start(processor):
        processors.append(processor)
        processor.start()
        return processor

    yield _start
    for processor in processors:
        processor.stop(timeout=2.0)


class TestPacketProcessor:
    def test_workers_deliver_every_packet_to_the_callback(self, started):
        seen = []
        lock = threading.Lock()

        def callback(pkt):
            with lock:
                seen.append(pkt)

        processor = started(PacketProcessor(callback, num_workers=2, queue_size=100))
        for i in range(20):
            processor.enqueue(i)

        assert _wait_for(lambda: len(seen) == 20)
        assert sorted(seen) == list(range(20))
        assert processor.stats["dropped_packets"] == 0

    def test_full_queue_drops_and_counts_instead_of_blocking(self):
        # Not started: nothing drains the queue, so the third packet finds it full.
        processor = PacketProcessor(lambda pkt: None, num_workers=1, queue_size=2)

        for i in range(5):
            processor.enqueue(i)

        assert processor.stats == {"queue_size": 2, "dropped_packets": 3, "workers": 0}

    def test_callback_error_does_not_kill_the_worker(self, started):
        seen = []

        def callback(pkt):
            if pkt == "bad":
                raise ValueError("malformed packet")
            seen.append(pkt)

        processor = started(PacketProcessor(callback, num_workers=1, queue_size=10))
        processor.enqueue("bad")
        processor.enqueue("good")

        assert _wait_for(lambda: seen == ["good"])
        assert processor.stats["workers"] == 1

    def test_start_and_stop_manage_the_worker_threads(self):
        processor = PacketProcessor(lambda pkt: None, num_workers=3, queue_size=10)
        assert processor.stats["workers"] == 0

        processor.start()
        workers = list(processor._workers)
        try:
            assert processor.stats["workers"] == 3
            assert all(t.is_alive() and t.daemon for t in workers)
        finally:
            processor.stop(timeout=2.0)

        assert processor.stats["workers"] == 0
        assert not any(t.is_alive() for t in workers)

    def test_processor_can_be_restarted_after_stop(self, started):
        seen = []
        processor = PacketProcessor(seen.append, num_workers=1, queue_size=10)
        processor.start()
        processor.stop(timeout=2.0)

        started(processor)
        processor.enqueue("after-restart")

        assert _wait_for(lambda: seen == ["after-restart"])


class TestPacketCapture:
    def test_sniff_is_wired_to_the_processor(self, monkeypatch):
        calls = []
        monkeypatch.setattr(packet_capture, "sniff", lambda **kwargs: calls.append(kwargs))
        processor = PacketProcessor(lambda pkt: None, num_workers=1, queue_size=10)
        capture = PacketCapture(processor, iface="eth9")

        capture.start()
        capture.stop()

        (kwargs,) = calls
        assert kwargs["iface"] == "eth9"
        assert kwargs["prn"] == processor.enqueue
        assert kwargs["store"] is False

    def test_stop_filter_ends_the_sniff_only_after_stop(self, monkeypatch):
        sniffing = threading.Event()
        release = threading.Event()
        captured = {}

        def fake_sniff(**kwargs):
            captured.update(kwargs)
            sniffing.set()
            release.wait(timeout=3.0)

        monkeypatch.setattr(packet_capture, "sniff", fake_sniff)
        capture = PacketCapture(PacketProcessor(lambda pkt: None), iface=None)

        capture.start()
        assert sniffing.wait(timeout=3.0)
        stop_filter = captured["stop_filter"]
        assert stop_filter(object()) is False

        release.set()
        capture.stop()

        assert stop_filter(object()) is True
        assert not capture._sniffer_thread.is_alive()

    def test_sniffed_packets_reach_the_callback(self, monkeypatch, started):
        seen = []

        def fake_sniff(prn, **_kwargs):
            for pkt in ("p1", "p2", "p3"):
                prn(pkt)

        monkeypatch.setattr(packet_capture, "sniff", fake_sniff)
        processor = started(PacketProcessor(seen.append, num_workers=1, queue_size=10))
        capture = PacketCapture(processor, iface="eth9")

        capture.start()
        capture.stop()

        assert _wait_for(lambda: seen == ["p1", "p2", "p3"])

    def test_stop_before_start_is_a_no_op(self):
        PacketCapture(PacketProcessor(lambda pkt: None)).stop()
