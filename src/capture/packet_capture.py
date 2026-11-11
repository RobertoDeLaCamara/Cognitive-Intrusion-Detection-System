"""Scapy-based packet capture with async worker queue.

Single capture loop dispatches packets to a bounded queue consumed
by worker threads — keeps the Scapy callback non-blocking.
"""

import queue
import threading
import logging
from typing import Callable, Optional

from scapy.all import sniff

from ..config import PACKET_WORKERS, PACKET_QUEUE_SIZE, CAPTURE_INTERFACE

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Bounded queue + worker pool that decouples capture from analysis."""

    def __init__(
        self,
        callback: Callable,
        num_workers: int = PACKET_WORKERS,
        queue_size: int = PACKET_QUEUE_SIZE,
    ):
        self._callback = callback
        self._num_workers = num_workers
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []
        self._dropped = 0
        self._dropped_lock = threading.Lock()

    def enqueue(self, packet) -> None:
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            with self._dropped_lock:
                self._dropped += 1

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                pkt = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._callback(pkt)
            except Exception as e:
                logger.error("Packet processing error: %s", e)
            finally:
                self._queue.task_done()

    def start(self) -> None:
        self._stop.clear()
        for i in range(self._num_workers):
            t = threading.Thread(target=self._loop, daemon=True, name=f"pkt-worker-{i}")
            t.start()
            self._workers.append(t)
        logger.info("PacketProcessor started: %d workers, queue=%d", self._num_workers, self._queue.maxsize)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        for t in self._workers:
            t.join(timeout=timeout)
        self._workers.clear()
        logger.info("PacketProcessor stopped")

    @property
    def stats(self) -> dict:
        with self._dropped_lock:
            dropped = self._dropped
        return {
            "queue_size": self._queue.qsize(),
            "dropped_packets": dropped,
            "workers": len(self._workers),
        }


class PacketCapture:
    """Wraps Scapy sniff; sends packets to a PacketProcessor."""

    def __init__(self, processor: PacketProcessor, iface: Optional[str] = CAPTURE_INTERFACE):
        self._processor = processor
        self._iface = iface
        self._sniffer_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def _sniffer_loop(self) -> None:
        logger.info("Starting packet capture on iface=%s", self._iface or "auto")
        sniff(
            iface=self._iface,
            prn=self._processor.enqueue,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )

    def start(self) -> None:
        self._stop.clear()
        self._sniffer_thread = threading.Thread(
            target=self._sniffer_loop, daemon=True, name="pkt-capture"
        )
        self._sniffer_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=5.0)
