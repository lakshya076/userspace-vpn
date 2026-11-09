"""Single-threaded event loop multiplexing the TUN device and the UDP socket."""
from __future__ import annotations

import logging
import selectors
import signal
import socket
import time
from collections import Counter
from typing import Callable

from .tun import Tun

log = logging.getLogger("uvpn")

BATCH = 64  # packets drained per readiness event, so one busy side cannot starve the other
TICK = 1.0  # seconds between timer checks


class Node:
    """Base for client and server: owns the socket, the TUN device and the loop."""

    def __init__(self, tun: Tun, sock: socket.socket):
        self.tun = tun
        self.sock = sock
        self.stats: Counter[str] = Counter()
        self._running = False

    # Subclasses implement these three.
    def on_tun_packet(self, packet: bytes) -> None: ...
    def on_udp_packet(self, packet: bytes, addr: tuple[str, int]) -> None: ...
    def on_tick(self, now: float) -> None: ...

    def send(self, packet: bytes, addr: tuple[str, int]) -> None:
        try:
            self.sock.sendto(packet, addr)
            self.stats["tx_packets"] += 1
            self.stats["tx_bytes"] += len(packet)
        except (BlockingIOError, OSError) as exc:
            self.stats["tx_errors"] += 1
            log.debug("sendto %s failed: %s", addr, exc)

    def _drain_tun(self) -> None:
        for _ in range(BATCH):
            packet = self.tun.read()
            if packet is None:
                return
            self.on_tun_packet(packet)

    def _drain_udp(self) -> None:
        for _ in range(BATCH):
            try:
                packet, addr = self.sock.recvfrom(65535)
            except BlockingIOError:
                return
            except OSError as exc:  # e.g. ICMP port unreachable surfaced as ECONNREFUSED
                log.debug("recvfrom failed: %s", exc)
                return
            self.stats["rx_packets"] += 1
            self.stats["rx_bytes"] += len(packet)
            self.on_udp_packet(packet, addr)

    def stop(self, *_: object) -> None:
        self._running = False

    def run(self) -> None:
        sel = selectors.DefaultSelector()
        handlers: dict[int, Callable[[], None]] = {self.tun.fileno(): self._drain_tun,
                                                   self.sock.fileno(): self._drain_udp}
        for fd in handlers:
            sel.register(fd, selectors.EVENT_READ)
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        self._running = True
        next_tick = 0.0
        while self._running:
            for key, _ in sel.select(timeout=TICK):
                handlers[key.fd]()
            now = time.monotonic()
            if now >= next_tick:
                self.on_tick(now)
                next_tick = now + TICK
        sel.close()
        log.info("stats: %s", dict(self.stats))
