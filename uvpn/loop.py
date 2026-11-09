"""Single-threaded event loop multiplexing the TUN device, the UDP socket and the status socket."""
from __future__ import annotations

import json
import logging
import os
import selectors
import signal
import socket
import time
from collections import Counter
from typing import Callable

from . import fec
from . import protocol as p
from .obfs import Obfuscator
from .tun import Tun

log = logging.getLogger("uvpn")

BATCH = 64  # packets drained per readiness event, so one busy side cannot starve the other
TICK = 1.0  # seconds between timer checks (FEC uses a shorter one)
STATUS_DIR = "/run/uvpn"


class Node:
    """Base for client and server: owns the socket, the TUN device and the loop."""

    role = "node"

    def __init__(self, tun: Tun, sock: socket.socket, obfuscator: Obfuscator | None = None,
                 fec_mode: str = "off"):
        self.tun = tun
        self.sock = sock
        self.obfs = obfuscator
        self.fec_mode = fec_mode
        self.tick = fec.FLUSH_DELAY if fec_mode != "off" else TICK
        self.stats: Counter[str] = Counter()
        self.started = time.monotonic()
        self._running = False

    # Subclasses implement these.
    def on_tun_packet(self, packet: bytes) -> None: ...
    def on_udp_packet(self, packet: bytes, addr: tuple[str, int]) -> None: ...
    def on_tick(self, now: float) -> None: ...
    def status(self) -> dict: return {}

    def send(self, packet: bytes, addr: tuple[str, int]) -> None:
        if self.obfs:
            packet = self.obfs.apply(packet)
        try:
            self.sock.sendto(packet, addr)
            self.stats["tx_packets"] += 1
            self.stats["tx_bytes"] += len(packet)
        except OSError as exc:
            self.stats["tx_errors"] += 1
            log.debug("sendto %s failed: %s", addr, exc)

    def send_sealed(self, session: p.Session, mtype: int, payload: bytes, addr: tuple[str, int]) -> None:
        """Seal, send, and send any FEC parity the packet completed."""
        self.send(session.seal(mtype, payload), addr)
        for parity in session.parity_out:
            self.send(parity, addr)
        session.parity_out.clear()

    def flush_parity(self, session: p.Session, addr: tuple[str, int], now: float) -> None:
        for parity in session.flush_parity(now):
            self.send(parity, addr)

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
            if len(packet) < p.MIN_PACKET:
                self.stats["drop_short"] += 1
                continue
            if self.obfs:
                packet = self.obfs.apply(packet)
            self.on_udp_packet(packet, addr)

    # ------------------------------------------------------------ status socket

    def _open_status_socket(self) -> socket.socket | None:
        path = os.path.join(STATUS_DIR, f"{self.role}-{self.tun.name}.sock")
        try:
            os.makedirs(STATUS_DIR, mode=0o700, exist_ok=True)
            if os.path.exists(path):
                os.unlink(path)
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(path)
            os.chmod(path, 0o600)  # status shows peer addresses: root only
            srv.listen(4)
            srv.setblocking(False)
            self._status_path = path
            return srv
        except OSError as exc:
            log.warning("status socket unavailable (%s): %s", path, exc)
            return None

    def _serve_status(self, srv: socket.socket) -> None:
        try:
            conn, _ = srv.accept()
        except BlockingIOError:
            return
        with conn:
            conn.setblocking(True)
            conn.settimeout(1.0)
            body = {"role": self.role, "tun": self.tun.name, "uptime_s": round(time.monotonic() - self.started, 1),
                    "obfuscation": self.obfs is not None, "fec": self.fec_mode,
                    "stats": dict(self.stats), **self.status()}
            try:
                conn.sendall(json.dumps(body).encode())
            except OSError:
                pass

    # ------------------------------------------------------------ loop

    def stop(self, *_: object) -> None:
        self._running = False

    def run(self) -> None:
        sel = selectors.DefaultSelector()
        handlers: dict[int, Callable[[], None]] = {self.tun.fileno(): self._drain_tun,
                                                   self.sock.fileno(): self._drain_udp}
        status = self._open_status_socket()
        if status:
            handlers[status.fileno()] = lambda: self._serve_status(status)
        for fd in handlers:
            sel.register(fd, selectors.EVENT_READ)
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        self._running = True
        next_tick = 0.0
        try:
            while self._running:
                for key, _ in sel.select(timeout=max(0.0, next_tick - time.monotonic())):
                    handlers[key.fd]()
                now = time.monotonic()
                if now >= next_tick:
                    self.on_tick(now)
                    next_tick = now + self.tick
        finally:
            sel.close()
            if status:
                status.close()
                try:
                    os.unlink(self._status_path)
                except OSError:
                    pass
        log.info("stats: %s", dict(self.stats))


def read_status(path: str) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(path)
        chunks = []
        while chunk := s.recv(65536):
            chunks.append(chunk)
    return json.loads(b"".join(chunks))
