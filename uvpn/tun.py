"""Linux TUN device: raw IP packets in and out of a user-space program."""
from __future__ import annotations

import fcntl
import os
import struct

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000  # no 4-byte packet-info prefix: reads return bare IP packets


class Tun:
    def __init__(self, name: str = "uvpn0"):
        if len(name.encode()) >= 16:
            raise ValueError("interface name must be shorter than 16 bytes")
        self.fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        try:
            ifr = fcntl.ioctl(self.fd, TUNSETIFF, struct.pack("16sH22x", name.encode(), IFF_TUN | IFF_NO_PI))
        except OSError:
            os.close(self.fd)
            raise
        self.name = ifr[:16].rstrip(b"\x00").decode()

    def fileno(self) -> int:
        return self.fd

    def read(self) -> bytes | None:
        """One IP packet, or None when the queue is empty."""
        try:
            return os.read(self.fd, 65535)
        except BlockingIOError:
            return None

    def write(self, packet: bytes) -> None:
        try:
            os.write(self.fd, packet)
        except BlockingIOError:
            pass  # kernel queue full: drop, like a congested link would

    def close(self) -> None:
        os.close(self.fd)
