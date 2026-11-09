"""Adaptive XOR forward error correction over sealed packets.

The sender groups every k consecutive transport packets into a block and sends one
parity packet: the XOR of their ciphertexts (each zero-padded to the longest). If
exactly one packet of a block is lost, the receiver XORs the parity with the k - 1
packets it did get and rebuilds the missing ciphertext, which then goes through
the normal AEAD check. k shrinks as the loss the peer reports grows, trading
bandwidth for resilience.

Parity body: count(1) | count x (type(1), length(2)) | xor bytes
(the parity packet's header carries the block's first sequence number).
"""
from __future__ import annotations

import struct

FLUSH_DELAY = 0.005  # seconds a partial block may wait before its parity is sent
MAX_K = 8            # keeps a parity packet under 1500 bytes at the default 1400 MTU
ENTRY = struct.Struct("!BH")

# (loss upper bound, k): loss below 0.5 % needs no parity; above 25 % every packet is sent twice.
ADAPT_TABLE = ((0.005, 0), (0.02, 8), (0.05, 6), (0.10, 4), (0.20, 3), (0.25, 2), (1.01, 1))


def k_for_loss(loss: float) -> int:
    return next(k for bound, k in ADAPT_TABLE if loss < bound)


def xor_bytes(chunks: list[bytes], length: int) -> bytes:
    acc = 0
    for c in chunks:
        acc ^= int.from_bytes(c.ljust(length, b"\x00"), "big")
    return acc.to_bytes(length, "big")


class Encoder:
    """mode: "off", "adaptive", or a fixed block size such as "4"."""

    def __init__(self, mode: str = "off"):
        self.mode = mode
        self.adaptive = mode == "adaptive"
        self.k = 0 if mode in ("off", "adaptive") else max(1, min(MAX_K, int(mode)))
        self.block: list[tuple[int, int, bytes]] = []  # (seq, type, body)
        self.started = 0.0

    def adapt(self, loss: float) -> None:
        if self.adaptive:
            self.k = k_for_loss(loss)

    def add(self, seq: int, mtype: int, body: bytes, now: float) -> tuple[int, bytes] | None:
        """Record a sealed packet; return (first seq, parity body) when the block is full."""
        if self.k == 0:
            self.block.clear()
            return None
        if self.block and seq != self.block[-1][0] + 1:
            self.block.clear()  # never mix non-consecutive packets in one block
        if not self.block:
            self.started = now
        self.block.append((seq, mtype, body))
        return self._emit() if len(self.block) >= self.k else None

    def flush(self, now: float) -> tuple[int, bytes] | None:
        if self.block and now - self.started >= FLUSH_DELAY:
            return self._emit()
        return None

    def _emit(self) -> tuple[int, bytes]:
        block, self.block = self.block, []
        length = max(len(body) for _, _, body in block)
        entries = b"".join(ENTRY.pack(mtype, len(body)) for _, mtype, body in block)
        return block[0][0], bytes([len(block)]) + entries + xor_bytes([b for _, _, b in block], length)


def parse_parity(body: bytes) -> tuple[list[tuple[int, int]], bytes]:
    """-> ([(type, length), ...], xor bytes); raises ValueError on malformed input."""
    if not body:
        raise ValueError("empty parity")
    count = body[0]
    end = 1 + count * ENTRY.size
    if count == 0 or count > MAX_K or len(body) < end:
        raise ValueError("bad parity header")
    entries = [ENTRY.unpack_from(body, 1 + i * ENTRY.size) for i in range(count)]
    xor = body[end:]
    if max(length for _, length in entries) != len(xor):
        raise ValueError("parity length mismatch")
    return entries, xor


def rebuild(xor: bytes, others: list[bytes], length: int) -> bytes:
    return xor_bytes([xor, *others], len(xor))[:length]
