"""Header obfuscation: make every UVPN packet look like random bytes on the wire.

The 16-byte header (version, type, session id, sequence) is XORed with a mask
ChaCha20(key, nonce = last 16 bytes of the packet). The last 16 bytes are an AEAD
tag, a MAC, random padding or XORed ciphertext, so the nonce differs per packet,
and the receiver can recompute the mask before it knows anything else. The key
comes from the pre-shared key, so an observer without it sees no fixed bytes to
fingerprint. This hides the protocol; it adds no security beyond the AEAD.
"""
from __future__ import annotations

import random

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HEADER_LEN = 16
SAMPLE_LEN = 16
PAD_BUCKET = 128  # DATA plaintext is padded up to a multiple of this, hiding exact packet sizes


class Obfuscator:
    def __init__(self, psk: bytes):
        self._key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                         info=b"uvpn header obfuscation").derive(psk)

    def _mask(self, sample: bytes) -> bytes:
        return Cipher(algorithms.ChaCha20(self._key, sample), mode=None).encryptor().update(bytes(HEADER_LEN))

    def apply(self, packet: bytes) -> bytes:
        """Mask or unmask (XOR is its own inverse). Packets must be at least 32 bytes."""
        mask = self._mask(packet[-SAMPLE_LEN:])
        header = bytes(a ^ b for a, b in zip(packet[:HEADER_LEN], mask))
        return header + packet[HEADER_LEN:]


def pad_ip_packet(packet: bytes, mtu: int) -> bytes:
    """Zero-pad an IP packet to the next bucket; the receiver trims by the IP length field."""
    target = min(mtu, -(-len(packet) // PAD_BUCKET) * PAD_BUCKET)
    return packet + bytes(max(0, target - len(packet)))


def random_padding(limit: int = 64) -> int:
    return random.randrange(limit)
