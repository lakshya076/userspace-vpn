"""UVPN wire format, handshake and per-session crypto (protocol version 1).

Every packet starts with a 16-byte header in network byte order:

    version(1) | type(1) | flags(2) | session id(4) | sequence(8)

Handshake messages carry a cleartext body authenticated with HMAC-SHA256
under the pre-shared key. DATA / KEEPALIVE / CLOSE carry a ChaCha20-Poly1305
ciphertext; the header is the AEAD associated data and the sequence number
is the nonce, so changing any header or payload byte makes the packet fail.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass
from ipaddress import IPv4Address

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
HS_INIT, HS_RESP, DATA, KEEPALIVE, CLOSE = 1, 2, 3, 4, 5
TYPE_NAMES = {HS_INIT: "HS_INIT", HS_RESP: "HS_RESP", DATA: "DATA", KEEPALIVE: "KEEPALIVE", CLOSE: "CLOSE"}
ENCRYPTED_TYPES = (DATA, KEEPALIVE, CLOSE)

HEADER = struct.Struct("!BBHIQ")
HEADER_LEN = HEADER.size  # 16
TAG_LEN = 16
KEY_LEN = 32
PSK_LEN = 32
CLIENT_ID_LEN = 16
MAC_LEN = 32

# INIT body: client id | client ephemeral public key | timestamp (ns) | mac
INIT_BODY = struct.Struct("!16s32sQ")
INIT_LEN = HEADER_LEN + INIT_BODY.size + MAC_LEN
# RESP body: server ephemeral public key | tunnel ip | prefix length | mtu | mac
RESP_BODY = struct.Struct("!32s4sBH")
RESP_LEN = HEADER_LEN + RESP_BODY.size + MAC_LEN

REPLAY_WINDOW = 2048
HANDSHAKE_MAX_SKEW = 120.0  # seconds a HS_INIT timestamp may differ from the server clock
REJECT_AFTER_MESSAGES = 2**64 - 2**13  # never let the 64-bit nonce wrap


class ProtocolError(Exception):
    """Malformed or unacceptable packet; the caller drops it silently."""


class AuthError(ProtocolError):
    """MAC or AEAD tag did not verify."""


class ReplayError(ProtocolError):
    """Sequence number already seen or older than the replay window."""


def parse_header(packet: bytes) -> tuple[int, int, int, int]:
    """Return (type, flags, session id, sequence) or raise ProtocolError."""
    if len(packet) < HEADER_LEN:
        raise ProtocolError("short packet")
    version, mtype, flags, sid, seq = HEADER.unpack_from(packet)
    if version != VERSION:
        raise ProtocolError(f"unsupported version {version}")
    if mtype not in TYPE_NAMES:
        raise ProtocolError(f"unknown type {mtype}")
    return mtype, flags, sid, seq


def _mac(psk: bytes, label: bytes, *parts: bytes) -> bytes:
    h = hmac.new(psk, label, hashlib.sha256)
    for p in parts:
        h.update(p)
    return h.digest()


def public_bytes(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive_keys(psk: bytes, private: X25519PrivateKey, peer_public: bytes,
                client_public: bytes, server_public: bytes) -> tuple[bytes, bytes]:
    """X25519 + HKDF-SHA256 -> (client-to-server key, server-to-client key)."""
    shared = private.exchange(X25519PublicKey.from_public_bytes(peer_public))
    if shared == bytes(32):
        raise ProtocolError("low-order public key")
    okm = HKDF(algorithm=hashes.SHA256(), length=2 * KEY_LEN, salt=psk,
               info=b"uvpn v1 session keys" + client_public + server_public).derive(shared)
    return okm[:KEY_LEN], okm[KEY_LEN:]


# ---------------------------------------------------------------- handshake

@dataclass
class Init:
    client_id: bytes
    client_public: bytes
    timestamp_ns: int
    mac: bytes


@dataclass
class Resp:
    session_id: int
    server_public: bytes
    tunnel_ip: IPv4Address
    prefix_len: int
    mtu: int


def build_init(psk: bytes, client_id: bytes, private: X25519PrivateKey,
               now_ns: int | None = None) -> tuple[bytes, Init]:
    header = HEADER.pack(VERSION, HS_INIT, 0, 0, 0)
    ts = time.time_ns() if now_ns is None else now_ns
    body = INIT_BODY.pack(client_id, public_bytes(private), ts)
    mac = _mac(psk, b"uvpn init", header, body)
    return header + body + mac, Init(client_id, public_bytes(private), ts, mac)


def parse_init(psk: bytes, packet: bytes, now_ns: int | None = None) -> Init:
    if len(packet) != INIT_LEN:
        raise ProtocolError("bad HS_INIT length")
    header, body = packet[:HEADER_LEN], packet[HEADER_LEN:HEADER_LEN + INIT_BODY.size]
    mac = packet[-MAC_LEN:]
    if not hmac.compare_digest(mac, _mac(psk, b"uvpn init", header, body)):
        raise AuthError("HS_INIT mac mismatch")
    client_id, client_public, ts = INIT_BODY.unpack(body)
    now = time.time_ns() if now_ns is None else now_ns
    if abs(now - ts) > HANDSHAKE_MAX_SKEW * 1e9:
        raise ProtocolError("HS_INIT timestamp outside allowed skew")
    return Init(client_id, client_public, ts, mac)


def build_resp(psk: bytes, session_id: int, private: X25519PrivateKey, tunnel_ip: IPv4Address,
               prefix_len: int, mtu: int, init_mac: bytes) -> bytes:
    header = HEADER.pack(VERSION, HS_RESP, 0, session_id, 0)
    body = RESP_BODY.pack(public_bytes(private), tunnel_ip.packed, prefix_len, mtu)
    # Binding the INIT mac ties this response to exactly one request.
    return header + body + _mac(psk, b"uvpn resp", header, body, init_mac)


def parse_resp(psk: bytes, packet: bytes, init_mac: bytes) -> Resp:
    if len(packet) != RESP_LEN:
        raise ProtocolError("bad HS_RESP length")
    header, body = packet[:HEADER_LEN], packet[HEADER_LEN:HEADER_LEN + RESP_BODY.size]
    if not hmac.compare_digest(packet[-MAC_LEN:], _mac(psk, b"uvpn resp", header, body, init_mac)):
        raise AuthError("HS_RESP mac mismatch")
    _, _, sid, _ = parse_header(packet)
    server_public, ip, prefix_len, mtu = RESP_BODY.unpack(body)
    return Resp(sid, server_public, IPv4Address(ip), prefix_len, mtu)


# ---------------------------------------------------------------- data path

class ReplayWindow:
    """Sliding bitmap of the last REPLAY_WINDOW sequence numbers (bit 0 = highest seen)."""

    def __init__(self, size: int = REPLAY_WINDOW):
        self.size = size
        self.top = -1
        self.bits = 0

    def check(self, seq: int) -> bool:
        if seq > self.top:
            return True
        offset = self.top - seq
        return offset < self.size and not (self.bits >> offset) & 1

    def update(self, seq: int) -> None:
        """Call only after the packet authenticated, so forgeries cannot move the window."""
        if seq > self.top:
            shift = seq - self.top
            self.bits = 1 if shift >= self.size else ((self.bits << shift) | 1) & ((1 << self.size) - 1)
            self.top = seq
        else:
            self.bits |= 1 << (self.top - seq)


def _nonce(seq: int) -> bytes:
    return b"\x00\x00\x00\x00" + seq.to_bytes(8, "big")


class Session:
    """One direction pair of keys plus counters for an established tunnel."""

    def __init__(self, session_id: int, send_key: bytes, recv_key: bytes):
        self.id = session_id
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)
        self.send_seq = 0
        self.replay = ReplayWindow()
        self.created = time.monotonic()
        self.last_recv = self.created
        self.last_send = self.created

    def seal(self, mtype: int, payload: bytes = b"") -> bytes:
        if self.send_seq >= REJECT_AFTER_MESSAGES:
            raise ProtocolError("message limit reached; rekey required")
        seq = self.send_seq
        self.send_seq += 1
        header = HEADER.pack(VERSION, mtype, 0, self.id, seq)
        self.last_send = time.monotonic()
        return header + self._send.encrypt(_nonce(seq), payload, header)

    def open(self, packet: bytes) -> tuple[int, bytes]:
        mtype, _, sid, seq = parse_header(packet)
        if mtype not in ENCRYPTED_TYPES or sid != self.id:
            raise ProtocolError("not a transport packet for this session")
        if len(packet) < HEADER_LEN + TAG_LEN:
            raise ProtocolError("short transport packet")
        if not self.replay.check(seq):
            raise ReplayError(f"replayed sequence {seq}")
        try:
            plaintext = self._recv.decrypt(_nonce(seq), packet[HEADER_LEN:], packet[:HEADER_LEN])
        except InvalidTag as exc:
            raise AuthError("bad tag") from exc
        self.replay.update(seq)
        self.last_recv = time.monotonic()
        return mtype, plaintext


def new_session_id() -> int:
    return int.from_bytes(os.urandom(4), "big") or 1
