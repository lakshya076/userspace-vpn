"""UVPN wire format, handshake and per-session crypto (protocol version 1).

Every packet starts with a 16-byte header in network byte order:

    version(1) | type(1) | flags(2) | session id(4) | sequence(8)

Handshake messages carry a cleartext body authenticated with HMAC-SHA256
under the pre-shared key. Transport messages (DATA, KEEPALIVE, CLOSE,
PATH_CHALLENGE, PATH_RESPONSE) carry a ChaCha20-Poly1305 ciphertext; the
header is the AEAD associated data and the sequence number is the nonce, so
changing any header or payload byte makes the packet fail. FEC parity
packets are XORs of ciphertexts: they need no encryption, and whatever they
rebuild must still pass the AEAD check of the packet it rebuilds.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass
from ipaddress import IPv4Address

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import fec

VERSION = 1
HS_INIT, HS_RESP, DATA, KEEPALIVE, CLOSE, FEC, PATH_CHALLENGE, PATH_RESPONSE = range(1, 9)
TYPE_NAMES = {HS_INIT: "HS_INIT", HS_RESP: "HS_RESP", DATA: "DATA", KEEPALIVE: "KEEPALIVE",
              CLOSE: "CLOSE", FEC: "FEC", PATH_CHALLENGE: "PATH_CHALLENGE", PATH_RESPONSE: "PATH_RESPONSE"}
ENCRYPTED_TYPES = (DATA, KEEPALIVE, CLOSE, PATH_CHALLENGE, PATH_RESPONSE)

HEADER = struct.Struct("!BBHIQ")
HEADER_LEN = HEADER.size  # 16
TAG_LEN = 16
KEY_LEN = 32
PSK_LEN = 32
CLIENT_ID_LEN = 16
MAC_LEN = 32
MIN_PACKET = 32  # every message is at least header + 16 bytes (obfuscation samples the last 16)

# INIT body: client id | client ephemeral public key | timestamp (ns); then mac; then optional padding
INIT_BODY = struct.Struct("!16s32sQ")
INIT_LEN = HEADER_LEN + INIT_BODY.size + MAC_LEN
# RESP body: server ephemeral public key | tunnel ip | prefix length | mtu; then mac; then optional padding
RESP_BODY = struct.Struct("!32s4sBH")
RESP_LEN = HEADER_LEN + RESP_BODY.size + MAC_LEN

REPLAY_WINDOW = 2048
HANDSHAKE_MAX_SKEW = 120.0  # seconds a HS_INIT timestamp may differ from the server clock
REJECT_AFTER_MESSAGES = 2**64 - 2**13  # never let the 64-bit nonce wrap
RECENT_PACKETS = 512  # authenticated packets kept for FEC recovery

LOSS_UNKNOWN = 0xFFFF  # KEEPALIVE feedback value when nothing was expected


class ProtocolError(Exception):
    """Malformed or unacceptable packet; the caller drops it silently."""


class AuthError(ProtocolError):
    """MAC or AEAD tag did not verify."""


class ReplayError(ProtocolError):
    """Sequence number already seen or older than the replay window."""


def parse_header(packet: bytes) -> tuple[int, int, int, int]:
    """Return (type, flags, session id, sequence) or raise ProtocolError."""
    if len(packet) < MIN_PACKET:
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
               now_ns: int | None = None, padding: int = 0) -> tuple[bytes, Init]:
    header = HEADER.pack(VERSION, HS_INIT, 0, 0, 0)
    ts = time.time_ns() if now_ns is None else now_ns
    body = INIT_BODY.pack(client_id, public_bytes(private), ts)
    mac = _mac(psk, b"uvpn init", header, body)
    return header + body + mac + os.urandom(padding), Init(client_id, public_bytes(private), ts, mac)


def parse_init(psk: bytes, packet: bytes, now_ns: int | None = None) -> Init:
    if len(packet) < INIT_LEN:
        raise ProtocolError("short HS_INIT")
    header, body = packet[:HEADER_LEN], packet[HEADER_LEN:HEADER_LEN + INIT_BODY.size]
    mac = packet[HEADER_LEN + INIT_BODY.size:INIT_LEN]  # anything after the mac is padding
    if not hmac.compare_digest(mac, _mac(psk, b"uvpn init", header, body)):
        raise AuthError("HS_INIT mac mismatch")
    client_id, client_public, ts = INIT_BODY.unpack(body)
    now = time.time_ns() if now_ns is None else now_ns
    if abs(now - ts) > HANDSHAKE_MAX_SKEW * 1e9:
        raise ProtocolError("HS_INIT timestamp outside allowed skew")
    return Init(client_id, client_public, ts, mac)


def build_resp(psk: bytes, session_id: int, private: X25519PrivateKey, tunnel_ip: IPv4Address,
               prefix_len: int, mtu: int, init_mac: bytes, padding: int = 0) -> bytes:
    header = HEADER.pack(VERSION, HS_RESP, 0, session_id, 0)
    body = RESP_BODY.pack(public_bytes(private), tunnel_ip.packed, prefix_len, mtu)
    # Binding the INIT mac ties this response to exactly one request.
    return header + body + _mac(psk, b"uvpn resp", header, body, init_mac) + os.urandom(padding)


def parse_resp(psk: bytes, packet: bytes, init_mac: bytes) -> Resp:
    if len(packet) < RESP_LEN:
        raise ProtocolError("short HS_RESP")
    header, body = packet[:HEADER_LEN], packet[HEADER_LEN:HEADER_LEN + RESP_BODY.size]
    mac = packet[HEADER_LEN + RESP_BODY.size:RESP_LEN]
    if not hmac.compare_digest(mac, _mac(psk, b"uvpn resp", header, body, init_mac)):
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
    """Keys, counters, loss accounting and FEC state for one established tunnel."""

    def __init__(self, session_id: int, send_key: bytes, recv_key: bytes, fec_mode: str = "off"):
        self.id = session_id
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)
        self.send_seq = 0
        self.replay = ReplayWindow()
        self.created = time.monotonic()
        self.last_recv = self.created
        self.last_send = self.created
        self.fec = fec.Encoder(fec_mode)
        self.parity_out: list[bytes] = []
        self.recent: OrderedDict[int, tuple[int, bytes]] = OrderedDict()  # seq -> (type, wire body)
        self.counters = {"rx": 0, "recovered": 0, "parity_tx": 0}
        self.rx_loss = 0.0   # smoothed loss this side sees on incoming packets
        self.tx_loss = 0.0   # loss the peer reports for packets we send
        self._loss_mark = (-1, 0)  # (highest seq, rx count) at the last measurement

    def seal(self, mtype: int, payload: bytes = b"") -> bytes:
        if self.send_seq >= REJECT_AFTER_MESSAGES:
            raise ProtocolError("message limit reached; rekey required")
        seq = self.send_seq
        self.send_seq += 1
        header = HEADER.pack(VERSION, mtype, 0, self.id, seq)
        body = self._send.encrypt(_nonce(seq), payload, header)
        self.last_send = time.monotonic()
        self._queue_parity(self.fec.add(seq, mtype, body, self.last_send))
        return header + body

    def _queue_parity(self, parity: tuple[int, bytes] | None) -> None:
        if parity:
            first, body = parity
            self.parity_out.append(HEADER.pack(VERSION, FEC, 0, self.id, first) + body)
            self.counters["parity_tx"] += 1

    def flush_parity(self, now: float) -> list[bytes]:
        """Parity packets ready to send (full blocks, or partial blocks past the flush delay)."""
        self._queue_parity(self.fec.flush(now))
        out, self.parity_out = self.parity_out, []
        return out

    def open(self, packet: bytes, recovered: bool = False) -> tuple[int, bytes]:
        mtype, _, sid, seq = parse_header(packet)
        if mtype not in ENCRYPTED_TYPES or sid != self.id:
            raise ProtocolError("not a transport packet for this session")
        if not self.replay.check(seq):
            raise ReplayError(f"replayed sequence {seq}")
        body = packet[HEADER_LEN:]
        try:
            plaintext = self._recv.decrypt(_nonce(seq), body, packet[:HEADER_LEN])
        except InvalidTag as exc:
            raise AuthError("bad tag") from exc
        self.replay.update(seq)
        self.last_recv = time.monotonic()
        self.counters["recovered" if recovered else "rx"] += 1
        self.recent[seq] = (mtype, body)
        if len(self.recent) > RECENT_PACKETS:
            self.recent.popitem(last=False)
        return mtype, plaintext

    def recover(self, parity_packet: bytes) -> bytes | None:
        """Rebuild the one packet a parity block is missing, as a wire packet ready for open()."""
        mtype, _, sid, first = parse_header(parity_packet)
        if mtype != FEC or sid != self.id:
            raise ProtocolError("not a parity packet for this session")
        try:
            entries, xor = fec.parse_parity(parity_packet[HEADER_LEN:])
        except ValueError as exc:
            raise ProtocolError(str(exc)) from exc
        missing = [i for i in range(len(entries)) if first + i not in self.recent]
        if len(missing) != 1 or not self.replay.check(first + missing[0]):
            return None  # nothing lost, or more lost than one parity can fix
        i = missing[0]
        others = [self.recent[first + j][1] for j in range(len(entries)) if j != i]
        mtype, length = entries[i]
        body = fec.rebuild(xor, others, length)
        return HEADER.pack(VERSION, mtype, 0, self.id, first + i) + body

    def measure_loss(self) -> int:
        """Loss on incoming packets since the last call, in permille (LOSS_UNKNOWN if none expected)."""
        top, rx = self.replay.top, self.counters["rx"]
        last_top, last_rx = self._loss_mark
        self._loss_mark = (top, rx)
        expected = top - last_top
        if expected <= 0:
            return LOSS_UNKNOWN
        loss = max(0.0, 1.0 - (rx - last_rx) / expected)
        self.rx_loss = 0.7 * self.rx_loss + 0.3 * loss
        return round(loss * 1000)

    def peer_feedback(self, permille: int) -> None:
        if permille == LOSS_UNKNOWN:
            return
        self.tx_loss = 0.7 * self.tx_loss + 0.3 * permille / 1000
        self.fec.adapt(self.tx_loss)

    def info(self) -> dict:
        return {"id": f"{self.id:08x}", "age_s": round(time.monotonic() - self.created, 1),
                "tx_seq": self.send_seq, "rx_loss": round(self.rx_loss, 4), "tx_loss": round(self.tx_loss, 4),
                "fec_k": self.fec.k, **self.counters}


def keepalive_payload(loss_permille: int, padding: int = 0) -> bytes:
    return struct.pack("!H", loss_permille) + bytes(padding)


def parse_keepalive(payload: bytes) -> int:
    return struct.unpack_from("!H", payload)[0] if len(payload) >= 2 else LOSS_UNKNOWN


def new_session_id() -> int:
    return int.from_bytes(os.urandom(4), "big") or 1
