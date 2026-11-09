"""VPN server (or the listening side of a peer-to-peer tunnel).

Accepts handshakes, assigns tunnel IPs, forwards between clients and its TUN,
validates new client addresses before following them, and can punch NAT holes
towards known peers.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import obfs
from . import protocol as p
from .loop import Node

log = logging.getLogger("uvpn.server")

SESSION_IDLE_TIMEOUT = 60.0  # clients send keepalives every 10 s (1 s with FEC)
SESSION_MAX_AGE = 180.0      # clients rekey every 120 s; older keys are wiped
PATH_CHALLENGE_INTERVAL = 1.0
PUNCH_INTERVAL = 1.0


@dataclass
class Peer:
    session: p.Session
    client_id: bytes
    tunnel_ip: IPv4Address
    endpoint: tuple[str, int]
    challenge: tuple[tuple[str, int], bytes, float] | None = field(default=None)  # (address, token, sent at)


class Server(Node):
    role = "server"

    def __init__(self, tun, sock, psk: bytes, network: IPv4Network, mtu: int,
                 obfuscator=None, fec_mode: str = "off", punch: list[tuple[str, int]] | None = None):
        super().__init__(tun, sock, obfuscator, fec_mode)
        self.psk = psk
        self.network = network
        self.mtu = mtu
        self.server_ip = next(network.hosts())
        self.punch = punch or []
        self._last_punch = float("-inf")
        self.sessions: dict[int, Peer] = {}           # session id -> peer
        self.by_ip: dict[IPv4Address, Peer] = {}      # tunnel ip -> newest peer session
        self.leases: dict[bytes, IPv4Address] = {}    # client id -> tunnel ip
        self.seen_inits: dict[bytes, float] = {}      # HS_INIT mac -> expiry (replay cache)

    # ------------------------------------------------------------ handshake

    def _allocate(self, client_id: bytes) -> IPv4Address | None:
        if client_id in self.leases:
            return self.leases[client_id]
        used = set(self.leases.values()) | {self.server_ip}
        for ip in self.network.hosts():
            if ip not in used:
                self.leases[client_id] = ip
                return ip
        return None

    def _handle_init(self, packet: bytes, addr: tuple[str, int]) -> None:
        init = p.parse_init(self.psk, packet)
        now = time.monotonic()
        if init.mac in self.seen_inits:
            raise p.ReplayError("replayed HS_INIT")
        self.seen_inits[init.mac] = now + 2 * p.HANDSHAKE_MAX_SKEW
        ip = self._allocate(init.client_id)
        if ip is None:
            log.warning("address pool exhausted; refusing %s", addr)
            return
        private = X25519PrivateKey.generate()
        server_public = p.public_bytes(private)
        c2s, s2c = p.derive_keys(self.psk, private, init.client_public, init.client_public, server_public)
        sid = p.new_session_id()
        while sid in self.sessions:
            sid = p.new_session_id()
        peer = Peer(p.Session(sid, send_key=s2c, recv_key=c2s, fec_mode=self.fec_mode), init.client_id, ip, addr)
        self.sessions[sid] = peer
        self.by_ip[ip] = peer  # the previous session stays in self.sessions until it expires
        padding = obfs.random_padding() if self.obfs else 0
        self.send(p.build_resp(self.psk, sid, private, ip, self.network.prefixlen, self.mtu, init.mac, padding), addr)
        self.stats["handshakes"] += 1
        log.info("session %08x: %s:%d -> %s", sid, addr[0], addr[1], ip)

    # ------------------------------------------------------------ data path

    def on_udp_packet(self, packet: bytes, addr: tuple[str, int]) -> None:
        try:
            mtype, _, sid, _ = p.parse_header(packet)
            if mtype == p.HS_INIT:
                self._handle_init(packet, addr)
                return
            peer = self.sessions.get(sid)
            if peer is None:
                raise p.ProtocolError(f"unknown session {sid:08x}")
            if mtype == p.FEC:
                rebuilt = peer.session.recover(packet)
                if rebuilt is None:
                    return
                mtype, payload = peer.session.open(rebuilt, recovered=True)
                self.stats["fec_recovered"] += 1
            else:
                mtype, payload = peer.session.open(packet)
        except p.ProtocolError as exc:
            # Silent drop: unauthenticated senders get no reply at all.
            self.stats[f"drop_{type(exc).__name__}"] += 1
            log.debug("drop from %s:%d: %s", addr[0], addr[1], exc)
            return
        if addr != peer.endpoint:
            self._check_new_path(peer, addr, mtype, payload)
        if mtype == p.DATA:
            payload = payload[:int.from_bytes(payload[2:4], "big")]  # strip obfuscation padding
            # Anti-spoofing: a client may only send from the address it was given.
            if len(payload) < 20 or payload[0] >> 4 != 4 or payload[12:16] != peer.tunnel_ip.packed:
                self.stats["drop_spoofed"] += 1
                return
            self.tun.write(payload)
        elif mtype == p.KEEPALIVE:
            peer.session.peer_feedback(p.parse_keepalive(payload))
            reply = p.keepalive_payload(peer.session.measure_loss(), obfs.random_padding() if self.obfs else 0)
            self.send_sealed(peer.session, p.KEEPALIVE, reply, peer.endpoint)
        elif mtype == p.CLOSE:
            log.info("session %08x closed by client", sid)
            self._remove(sid, release_lease=True)

    def _check_new_path(self, peer: Peer, addr: tuple[str, int], mtype: int, payload: bytes) -> None:
        """Follow a client to a new address only after it proves it receives there (as QUIC does)."""
        if mtype == p.PATH_RESPONSE and peer.challenge and peer.challenge[0] == addr \
                and payload == peer.challenge[1]:
            log.info("session %08x moved %s:%d -> %s:%d (path validated)",
                     peer.session.id, *peer.endpoint, *addr)
            peer.endpoint, peer.challenge = addr, None
            self.stats["path_migrations"] += 1
            return
        now = time.monotonic()
        if peer.challenge and peer.challenge[0] == addr and now - peer.challenge[2] < PATH_CHALLENGE_INTERVAL:
            return  # one challenge per second per address: no amplification
        token = os.urandom(8)
        peer.challenge = (addr, token, now)
        self.send(peer.session.seal(p.PATH_CHALLENGE, token), addr)
        self.stats["path_challenges"] += 1

    def on_tun_packet(self, packet: bytes) -> None:
        if len(packet) < 20 or packet[0] >> 4 != 4:
            return  # IPv4 only for now
        peer = self.by_ip.get(IPv4Address(packet[16:20]))
        if peer is None:
            self.stats["drop_no_route"] += 1
            return
        if self.obfs:
            packet = obfs.pad_ip_packet(packet, self.mtu)
        self.send_sealed(peer.session, p.DATA, packet, peer.endpoint)

    # ------------------------------------------------------------ timers

    def _remove(self, sid: int, release_lease: bool) -> None:
        peer = self.sessions.pop(sid, None)
        if peer is None:
            return
        if self.by_ip.get(peer.tunnel_ip) is peer:
            del self.by_ip[peer.tunnel_ip]
            if release_lease:
                self.leases.pop(peer.client_id, None)

    def on_tick(self, now: float) -> None:
        for sid, peer in list(self.sessions.items()):
            s = peer.session
            if now - s.last_recv > SESSION_IDLE_TIMEOUT or now - s.created > SESSION_MAX_AGE:
                log.info("session %08x expired", sid)
                self._remove(sid, release_lease=True)
            else:
                self.flush_parity(s, peer.endpoint, now)
        for mac, expiry in list(self.seen_inits.items()):
            if expiry < now:
                del self.seen_inits[mac]
        if self.punch and now - self._last_punch >= PUNCH_INTERVAL:
            self._last_punch = now
            connected = {peer.endpoint[0] for peer in self.sessions.values()}
            for target in self.punch:
                if target[0] not in connected:
                    # Outbound packet opens our NAT for the peer's handshake; the peer drops it as noise.
                    self.send(os.urandom(p.MIN_PACKET), target)
                    self.stats["punch_tx"] += 1

    def status(self) -> dict:
        return {"tunnel": f"{self.server_ip}/{self.network.prefixlen}", "punch": [f"{h}:{pt}" for h, pt in self.punch],
                "sessions": [{**peer.session.info(), "tunnel_ip": str(peer.tunnel_ip),
                              "endpoint": f"{peer.endpoint[0]}:{peer.endpoint[1]}"}
                             for peer in self.sessions.values()]}
