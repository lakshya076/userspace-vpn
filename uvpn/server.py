"""VPN server: accepts handshakes, assigns tunnel IPs, forwards between clients and its TUN."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import protocol as p
from .loop import Node

log = logging.getLogger("uvpn.server")

SESSION_IDLE_TIMEOUT = 60.0  # clients send keepalives every 10 s
SESSION_MAX_AGE = 180.0      # clients rekey every 120 s; older keys are wiped


@dataclass
class Peer:
    session: p.Session
    client_id: bytes
    tunnel_ip: IPv4Address
    endpoint: tuple[str, int]


class Server(Node):
    def __init__(self, tun, sock, psk: bytes, network: IPv4Network, mtu: int):
        super().__init__(tun, sock)
        self.psk = psk
        self.network = network
        self.mtu = mtu
        self.server_ip = next(network.hosts())
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
        peer = Peer(p.Session(sid, send_key=s2c, recv_key=c2s), init.client_id, ip, addr)
        self.sessions[sid] = peer
        self.by_ip[ip] = peer  # the previous session stays in self.sessions until it expires
        self.send(p.build_resp(self.psk, sid, private, ip, self.network.prefixlen, self.mtu, init.mac), addr)
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
            mtype, payload = peer.session.open(packet)
        except p.ProtocolError as exc:
            # Silent drop: unauthenticated senders get no reply at all.
            self.stats[f"drop_{type(exc).__name__}"] += 1
            log.debug("drop from %s:%d: %s", addr[0], addr[1], exc)
            return
        if peer.endpoint != addr:
            log.info("session %08x roamed %s:%d -> %s:%d", sid, *peer.endpoint, *addr)
            peer.endpoint = addr  # only after the packet authenticated
        if mtype == p.DATA:
            # Anti-spoofing: a client may only send from the address it was given.
            if len(payload) < 20 or payload[0] >> 4 != 4 or payload[12:16] != peer.tunnel_ip.packed:
                self.stats["drop_spoofed"] += 1
                return
            self.tun.write(payload)
        elif mtype == p.KEEPALIVE:
            self.send(peer.session.seal(p.KEEPALIVE), addr)
        elif mtype == p.CLOSE:
            log.info("session %08x closed by client", sid)
            self._remove(sid, release_lease=True)

    def on_tun_packet(self, packet: bytes) -> None:
        if len(packet) < 20 or packet[0] >> 4 != 4:
            return  # IPv4 only for now
        peer = self.by_ip.get(IPv4Address(packet[16:20]))
        if peer is None:
            self.stats["drop_no_route"] += 1
            return
        self.send(peer.session.seal(p.DATA, packet), peer.endpoint)

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
        for mac, expiry in list(self.seen_inits.items()):
            if expiry < now:
                del self.seen_inits[mac]
