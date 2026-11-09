"""VPN client: handshakes with the server, configures its TUN, keeps the session alive."""
from __future__ import annotations

import logging
import os
import time
from ipaddress import IPv4Interface

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import protocol as p
from .loop import Node
from .netconf import NetConfig

log = logging.getLogger("uvpn.client")

KEEPALIVE_INTERVAL = 10.0
DEAD_PEER_TIMEOUT = 35.0   # ~3 missed keepalive replies
REKEY_AFTER_TIME = 120.0
HANDSHAKE_RETRY = 5.0


class Client(Node):
    def __init__(self, tun, sock, psk: bytes, server: tuple[str, int], net: NetConfig,
                 route_all: bool = False, routes: list[str] | None = None):
        super().__init__(tun, sock)
        self.psk = psk
        self.server = server
        self.net = net
        self.route_all = route_all
        self.routes = routes or []
        self.client_id = os.urandom(p.CLIENT_ID_LEN)  # keeps the same tunnel IP across rekeys
        self.current: p.Session | None = None
        self.previous: p.Session | None = None       # still accepted for in-flight packets after a rekey
        self.address: IPv4Interface | None = None
        self._pending: tuple[X25519PrivateKey, p.Init] | None = None
        self._last_init = float("-inf")

    # ------------------------------------------------------------ handshake

    def _send_init(self, now: float) -> None:
        private = X25519PrivateKey.generate()
        packet, init = p.build_init(self.psk, self.client_id, private)
        self._pending = (private, init)
        self._last_init = now
        self.send(packet, self.server)
        log.info("HS_INIT sent to %s:%d", *self.server)

    def _handle_resp(self, packet: bytes) -> None:
        if self._pending is None:
            raise p.ProtocolError("unexpected HS_RESP")
        private, init = self._pending
        resp = p.parse_resp(self.psk, packet, init.mac)
        c2s, s2c = p.derive_keys(self.psk, private, resp.server_public, init.client_public, resp.server_public)
        self._pending = None
        self.previous, self.current = self.current, p.Session(resp.session_id, send_key=c2s, recv_key=s2c)
        self.stats["handshakes"] += 1
        address = IPv4Interface(f"{resp.tunnel_ip}/{resp.prefix_len}")
        if self.address is None:
            self.net.interface_up(self.tun.name, str(address), resp.mtu)
            for cidr in self.routes:
                self.net.add_route(cidr, dev=self.tun.name)
            if self.route_all:
                self.net.route_all_via(self.tun.name, self.server[0])
            log.info("tunnel up: %s on %s (mtu %d), session %08x", address, self.tun.name, resp.mtu, resp.session_id)
        elif address != self.address:
            self.net.set_address(self.tun.name, str(address))
            log.info("tunnel address changed to %s", address)
        else:
            log.info("rekeyed: session %08x", resp.session_id)
        self.address = address
        self.send(self.current.seal(p.KEEPALIVE), self.server)  # confirms the keys to the server

    # ------------------------------------------------------------ data path

    def on_udp_packet(self, packet: bytes, addr: tuple[str, int]) -> None:
        if addr != self.server:
            return
        try:
            mtype, _, sid, _ = p.parse_header(packet)
            if mtype == p.HS_RESP:
                self._handle_resp(packet)
                return
            session = next((s for s in (self.current, self.previous) if s and s.id == sid), None)
            if session is None:
                raise p.ProtocolError(f"unknown session {sid:08x}")
            mtype, payload = session.open(packet)
        except p.ProtocolError as exc:
            self.stats[f"drop_{type(exc).__name__}"] += 1
            log.debug("drop: %s", exc)
            return
        if mtype == p.DATA:
            self.tun.write(payload)
        elif mtype == p.CLOSE:
            log.warning("server closed the session")
            self.current = self.previous = None

    def on_tun_packet(self, packet: bytes) -> None:
        if self.current is None:
            self.stats["drop_no_session"] += 1
            return
        self.send(self.current.seal(p.DATA, packet), self.server)

    # ------------------------------------------------------------ timers

    def on_tick(self, now: float) -> None:
        s = self.current
        if s is not None and now - s.last_recv > DEAD_PEER_TIMEOUT:
            log.warning("no reply from server for %.0f s; reconnecting", now - s.last_recv)
            self.current = self.previous = None
            s = None
        needs_handshake = s is None or now - s.created > REKEY_AFTER_TIME
        if needs_handshake and now - self._last_init >= HANDSHAKE_RETRY:
            self._send_init(now)
        if s is not None and now - s.last_send >= KEEPALIVE_INTERVAL:
            self.send(s.seal(p.KEEPALIVE), self.server)

    def close(self) -> None:
        if self.current is not None:
            self.send(self.current.seal(p.CLOSE), self.server)
