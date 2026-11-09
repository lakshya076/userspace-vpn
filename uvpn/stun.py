"""Minimal STUN client (RFC 5389 Binding request) to learn a socket's public endpoint.

Used for peer-to-peer tunnels: each computer asks two public STUN servers which
IP:port its NAT maps the UVPN socket to. If both servers see the same port the NAT
is endpoint-independent and UDP hole punching works; if the ports differ the NAT
is symmetric and the peers need a port forward, a LAN, or a relay.
"""
from __future__ import annotations

import os
import socket
import struct
from ipaddress import IPv4Address

MAGIC = 0x2112A442
BINDING_REQUEST, BINDING_SUCCESS = 0x0001, 0x0101
ATTR_MAPPED, ATTR_XOR_MAPPED = 0x0001, 0x0020
SERVERS = (("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478))


def build_request() -> tuple[bytes, bytes]:
    txid = os.urandom(12)
    return struct.pack("!HHI", BINDING_REQUEST, 0, MAGIC) + txid, txid


def parse_response(data: bytes, txid: bytes) -> tuple[str, int]:
    if len(data) < 20:
        raise ValueError("short STUN response")
    mtype, length, magic = struct.unpack_from("!HHI", data)
    if mtype != BINDING_SUCCESS or magic != MAGIC or data[8:20] != txid:
        raise ValueError("not a matching STUN success response")
    pos, end, mapped = 20, 20 + length, None
    while pos + 4 <= min(end, len(data)):
        atype, alen = struct.unpack_from("!HH", data, pos)
        value = data[pos + 4:pos + 4 + alen]
        if atype in (ATTR_XOR_MAPPED, ATTR_MAPPED) and len(value) >= 8 and value[1] == 1:  # IPv4
            port, ip = struct.unpack_from("!HI", value, 2)
            if atype == ATTR_XOR_MAPPED:
                port, ip = port ^ (MAGIC >> 16), ip ^ MAGIC
                return str(IPv4Address(ip)), port
            mapped = (str(IPv4Address(ip)), port)
        pos += 4 + alen + (-alen % 4)  # attributes are padded to 4 bytes
    if mapped:
        return mapped
    raise ValueError("no mapped address in STUN response")


def query(sock: socket.socket, server: tuple[str, int], timeout: float = 2.0, tries: int = 3) -> tuple[str, int]:
    """Blocking Binding request from sock; returns the public (ip, port) the server saw."""
    addr = (socket.gethostbyname(server[0]), server[1])
    request, txid = build_request()
    sock.settimeout(timeout)
    for _ in range(tries):
        sock.sendto(request, addr)
        try:
            while True:
                data, src = sock.recvfrom(2048)
                if src == addr:
                    return parse_response(data, txid)
        except socket.timeout:
            continue
    raise TimeoutError(f"no STUN reply from {server[0]}:{server[1]}")


def discover(port: int) -> list[tuple[str, tuple[str, int] | str]]:
    """Query every server from one socket bound to port; returns (server, endpoint or error)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    results: list[tuple[str, tuple[str, int] | str]] = []
    try:
        for server in SERVERS:
            try:
                results.append((f"{server[0]}:{server[1]}", query(sock, server)))
            except (OSError, ValueError) as exc:
                results.append((f"{server[0]}:{server[1]}", str(exc)))
    finally:
        sock.close()
    return results
