"""Command line: python3 -m uvpn {genpsk,server,client}."""
from __future__ import annotations

import argparse
import base64
import logging
import os
import socket
import stat
import sys
from ipaddress import IPv4Network

from . import protocol as p
from .netconf import NetConfig, default_interface
from .tun import Tun

log = logging.getLogger("uvpn")


def load_psk(path: str) -> bytes:
    mode = os.stat(path).st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        log.warning("%s is readable by other users; run: chmod 600 %s", path, path)
    with open(path) as f:
        psk = base64.b64decode(f.read().strip(), validate=True)
    if len(psk) != p.PSK_LEN:
        sys.exit(f"{path}: pre-shared key must be {p.PSK_LEN} bytes (base64)")
    return psk


def parse_endpoint(text: str, default_port: int) -> tuple[str, int]:
    host, _, port = text.rpartition(":") if ":" in text else (text, "", str(default_port))
    infos = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)
    return infos[0][4][0], int(port)


def udp_socket(bind: tuple[str, int]) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(bind)
    sock.setblocking(False)
    return sock


def cmd_genpsk(_: argparse.Namespace) -> None:
    print(base64.b64encode(os.urandom(p.PSK_LEN)).decode())


def cmd_server(args: argparse.Namespace) -> None:
    from .server import Server

    network = IPv4Network(args.subnet)
    psk = load_psk(args.psk_file)
    host, _, port = args.listen.rpartition(":")
    sock = udp_socket((host or "0.0.0.0", int(port)))
    tun = Tun(args.tun)
    net = NetConfig()
    server = Server(tun, sock, psk, network, args.mtu)
    try:
        net.interface_up(tun.name, f"{server.server_ip}/{network.prefixlen}", args.mtu)
        if args.nat:
            out = args.out_iface or default_interface()
            net.enable_forwarding()
            net.masquerade(str(network), tun.name, out)
            log.info("NAT: %s -> %s", network, out)
        log.info("server listening on udp %s, tunnel %s/%d on %s", args.listen, server.server_ip,
                 network.prefixlen, tun.name)
        server.run()
    finally:
        net.cleanup()
        tun.close()


def cmd_client(args: argparse.Namespace) -> None:
    from .client import Client

    psk = load_psk(args.psk_file)
    endpoint = parse_endpoint(args.server, 51820)
    sock = udp_socket(("0.0.0.0", 0))
    tun = Tun(args.tun)
    net = NetConfig()
    client = Client(tun, sock, psk, endpoint, net, route_all=args.route_all, routes=args.route)
    try:
        client.run()
        client.close()
    finally:
        net.cleanup()
        tun.close()


def main() -> None:
    ap = argparse.ArgumentParser(prog="uvpn", description="Secure Userspace VPN")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every dropped packet")
    sub = ap.add_subparsers(dest="command", required=True)

    sub.add_parser("genpsk", help="print a new random pre-shared key").set_defaults(func=cmd_genpsk)

    s = sub.add_parser("server", help="run the VPN server")
    s.add_argument("--listen", default="0.0.0.0:51820", help="UDP address:port (default %(default)s)")
    s.add_argument("--psk-file", required=True)
    s.add_argument("--subnet", default="10.8.0.0/24", help="tunnel subnet (default %(default)s)")
    s.add_argument("--mtu", type=int, default=1400)
    s.add_argument("--tun", default="uvpn0")
    s.add_argument("--nat", action="store_true", help="enable IP forwarding + MASQUERADE to the Internet")
    s.add_argument("--out-iface", help="NAT egress interface (default: the default-route interface)")
    s.set_defaults(func=cmd_server)

    c = sub.add_parser("client", help="run the VPN client")
    c.add_argument("--server", required=True, help="server host[:port]")
    c.add_argument("--psk-file", required=True)
    c.add_argument("--tun", default="uvpn0")
    c.add_argument("--route-all", action="store_true", help="send all IPv4 traffic through the tunnel")
    c.add_argument("--route", action="append", default=[], metavar="CIDR", help="extra network to route into the tunnel")
    c.set_defaults(func=cmd_client)

    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    args.func(args)


if __name__ == "__main__":
    main()
