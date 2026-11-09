"""Command line: python3 -m uvpn {genpsk,server,client,stun,status}."""
from __future__ import annotations

import argparse
import base64
import glob
import json
import logging
import os
import socket
import stat
import sys
from ipaddress import IPv4Network

from . import protocol as p
from .netconf import NetConfig, default_interface
from .obfs import Obfuscator

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


def parse_endpoint(text: str, default_port: int = 51820) -> tuple[str, int]:
    host, _, port = text.rpartition(":") if ":" in text else (text, "", str(default_port))
    infos = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)
    return infos[0][4][0], int(port)


def fec_mode(text: str) -> str:
    if text in ("off", "adaptive") or (text.isdigit() and 1 <= int(text) <= 8):
        return text
    raise argparse.ArgumentTypeError("use off, adaptive, or a block size 1-8")


def udp_socket(bind: tuple[str, int]) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(bind)
    sock.setblocking(False)
    return sock


def cmd_genpsk(_: argparse.Namespace) -> None:
    print(base64.b64encode(os.urandom(p.PSK_LEN)).decode())


def cmd_server(args: argparse.Namespace) -> None:
    from .server import Server
    from .tun import Tun

    network = IPv4Network(args.subnet)
    psk = load_psk(args.psk_file)
    host, _, port = args.listen.rpartition(":")
    sock = udp_socket((host or "0.0.0.0", int(port)))
    punch = [parse_endpoint(peer) for peer in args.peer]
    tun = Tun(args.tun)
    net = NetConfig()
    server = Server(tun, sock, psk, network, args.mtu, Obfuscator(psk) if args.obfs else None, args.fec, punch)
    try:
        net.interface_up(tun.name, f"{server.server_ip}/{network.prefixlen}", args.mtu)
        if args.nat:
            out = args.out_iface or default_interface()
            net.enable_forwarding()
            net.masquerade(str(network), tun.name, out)
            log.info("NAT: %s -> %s", network, out)
        log.info("server listening on udp %s, tunnel %s/%d on %s (fec %s, obfuscation %s)", args.listen,
                 server.server_ip, network.prefixlen, tun.name, args.fec, "on" if args.obfs else "off")
        for target in punch:
            log.info("punching NAT towards %s:%d", *target)
        server.run()
    finally:
        net.cleanup()
        tun.close()


def cmd_client(args: argparse.Namespace) -> None:
    from .client import Client
    from .tun import Tun

    psk = load_psk(args.psk_file)
    endpoint = parse_endpoint(args.server)
    sock = udp_socket(("0.0.0.0", args.local_port))
    tun = Tun(args.tun)
    net = NetConfig()
    client = Client(tun, sock, psk, endpoint, net, route_all=args.route_all, routes=args.route,
                    kill_switch=args.kill_switch, obfuscator=Obfuscator(psk) if args.obfs else None,
                    fec_mode=args.fec)
    try:
        client.run()
        client.close()
    finally:
        net.cleanup()
        tun.close()


def cmd_stun(args: argparse.Namespace) -> None:
    from . import stun

    results = stun.discover(args.port)
    endpoints = set()
    for server, result in results:
        if isinstance(result, tuple):
            endpoints.add(result)
            print(f"{server:28} sees you as {result[0]}:{result[1]}")
        else:
            print(f"{server:28} error: {result}")
    if not endpoints:
        sys.exit("no STUN server answered (is outbound UDP blocked?)")
    if len(endpoints) == 1:
        ip, port = endpoints.pop()
        same = "kept" if port == args.port else f"changed to {port}"
        print(f"\nPublic endpoint: {ip}:{port}  (local port {args.port} {same})")
        print("NAT mapping is endpoint-independent: hole punching should work.")
    else:
        print("\nNAT gives a different port per destination (symmetric NAT): hole punching will not work.")
        print("Use the same LAN, a port forward on the router, or a relay server instead.")


def cmd_status(args: argparse.Namespace) -> None:
    from .loop import STATUS_DIR, read_status

    paths = sorted(glob.glob(os.path.join(STATUS_DIR, "*.sock")))
    if not paths:
        sys.exit(f"no running uvpn found in {STATUS_DIR} (run as root)")
    for path in paths:
        info = read_status(path)
        if args.json:
            print(json.dumps(info, indent=2))
            continue
        print(f"{info['role']} on {info['tun']}  up {info['uptime_s']:.0f} s  fec={info['fec']}  "
              f"obfuscation={'on' if info['obfuscation'] else 'off'}  tunnel={info.get('tunnel')}")
        st = info["stats"]
        print(f"  packets tx {st.get('tx_packets', 0)} rx {st.get('rx_packets', 0)}  "
              f"handshakes {st.get('handshakes', 0)}  fec recovered {st.get('fec_recovered', 0)}")
        drops = {k: v for k, v in st.items() if k.startswith("drop_")}
        if drops:
            print("  drops " + ", ".join(f"{k[5:]} {v}" for k, v in sorted(drops.items())))
        for s in info.get("sessions", []):
            where = s.get("endpoint") or info.get("server")
            print(f"  session {s['id']}  {s.get('tunnel_ip', '')} {where}  age {s['age_s']:.0f} s  "
                  f"loss in {s['rx_loss']:.1%} out {s['tx_loss']:.1%}  fec k={s['fec_k']} "
                  f"parity {s['parity_tx']} recovered {s['recovered']}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="uvpn", description="Secure Userspace VPN")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every dropped packet")
    sub = ap.add_subparsers(dest="command", required=True)

    sub.add_parser("genpsk", help="print a new random pre-shared key").set_defaults(func=cmd_genpsk)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--psk-file", required=True)
        sp.add_argument("--tun", default="uvpn0")
        sp.add_argument("--fec", type=fec_mode, default="off",
                        help="forward error correction: off, adaptive, or fixed block size 1-8 (default off)")
        sp.add_argument("--obfs", action="store_true", help="hide headers and pad packets (both sides must match)")

    s = sub.add_parser("server", help="run the VPN server, or the listening side of a peer-to-peer tunnel")
    common(s)
    s.add_argument("--listen", default="0.0.0.0:51820", help="UDP address:port (default %(default)s)")
    s.add_argument("--subnet", default="10.8.0.0/24", help="tunnel subnet (default %(default)s)")
    s.add_argument("--mtu", type=int, default=1400)
    s.add_argument("--nat", action="store_true", help="enable IP forwarding + MASQUERADE to the Internet")
    s.add_argument("--out-iface", help="NAT egress interface (default: the default-route interface)")
    s.add_argument("--peer", action="append", default=[], metavar="IP:PORT",
                   help="punch a NAT hole towards this peer's public endpoint (repeatable)")
    s.set_defaults(func=cmd_server)

    c = sub.add_parser("client", help="run the VPN client, or the connecting side of a peer-to-peer tunnel")
    common(c)
    c.add_argument("--server", required=True, help="server host[:port]")
    c.add_argument("--local-port", type=int, default=0, help="fixed local UDP port (needed for hole punching)")
    c.add_argument("--route-all", action="store_true", help="send all IPv4 traffic through the tunnel")
    c.add_argument("--route", action="append", default=[], metavar="CIDR", help="extra network to route into the tunnel")
    c.add_argument("--kill-switch", action="store_true", help="block all non-tunnel traffic and all IPv6")
    c.set_defaults(func=cmd_client)

    st = sub.add_parser("stun", help="show this computer's public UDP endpoint and NAT type")
    st.add_argument("--port", type=int, default=51820, help="local UDP port to test (default %(default)s)")
    st.set_defaults(func=cmd_stun)

    ss = sub.add_parser("status", help="show running tunnels, sessions, loss and FEC counters")
    ss.add_argument("--json", action="store_true")
    ss.set_defaults(func=cmd_status)

    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    args.func(args)


if __name__ == "__main__":
    main()
