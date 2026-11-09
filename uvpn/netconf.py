"""Interface, route and NAT setup through iproute2 / iptables, with undo on exit."""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

log = logging.getLogger("uvpn.net")


def run(*args: str) -> str:
    log.debug("$ %s", " ".join(args))
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


class NetConfig:
    """Applies system changes and remembers how to reverse each one."""

    def __init__(self) -> None:
        self._undo: list[tuple[str, ...]] = []
        self._restore_forward: str | None = None

    def interface_up(self, dev: str, address: str, mtu: int) -> None:
        run("ip", "addr", "add", address, "dev", dev)
        run("ip", "link", "set", "dev", dev, "mtu", str(mtu), "up")

    def set_address(self, dev: str, address: str) -> None:
        run("ip", "addr", "flush", "dev", dev)
        run("ip", "addr", "add", address, "dev", dev)

    def add_route(self, cidr: str, dev: str | None = None, via: str | None = None) -> None:
        cmd = ["ip", "route", "add", cidr] + (["via", via] if via else []) + (["dev", dev] if dev else [])
        run(*cmd)
        self._undo.append(("ip", "route", "del", cidr))

    def route_all_via(self, dev: str, server_ip: str) -> None:
        """Send all IPv4 traffic into the tunnel, except packets to the VPN server itself."""
        via, out_dev = route_to(server_ip)
        self.add_route(f"{server_ip}/32", dev=out_dev, via=via)
        # Two /1 routes beat the existing default route without deleting it.
        self.add_route("0.0.0.0/1", dev=dev)
        self.add_route("128.0.0.0/1", dev=dev)

    def enable_forwarding(self) -> None:
        path = Path("/proc/sys/net/ipv4/ip_forward")
        if path.read_text().strip() != "1":
            self._restore_forward = "0"
            path.write_text("1\n")

    def masquerade(self, subnet: str, tun_dev: str, out_dev: str) -> None:
        rules = [
            ("-t", "nat", "POSTROUTING", "-s", subnet, "-o", out_dev, "-j", "MASQUERADE"),
            ("-t", "filter", "FORWARD", "-i", tun_dev, "-j", "ACCEPT"),
            ("-t", "filter", "FORWARD", "-o", tun_dev, "-m", "conntrack",
             "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"),
        ]
        for table_flag, table, chain, *spec in rules:
            # Insert at the top so a DROP policy (e.g. Docker's FORWARD chain) does not win.
            run("iptables", table_flag, table, "-I", chain, "1", *spec)
            self._undo.append(("iptables", table_flag, table, "-D", chain, *spec))

    def cleanup(self) -> None:
        for cmd in reversed(self._undo):
            try:
                run(*cmd)
            except subprocess.CalledProcessError as exc:
                log.warning("cleanup failed: %s: %s", " ".join(cmd), exc.stderr.strip())
        self._undo.clear()
        if self._restore_forward is not None:
            Path("/proc/sys/net/ipv4/ip_forward").write_text(self._restore_forward + "\n")
            self._restore_forward = None


def route_to(ip: str) -> tuple[str | None, str]:
    """(gateway or None, device) the kernel currently uses to reach ip."""
    out = run("ip", "route", "get", ip)
    dev = re.search(r"\bdev (\S+)", out)
    if not dev:
        raise RuntimeError(f"no route to {ip}: {out.strip()}")
    via = re.search(r"\bvia (\S+)", out)
    return (via.group(1) if via else None), dev.group(1)


def default_interface() -> str:
    return route_to("1.1.1.1")[1]
