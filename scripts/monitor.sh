#!/usr/bin/env bash
# Live views that show UVPN working. Run each in its own terminal, on either machine,
# while the tunnel is up (works for both client/server and peer-to-peer).
#
#   sudo bash scripts/monitor.sh stats          sessions, packets, loss and FEC, refreshed every second
#   sudo bash scripts/monitor.sh wire [PORT]    real network: UDP 51820, only encrypted bytes
#   sudo bash scripts/monitor.sh tunnel         inside the tunnel (uvpn0): readable IP traffic
#   sudo bash scripts/monitor.sh check          one-shot check: interface, ping, HTTP, routes, status
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/common.sh"

usage() { sed -n '2,8p' "$SELF" | sed 's/^# \{0,1\}//'; exit 1; }

need_tcpdump() {
    command -v tcpdump >/dev/null || { apt-get update -qq && apt-get install -y -qq tcpdump; }
}

need_root "$@"
case ${1:-} in
stats)
    # -d highlights the numbers that changed since the last refresh.
    exec watch -n 1 -d -t "$PY -m uvpn status"
    ;;
wire)
    need_tcpdump
    port=${2:-$PORT}
    title "Real network, UDP $port: this is all an eavesdropper sees (no readable text)"
    exec tcpdump -l -n -i any -X udp port "$port"
    ;;
tunnel)
    need_tcpdump
    ip link show uvpn0 >/dev/null 2>&1 || die "uvpn0 does not exist: start the tunnel first"
    title "Inside the tunnel (uvpn0): the same traffic before encryption"
    exec tcpdump -l -n -i uvpn0 -A
    ;;
check)
    exec bash scripts/demo-verify.sh
    ;;
*)
    usage
    ;;
esac
