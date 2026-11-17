#!/usr/bin/env bash
# Setup 2, peer-to-peer: two equal computers get a private encrypted link,
# 10.8.0.1 <-> 10.8.0.2. No gateway: internet traffic does not use the tunnel.
#
#   peer A (listens):   sudo bash scripts/p2p.sh listen [uvpn flags]
#   peer B (connects):  sudo bash scripts/p2p.sh connect PEER_A_IP[:PORT] [uvpn flags]
#   either, first:      bash scripts/p2p.sh stun [PORT]   (public address and NAT type)
#
# Different networks (hole punching): A adds --peer B_PUBLIC_IP:51821, B adds --local-port 51821.
# Optional flags: --fec adaptive and --obfs (give the same ones to both sides).
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/common.sh"

usage() { sed -n '2,10p' "$SELF" | sed 's/^# \{0,1\}//'; exit 1; }

role=${1:-}
case $role in
listen)
    shift
    need_root listen "$@"
    prepare
    key create
    title "PEER-TO-PEER: peer A (listening)"
    info "this peer is 10.8.0.1, the other peer will be 10.8.0.2"
    info "on peer B run:  ${BOLD}sudo bash scripts/p2p.sh connect $(lan_ip) $(shared_flags "$@")${RESET}"
    info "watch it:       sudo bash scripts/monitor.sh stats | wire | tunnel"
    exec $PY -m uvpn server --psk-file "$PSK_FILE" "$@"
    ;;
connect)
    [ $# -ge 2 ] || usage
    peer=$2
    shift 2
    need_root connect "$peer" "$@"
    prepare
    key
    title "PEER-TO-PEER: peer B (connecting)"
    info "this peer gets 10.8.0.2 once 'tunnel up' appears; peer A is 10.8.0.1"
    info "try:  ping 10.8.0.1"
    exec $PY -m uvpn client --psk-file "$PSK_FILE" --server "$peer" "$@"
    ;;
stun)
    exec $PY -m uvpn stun --port "${2:-$PORT}"
    ;;
*)
    usage
    ;;
esac
