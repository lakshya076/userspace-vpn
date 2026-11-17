#!/usr/bin/env bash
# Setup 1, client/server: a classic VPN. The client sends ALL its IPv4 internet traffic
# through the server, and the server forwards it to the internet with NAT.
#
#   server machine:  sudo bash scripts/client-server.sh server [uvpn flags]
#   client machine:  sudo bash scripts/client-server.sh client SERVER_IP[:PORT] [uvpn flags]
#
# Optional flags: --fec adaptive and --obfs (give the same ones to both sides),
# --kill-switch (client only: nothing can leave outside the tunnel).
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/common.sh"

usage() { sed -n '2,9p' "$SELF" | sed 's/^# \{0,1\}//'; exit 1; }

role=${1:-}
case $role in
server)
    shift
    need_root server "$@"
    prepare
    key create
    title "CLIENT/SERVER: server (VPN gateway)"
    info "tunnel address 10.8.0.1, client traffic leaves to the internet through this machine (NAT)"
    info "on the client run:  ${BOLD}sudo bash scripts/client-server.sh client $(lan_ip) $(shared_flags "$@")${RESET}"
    info "watch it:           sudo bash scripts/monitor.sh stats | wire | tunnel"
    exec $PY -m uvpn server --psk-file "$PSK_FILE" --nat "$@"
    ;;
client)
    [ $# -ge 2 ] || usage
    server=$2
    shift 2
    need_root client "$server" "$@"
    prepare
    key
    title "CLIENT/SERVER: client"
    info "all IPv4 internet traffic goes through the tunnel to $server (--route-all)"
    info "prove it:  ip route get 1.1.1.1   (shows dev uvpn0)"
    info "           ping 10.8.0.1          (the server inside the tunnel)"
    exec $PY -m uvpn client --psk-file "$PSK_FILE" --server "$server" --route-all "$@"
    ;;
*)
    usage
    ;;
esac
