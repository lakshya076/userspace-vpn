#!/usr/bin/env bash
# Measure what adaptive FEC buys on a lossy link. Run as root.
# Drops a random share of tunnel packets in each direction, then measures ping loss
# and the time to download 2 MB over HTTP through the tunnel, with FEC off and adaptive.
#
#   sudo bash scripts/fec-bench.sh            # default loss levels 0 5 10 20 %
#   sudo bash scripts/fec-bench.sh 2 15       # your own levels
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lab.sh

LEVELS=("${@:-0 5 10 20}")
LEVELS=(${LEVELS[*]})
lab_basic
mkdir -p "$WORK/www" && head -c 2000000 /dev/urandom >"$WORK/www/blob"
ip netns exec uvpn-net $PY -m http.server 8080 --bind 198.51.100.2 --directory "$WORK/www" >/dev/null 2>&1 &
PIDS+=($!)

printf "%-6s %-9s %-11s %-12s %s\n" "loss" "fec" "ping loss" "2 MB fetch" "parity sent / recovered (server)"
for loss in "${LEVELS[@]}"; do
    for mode in off adaptive; do
        set_loss 0
        uvpn server uvpn-srv server --psk-file "$WORK/psk" --nat --out-iface srv-wan --fec "$mode"
        wait_log server listening || fail "server start"
        uvpn client uvpn-cli client --server 10.0.1.1:51820 --psk-file "$WORK/psk" --route-all --fec "$mode"
        wait_log client "tunnel up" || fail "handshake"
        set_loss "$loss"
        ip netns exec uvpn-cli ping -c 100 -i 0.02 -q 10.8.0.1 >/dev/null 2>&1 || true  # lets FEC learn the loss
        sleep 1.5
        ping_loss=$(ip netns exec uvpn-cli ping -c 200 -i 0.02 -q -W 1 10.8.0.1 2>/dev/null | grep -o "[0-9.]*% packet loss" | cut -d% -f1)
        if fetch=$(ip netns exec uvpn-cli curl -s -o /dev/null --max-time 60 -w "%{time_total}" http://198.51.100.2:8080/blob); then
            fetch=$(printf "%.2fs" "$fetch")
        else
            fetch=">60s"
        fi
        counters=$(ip netns exec uvpn-srv $PY -m uvpn status | grep -o "parity [0-9]* recovered [0-9]*" | head -1)
        printf "%-6s %-9s %-11s %-12s %s\n" "$loss%" "$mode" "${ping_loss}%" "$fetch" "$counters"
        stop client; stop server
    done
done
