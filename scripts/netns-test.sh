#!/usr/bin/env bash
# End-to-end test on one Linux machine using network namespaces. Run as root.
#
#   [uvpn-cli] 10.0.1.2 ---- 10.0.1.1 [uvpn-srv] 198.51.100.1 ---- 198.51.100.2 [uvpn-net]
#    client                      server + NAT                       "the Internet"
#
# uvpn-net has no route back to 10.8.0.0/24 or 10.0.1.0/24, so reaching it from the
# client proves both the tunnel and the server's NAT work.
set -euo pipefail
cd "$(dirname "$0")/.."

PY=${PY:-python3}
WORK=$(mktemp -d)
MARKER="uvpn-plaintext-marker-$RANDOM$RANDOM"
fail() { echo "FAIL: $*"; echo "--- server log"; cat "$WORK/server.log"; echo "--- client log"; cat "$WORK/client.log"; exit 1; }

cleanup() {
    set +e
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
    wait 2>/dev/null
    for ns in uvpn-cli uvpn-srv uvpn-net; do ip netns del "$ns" 2>/dev/null; done
    rm -rf "$WORK"
}
PIDS=()
trap cleanup EXIT

for ns in uvpn-cli uvpn-srv uvpn-net; do ip netns del "$ns" 2>/dev/null || true; ip netns add "$ns"; done
ip link add cli-eth netns uvpn-cli type veth peer name srv-lan netns uvpn-srv
ip link add srv-wan netns uvpn-srv type veth peer name net-eth netns uvpn-net
ip -n uvpn-cli addr add 10.0.1.2/24 dev cli-eth
ip -n uvpn-srv addr add 10.0.1.1/24 dev srv-lan
ip -n uvpn-srv addr add 198.51.100.1/24 dev srv-wan
ip -n uvpn-net addr add 198.51.100.2/24 dev net-eth
for pair in uvpn-cli:cli-eth uvpn-srv:srv-lan uvpn-srv:srv-wan uvpn-net:net-eth; do
    ip -n "${pair%%:*}" link set "${pair##*:}" up
done
for ns in uvpn-cli uvpn-srv uvpn-net; do ip -n "$ns" link set lo up; done
ip -n uvpn-cli route add default via 10.0.1.1
ip -n uvpn-srv route add default via 198.51.100.2

$PY -m uvpn genpsk > "$WORK/psk" && chmod 600 "$WORK/psk"

ip netns exec uvpn-srv $PY -m uvpn server --psk-file "$WORK/psk" --nat --out-iface srv-wan >"$WORK/server.log" 2>&1 &
PIDS+=($!)
sleep 1
ip netns exec uvpn-srv tcpdump -i srv-lan -w "$WORK/lan.pcap" -U udp port 51820 >/dev/null 2>&1 &
PIDS+=($!)
ip netns exec uvpn-cli $PY -m uvpn client --server 10.0.1.1:51820 --psk-file "$WORK/psk" --route-all >"$WORK/client.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 20); do grep -q "tunnel up" "$WORK/client.log" && break; sleep 0.5; done
grep -q "tunnel up" "$WORK/client.log" || fail "client did not complete the handshake"
echo "ok   handshake"

ip netns exec uvpn-cli ping -c 3 -W 2 10.8.0.1 >/dev/null || fail "ping to server tunnel IP"
echo "ok   ping server tunnel IP 10.8.0.1"

ip netns exec uvpn-cli ping -c 3 -W 2 198.51.100.2 >/dev/null || fail "ping through NAT"
echo "ok   ping 'Internet' host through tunnel + NAT"

mkdir -p "$WORK/www" && echo "$MARKER" > "$WORK/www/index.html"
ip netns exec uvpn-net $PY -m http.server 8080 --bind 198.51.100.2 --directory "$WORK/www" >/dev/null 2>&1 &
PIDS+=($!)
sleep 1
body=$(ip netns exec uvpn-cli curl -s --max-time 5 http://198.51.100.2:8080/) || fail "HTTP through tunnel"
[ "$body" = "$MARKER" ] || fail "HTTP body mismatch"
echo "ok   HTTP (TCP) through tunnel"

sleep 1
if grep -qa "$MARKER" "$WORK/lan.pcap"; then fail "plaintext visible on the underlay"; fi
[ -s "$WORK/lan.pcap" ] || fail "no tunnel packets captured"
echo "ok   underlay capture holds no plaintext"

echo "PASS"
