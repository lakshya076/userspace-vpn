#!/usr/bin/env bash
# End-to-end tests on one Linux machine using network namespaces. Run as root.
#
#   [uvpn-cli] 10.0.1.2 ---- 10.0.1.1 [uvpn-srv] 198.51.100.1 ---- 198.51.100.2 [uvpn-net]
#    client                      server + NAT                       "the Internet"
#
# uvpn-net has no route back to 10.8.0.0/24 or 10.0.1.0/24, so reaching it from the
# client proves both the tunnel and the server's NAT work.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lab.sh

MARKER="uvpn-plaintext-marker-$RANDOM$RANDOM"
CLIENT=(client --server 10.0.1.1:51820 --psk-file "$WORK/psk")
SERVER=(server --psk-file "$WORK/psk" --nat --out-iface srv-wan)

# Distinct first two bytes (version, type) of captured UDP payloads.
header_variety() {
    $PY - "$1" <<'EOF'
import struct, sys
data = open(sys.argv[1], "rb").read()
pos, seen = 24, set()
while pos + 16 <= len(data):
    caplen = struct.unpack_from("<I", data, pos + 8)[0]
    frame = data[pos + 16:pos + 16 + caplen]
    seen.add(frame[14 + 20 + 8:14 + 20 + 8 + 2])  # Ethernet + IPv4 + UDP headers
    pos += 16 + caplen
print(len(seen))
EOF
}

lab_basic
mkdir -p "$WORK/www" && echo "$MARKER" >"$WORK/www/index.html"
ip netns exec uvpn-net $PY -m http.server 8080 --bind 198.51.100.2 --directory "$WORK/www" >/dev/null 2>&1 &
PIDS+=($!)

echo "== basic tunnel"
uvpn server uvpn-srv "${SERVER[@]}"
wait_log server "listening" || fail "server did not start"
ip netns exec uvpn-srv tcpdump -i srv-lan -w "$WORK/plain.pcap" -U udp port 51820 >/dev/null 2>&1 &
TCPDUMP=$!
uvpn client uvpn-cli "${CLIENT[@]}" --route-all
wait_log client "tunnel up" || fail "client did not complete the handshake"
ok "handshake"
ip netns exec uvpn-cli ping -c 3 -W 2 10.8.0.1 >/dev/null || fail "ping to server tunnel IP"
ok "ping server tunnel IP 10.8.0.1"
ip netns exec uvpn-cli ping -c 3 -W 2 198.51.100.2 >/dev/null || fail "ping through NAT"
ok "ping 'Internet' host through tunnel + NAT"
body=$(ip netns exec uvpn-cli curl -s --max-time 5 http://198.51.100.2:8080/) || fail "HTTP through tunnel"
[ "$body" = "$MARKER" ] || fail "HTTP body mismatch"
ok "HTTP (TCP) through tunnel"
sleep 1
kill "$TCPDUMP"; wait "$TCPDUMP" 2>/dev/null || true
grep -qa "$MARKER" "$WORK/plain.pcap" && fail "plaintext visible on the underlay"
ok "underlay capture holds no plaintext"

ip netns exec uvpn-srv $PY -m uvpn status >"$WORK/status.txt" || fail "status command"
grep -q "session .* 10.8.0.2" "$WORK/status.txt" || fail "status shows no session: $(cat "$WORK/status.txt")"
ok "status command lists the session"

echo "== roaming with path validation"
ip -n uvpn-cli addr add 10.0.1.3/24 dev cli-eth
ip -n uvpn-cli route replace 10.0.1.1 dev cli-eth src 10.0.1.3
ip netns exec uvpn-cli ping -c 5 -i 0.3 -W 2 10.8.0.1 >/dev/null || fail "ping after address change"
wait_log server "path validated" 5 || fail "server did not validate the new path"
grep -q "PATH_CHALLENGE\|path_challenges" <(ip netns exec uvpn-srv $PY -m uvpn status --json) || fail "no challenge counted"
ip netns exec uvpn-srv $PY -m uvpn status | grep -q "10.0.1.3:" || fail "server still sends to the old address"
ok "server moved to 10.0.1.3 after a PATH_CHALLENGE / PATH_RESPONSE"
ip -n uvpn-cli route replace 10.0.1.1 dev cli-eth
stop client

echo "== kill switch"
uvpn client uvpn-cli "${CLIENT[@]}" --route-all --kill-switch
wait_log client "tunnel up" || fail "kill-switch client handshake"
ip netns exec uvpn-cli ping -c 2 -W 2 198.51.100.2 >/dev/null || fail "tunnel traffic blocked by kill switch"
ok "tunnel traffic allowed"
stop server
ip netns exec uvpn-cli ping -c 2 -W 1 10.0.1.1 >/dev/null 2>&1 && fail "non-tunnel traffic leaked"
ok "server gone: direct traffic is blocked, nothing leaks"
ip netns exec uvpn-cli ip6tables -S OUTPUT | grep -q UVPN-KILLSWITCH || fail "no IPv6 block"
ok "IPv6 blocked"
stop client
ip netns exec uvpn-cli iptables -S | grep -q UVPN-KILLSWITCH && fail "kill switch not removed on exit"
ip netns exec uvpn-cli ping -c 2 -W 2 10.0.1.1 >/dev/null || fail "connectivity not restored"
ok "rules removed on clean exit"

echo "== obfuscation + FEC"
uvpn server uvpn-srv "${SERVER[@]}" --obfs --fec adaptive
wait_log server "listening" || fail "obfs server start"
ip netns exec uvpn-srv tcpdump -i srv-lan -w "$WORK/obfs.pcap" -U udp port 51820 >/dev/null 2>&1 &
TCPDUMP=$!
uvpn client uvpn-cli "${CLIENT[@]}" --route-all --obfs --fec adaptive
wait_log client "tunnel up" || fail "obfuscated handshake"
body=$(ip netns exec uvpn-cli curl -s --max-time 5 http://198.51.100.2:8080/) || fail "HTTP with obfuscation"
[ "$body" = "$MARKER" ] || fail "HTTP body mismatch with obfuscation"
ip netns exec uvpn-cli ping -c 20 -i 0.05 -W 2 10.8.0.1 >/dev/null || fail "ping with obfuscation"
sleep 1
kill "$TCPDUMP"; wait "$TCPDUMP" 2>/dev/null || true
plain=$(header_variety "$WORK/plain.pcap")
masked=$(header_variety "$WORK/obfs.pcap")
[ "$plain" -le 4 ] || fail "expected few distinct cleartext headers, got $plain"
[ "$masked" -ge 20 ] || fail "obfuscated headers not random: $masked distinct"
ok "header bytes: $plain distinct values in clear, $masked when obfuscated"
uvpn plain_client uvpn-cli client --server 10.0.1.1:51820 --psk-file "$WORK/psk" --tun uvpn1
wait_log plain_client "tunnel up" 6 && fail "an unobfuscated client got through to an obfuscated server"
ok "unobfuscated client is ignored by an obfuscated server"

echo "PASS"
