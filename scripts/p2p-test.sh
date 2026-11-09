#!/usr/bin/env bash
# Peer-to-peer tunnel between two computers that are each behind their own NAT router,
# with no server in the middle. Run as root.
#
#   [uvpn-a] 10.1.0.2 -- [uvpn-nat-a] 203.0.113.1 -- [uvpn-inet] -- 198.51.100.1 [uvpn-nat-b] -- 10.2.0.2 [uvpn-b]
#
# Each NAT router only lets in replies to traffic sent from inside (like a home router),
# so B's handshake reply cannot reach A, nor A's handshake reach B, until B punches a hole.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lab.sh

for ns in uvpn-a uvpn-nat-a uvpn-inet uvpn-nat-b uvpn-b; do ns_add "$ns"; done
veth uvpn-a a-eth 10.1.0.2/24 uvpn-nat-a nata-lan 10.1.0.1/24
veth uvpn-nat-a nata-wan 203.0.113.1/24 uvpn-inet inet-a 203.0.113.254/24
veth uvpn-nat-b natb-wan 198.51.100.1/24 uvpn-inet inet-b 198.51.100.254/24
veth uvpn-b b-eth 10.2.0.2/24 uvpn-nat-b natb-lan 10.2.0.1/24
ip -n uvpn-a route add default via 10.1.0.1
ip -n uvpn-b route add default via 10.2.0.1
ip -n uvpn-nat-a route add default via 203.0.113.254
ip -n uvpn-nat-b route add default via 198.51.100.254
for ns in uvpn-nat-a uvpn-inet uvpn-nat-b; do ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1; done
ip netns exec uvpn-nat-a iptables -t nat -A POSTROUTING -o nata-wan -j MASQUERADE
ip netns exec uvpn-nat-b iptables -t nat -A POSTROUTING -o natb-wan -j MASQUERADE
# Like a home router's firewall: drop unsolicited packets from the WAN. A dropped packet
# leaves no conntrack entry behind, so it cannot make the NAT pick a different port later.
for pair in uvpn-nat-a:nata-wan uvpn-nat-b:natb-wan; do
    ip netns exec "${pair%%:*}" iptables -A INPUT -i "${pair##*:}" -m conntrack --ctstate NEW -j DROP
    ip netns exec "${pair%%:*}" iptables -A FORWARD -i "${pair##*:}" -m conntrack --ctstate NEW -j DROP
done
$PY -m uvpn genpsk >"$WORK/psk" && chmod 600 "$WORK/psk"

echo "== without hole punching"
# Other ports than the second test, so its NAT state cannot help or hurt the second one.
uvpn b uvpn-b server --psk-file "$WORK/psk" --listen 0.0.0.0:51830
uvpn a uvpn-a client --server 198.51.100.1:51830 --local-port 51831 --psk-file "$WORK/psk"
wait_log a "tunnel up" 7 && fail "handshake crossed both NATs without punching (NAT too permissive?)"
ok "B's NAT drops A's handshake: no tunnel"
stop a; stop b

echo "== with hole punching"
# B learns A's public endpoint out of band (in real life: uvpn stun + a chat message).
uvpn b uvpn-b server --psk-file "$WORK/psk" --peer 203.0.113.1:51821
wait_log b "punching" || fail "B did not start"
sleep 1.5  # let B's punch open its NAT before A's first handshake arrives
uvpn a uvpn-a client --server 198.51.100.1:51820 --local-port 51821 --psk-file "$WORK/psk"
wait_log a "tunnel up" 12 || fail "no tunnel through both NATs"
ok "handshake crossed both NATs"
ip netns exec uvpn-a ping -c 3 -W 2 10.8.0.1 >/dev/null || fail "A cannot reach B"
ip netns exec uvpn-b ping -c 3 -W 2 10.8.0.2 >/dev/null || fail "B cannot reach A"
ok "A (10.8.0.2) and B (10.8.0.1) reach each other directly"

echo "PASS"
