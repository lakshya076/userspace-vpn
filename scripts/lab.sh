# Helpers for the network-namespace test labs. Source this file; run as root.
# shellcheck shell=bash

PY=${PY:-python3}
WORK=$(mktemp -d)
PIDS=()
LAB_NS=()

lab_cleanup() {
    set +e
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
    wait 2>/dev/null
    for ns in "${LAB_NS[@]:-}"; do ip netns del "$ns" 2>/dev/null; done
    rm -rf "$WORK"
}
trap lab_cleanup EXIT

ns_add() {
    ip netns del "$1" 2>/dev/null || true
    ip netns add "$1"
    ip -n "$1" link set lo up
    LAB_NS+=("$1")
}

# veth NS1 IF1 ADDR1 NS2 IF2 ADDR2: connect two namespaces with addressed veth ends
veth() {
    ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
    ip -n "$1" addr add "$3" dev "$2"
    ip -n "$4" addr add "$6" dev "$5"
    ip -n "$1" link set "$2" up
    ip -n "$4" link set "$5" up
}

# uvpn NAME NS ARGS...: start uvpn in a namespace, log to $WORK/NAME.log, pid in PID_NAME
uvpn() {
    local name=$1 ns=$2
    shift 2
    ip netns exec "$ns" $PY -m uvpn "$@" >"$WORK/$name.log" 2>&1 &
    PIDS+=($!)
    printf -v "PID_$name" %s $!
}

stop() {  # stop NAME: SIGTERM, so it cleans up its routes and rules
    local var="PID_$1"
    kill "${!var}" 2>/dev/null
    wait "${!var}" 2>/dev/null || true
}

wait_log() {  # wait_log NAME PATTERN [SECONDS]
    local i
    for ((i = 0; i < ${3:-10} * 4; i++)); do
        grep -q "$2" "$WORK/$1.log" 2>/dev/null && return 0
        sleep 0.25
    done
    return 1
}

fail() {
    echo "FAIL: $*"
    for log in "$WORK"/*.log; do echo "--- $(basename "$log")"; tail -20 "$log"; done
    exit 1
}

ok() { echo "ok   $*"; }

# Client <-> server <-> "Internet":
#   [uvpn-cli] 10.0.1.2 ---- 10.0.1.1 [uvpn-srv] 198.51.100.1 ---- 198.51.100.2 [uvpn-net]
lab_basic() {
    ns_add uvpn-cli; ns_add uvpn-srv; ns_add uvpn-net
    veth uvpn-cli cli-eth 10.0.1.2/24 uvpn-srv srv-lan 10.0.1.1/24
    veth uvpn-srv srv-wan 198.51.100.1/24 uvpn-net net-eth 198.51.100.2/24
    ip -n uvpn-cli route add default via 10.0.1.1
    ip -n uvpn-srv route add default via 198.51.100.2
    $PY -m uvpn genpsk >"$WORK/psk" && chmod 600 "$WORK/psk"
}

# Random loss on the tunnel's UDP packets in both directions (WSL kernels lack netem).
set_loss() {  # set_loss PERCENT (0 removes it)
    local ns spec prob
    for ns in uvpn-cli uvpn-srv; do ip netns exec "$ns" iptables -F OUTPUT; done
    [ "$1" = 0 ] && return
    prob=$(awk "BEGIN { print $1 / 100 }")
    for spec in "uvpn-cli --dport" "uvpn-srv --sport"; do
        set -- $spec
        ip netns exec "$1" iptables -A OUTPUT -p udp "$2" 51820 -m statistic --mode random --probability "$prob" -j DROP
    done
}
