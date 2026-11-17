# Shared helpers for the demo launchers (client-server.sh, p2p.sh, monitor.sh).
# Source this file; do not run it.

SELF=$(readlink -f "$0")
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.."

PSK_FILE=psk.key
PORT=51820
PY=python3
[ -x .venv/bin/python ] && PY=.venv/bin/python

if [ -t 1 ]; then
    BOLD=$'\e[1m' GREEN=$'\e[92m' YELLOW=$'\e[93m' CYAN=$'\e[96m' RED=$'\e[91m' RESET=$'\e[0m'
else
    BOLD="" GREEN="" YELLOW="" CYAN="" RED="" RESET=""
fi

ok()    { echo "${GREEN}[+]${RESET} $*"; }
info()  { echo "${CYAN}[i]${RESET} $*"; }
warn()  { echo "${YELLOW}[!]${RESET} $*"; }
die()   { echo "${RED}[-]${RESET} $*" >&2; exit 1; }
title() { echo; echo "${BOLD}${CYAN}=== $* ===${RESET}"; }

# Re-run the calling script as root with the same arguments.
need_root() {
    [ "$(id -u)" -eq 0 ] || exec sudo bash "$SELF" "$@"
}

# The checks every tunnel start needs: clock, Python package, TUN device.
prepare() {
    # The handshake rejects clocks more than 120 s apart, and the WSL clock drifts after sleep.
    # Only on WSL: on a normal Linux the hardware clock may hold local time, and NTP keeps time anyway.
    if grep -qi microsoft /proc/version 2>/dev/null; then
        if hwclock -s 2>/dev/null; then ok "WSL clock synced with Windows"; else warn "could not sync the clock (hwclock -s)"; fi
    fi
    if ! $PY -c "import cryptography" 2>/dev/null; then
        warn "Python package 'cryptography' is missing; installing python3-cryptography"
        apt-get update -qq && apt-get install -y -qq python3-cryptography || die "install failed: pip install -r requirements.txt"
    fi
    if [ ! -c /dev/net/tun ]; then
        mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun || die "no /dev/net/tun on this system"
    fi
}

# Load psk.key, creating it first when $1 is "create" (the listening side).
# Prints a fingerprint instead of the key, so the key never shows up on a projector.
key() {
    if [ ! -s "$PSK_FILE" ]; then
        [ "${1:-}" = create ] || die "no $PSK_FILE in $(pwd): copy it here from the other machine (same file on both)"
        (umask 077 && $PY -m uvpn genpsk > "$PSK_FILE")
        ok "made a new $PSK_FILE: copy it to the other machine privately (scp, USB or a private chat)"
    fi
    chmod 600 "$PSK_FILE"
    local fp
    fp=$($PY -c 'import hashlib, sys; from uvpn.__main__ import load_psk; print(hashlib.sha256(load_psk(sys.argv[1])).hexdigest()[:16])' "$PSK_FILE") || exit 1
    ok "key fingerprint ${BOLD}$fp${RESET} (must be the same on both machines)"
}

# The flags both sides must agree on (--fec, --obfs), picked out of the listening side's flags,
# so the printed command for the other side is complete and leaves out listener-only flags.
shared_flags() {
    local out=()
    while [ $# -gt 0 ]; do
        case $1 in
            --obfs|--fec=*) out+=("$1") ;;
            --fec) out+=("$1" "${2:-}"); if [ $# -gt 1 ]; then shift; fi ;;
        esac
        shift
    done
    echo "${out[*]}"
}

# This machine's address on the local network, for the other side to connect to.
lan_ip() {
    ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || echo "THIS_MACHINE_IP"
}
