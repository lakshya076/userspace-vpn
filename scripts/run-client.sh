#!/usr/bin/env bash
# run-client.sh - Automated launcher for UVPN Client on WSL/Linux
set -euo pipefail

# Ensure working directory is the repository root
cd "$(dirname "$0")/.."

# 1. Require root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[-] This script requires root privileges. Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

echo "=========================================================="
echo "               UVPN CLIENT SETUP (WSL / Linux)           "
echo "=========================================================="

# 2. Synchronize clock (vital for WSL handshake timestamp verification)
if command -v hwclock >/dev/null 2>&1; then
    hwclock -s 2>/dev/null || true
    echo "[+] Clock synchronized with host hardware clock."
fi

# 3. Detect Python environment
PY="python3"
if [ -f ".venv/bin/python" ]; then
    PY=".venv/bin/python"
fi

if ! $PY -c "import cryptography" 2>/dev/null; then
    echo "[!] 'cryptography' Python package not found."
    echo "[*] Attempting to install python3-cryptography via apt..."
    apt-get update && apt-get install -y python3-cryptography || {
        echo "[-] Failed to install cryptography package. Please run: pip install -r requirements.txt"
        exit 1
    }
fi

# 4. Check /dev/net/tun
if [ ! -c /dev/net/tun ]; then
    echo "[*] Creating /dev/net/tun device node..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 || true
    chmod 600 /dev/net/tun || true
fi

# 5. Parse Server Host / IP
SERVER_HOST=""
if [ $# -gt 0 ] && [[ "$1" != -* ]]; then
    SERVER_HOST="$1"
    shift
fi

if [ -z "$SERVER_HOST" ]; then
    read -rp "Enter UVPN Server IP (e.g. 192.168.1.50): " SERVER_HOST
    if [ -z "$SERVER_HOST" ]; then
        echo "[-] Server IP is required."
        exit 1
    fi
fi

# Append default port 51820 if omitted
if [[ "$SERVER_HOST" != *:* ]]; then
    SERVER_ENDPOINT="${SERVER_HOST}:51820"
else
    SERVER_ENDPOINT="$SERVER_HOST"
fi

# 6. Parse or Prompt for Pre-Shared Key (PSK)
PSK_FILE="psk.key"

if [ $# -gt 0 ] && [[ "$1" != -* ]]; then
    # Argument is either a file path or the raw base64 string
    if [ -f "$1" ]; then
        PSK_FILE="$1"
        chmod 600 "$PSK_FILE"
    else
        echo "$1" > "$PSK_FILE"
        chmod 600 "$PSK_FILE"
    fi
    shift
fi

if [ ! -f "$PSK_FILE" ]; then
    echo ""
    echo "[?] No psk.key found."
    read -rp "Paste the Pre-Shared Key from the server: " PSK_INPUT
    if [ -z "$PSK_INPUT" ]; then
        echo "[-] Pre-Shared Key is required to connect."
        exit 1
    fi
    echo "$PSK_INPUT" > "$PSK_FILE"
    chmod 600 "$PSK_FILE"
fi

echo ""
echo "=========================================================="
echo "                 UVPN CLIENT CONNECTING                   "
echo "=========================================================="
echo " Server Endpoint: $SERVER_ENDPOINT"
echo " PSK File       : $PSK_FILE"
echo " Extra Options  : ${*:-none (direct peer mode)}"
echo "=========================================================="
echo ""

echo "[*] Launching UVPN Client..."
exec $PY -m uvpn client --server "$SERVER_ENDPOINT" --psk-file "$PSK_FILE" "$@"
