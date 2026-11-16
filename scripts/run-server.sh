#!/usr/bin/env bash
# run-server.sh - Automated launcher for UVPN Server on WSL/Linux
set -euo pipefail

# Ensure working directory is the repository root
cd "$(dirname "$0")/.."

# 1. Require root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[-] This script requires root privileges. Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

echo "=========================================================="
echo "               UVPN SERVER SETUP (WSL / Linux)           "
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

# 5. Pre-Shared Key (psk.key)
PSK_FILE="psk.key"
if [ ! -f "$PSK_FILE" ]; then
    echo "[*] Generating new Pre-Shared Key ($PSK_FILE)..."
    $PY -m uvpn genpsk > "$PSK_FILE"
    chmod 600 "$PSK_FILE"
    echo "[+] Generated $PSK_FILE successfully."
else
    chmod 600 "$PSK_FILE"
    echo "[+] Using existing $PSK_FILE."
fi

PSK_VALUE=$(cat "$PSK_FILE")

# 6. Detect Server IP Address
SERVER_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || hostname -I 2>/dev/null | awk '{print $1}' || echo "YOUR_SERVER_IP")

echo ""
echo "=========================================================="
echo "                 UVPN SERVER IS READY                     "
echo "=========================================================="
echo " Server LAN IP : ${SERVER_IP}"
echo " Listening Port: 51820 (UDP)"
echo " PSK Key       : ${PSK_VALUE}"
echo "----------------------------------------------------------"
echo " To connect from Machine B (Client WSL), run:"
echo ""
echo "   sudo bash scripts/run-client.sh ${SERVER_IP} '${PSK_VALUE}'"
echo ""
echo " Note: Pass any extra flags to this script if needed:"
echo "   --nat            (Enable Internet forwarding & masquerading)"
echo "   --fec adaptive   (Enable Forward Error Correction)"
echo "   --obfs           (Mask packet headers & pad sizes)"
echo "=========================================================="
echo ""

echo "[*] Launching UVPN Server..."
exec $PY -m uvpn server --psk-file "$PSK_FILE" "$@"
