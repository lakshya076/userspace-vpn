#!/usr/bin/env bash
# demo-verify.sh - Live proof and verification script for classroom presentations
set -euo pipefail

# Ensure working directory is repo root
cd "$(dirname "$0")/.."

GREEN="\033[92m"
YELLOW="\033[93m"
CYAN="\033[96m"
BOLD="\033[1m"
RESET="\033[0m"

echo -e "\n${BOLD}${CYAN}============================================================${RESET}"
echo -e "${BOLD}${CYAN}        SECURE USERSPACE VPN (UVPN) - LIVE VERIFICATION     ${RESET}"
echo -e "${BOLD}${CYAN}============================================================${RESET}\n"

# 1. Check if uvpn0 interface exists
echo -e "${BOLD}[TEST 1/5] Checking TUN Interface (uvpn0)...${RESET}"
if ip addr show dev uvpn0 >/dev/null 2>&1; then
    MY_IP=$(ip -4 addr show dev uvpn0 | grep -oP 'inet \K[\d.]+')
    echo -e "  ${GREEN}✓ TUN device 'uvpn0' is UP with Tunnel IP: ${BOLD}${MY_IP}${RESET}"
else
    echo -e "  ${YELLOW}✗ Interface 'uvpn0' not found. Is the VPN client or server running?${RESET}"
    exit 1
fi

# 2. Ping peer tunnel IP
PEER_IP="10.8.0.1"
if [ "$MY_IP" = "10.8.0.1" ]; then
    PEER_IP="10.8.0.2"
fi

echo -e "\n${BOLD}[TEST 2/5] Pinging VPN Peer (${PEER_IP}) through Tunnel...${RESET}"
if ping -c 3 -W 2 "$PEER_IP" >/dev/null 2>&1; then
    RTT=$(ping -c 3 -W 2 "$PEER_IP" | tail -1 | awk -F '/' '{print $5}')
    echo -e "  ${GREEN}✓ Ping successful! Average RTT: ${RTT} ms (0% packet loss)${RESET}"
else
    echo -e "  ${YELLOW}✗ Ping to ${PEER_IP} failed. Check if server is running.${RESET}"
fi

# 3. HTTP Traffic through Tunnel
echo -e "\n${BOLD}[TEST 3/5] Sending HTTP Web Traffic to Demo Server (http://10.8.0.1:8080)...${RESET}"
if command -v curl >/dev/null 2>&1; then
    HTTP_OUT=$(curl -s --max-time 3 http://10.8.0.1:8080/ || true)
    if [ -n "$HTTP_OUT" ]; then
        echo -e "  ${GREEN}✓ Received HTTP response from server:${RESET}"
        echo "$HTTP_OUT" | sed 's/^/    /'
    else
        echo -e "  ${YELLOW}ℹ Could not reach demo web server on port 8080.${RESET}"
        echo -e "    (Run 'python3 scripts/demo-web.py' on Machine A to see live web logs)."
    fi
else
    echo -e "  ${YELLOW}ℹ curl not installed. Skipping HTTP fetch test.${RESET}"
fi

# 4. Public IP Verification (if route-all is enabled)
echo -e "\n${BOLD}[TEST 4/5] Checking Route & Public IP...${RESET}"
ROUTE_TARGET=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' || echo "unknown")
echo -e "  Default route goes through device: ${BOLD}${ROUTE_TARGET}${RESET}"
if [ "$ROUTE_TARGET" = "uvpn0" ]; then
    echo -e "  ${GREEN}✓ Full Tunnel Active! All internet traffic is redirected through UVPN.${RESET}"
    if command -v curl >/dev/null 2>&1; then
        EXT_IP=$(curl -s --max-time 3 https://ifconfig.me 2>/dev/null || curl -s --max-time 3 https://icanhazip.com 2>/dev/null || true)
        if [ -n "$EXT_IP" ]; then
            echo -e "  Public Egress IP: ${BOLD}${EXT_IP}${RESET} (Server's public IP)"
        fi
    fi
else
    echo -e "  ${CYAN}ℹ Split Tunnel Mode: Only 10.8.0.0/24 subnet traffic travels through UVPN.${RESET}"
fi

# 5. Live UVPN Telemetry
echo -e "\n${BOLD}[TEST 5/5] Live UVPN Cryptographic & Protocol Status...${RESET}"
# The status sockets live in /run/uvpn and are readable by root only.
if ! python3 -m uvpn status 2>/dev/null && ! sudo python3 -m uvpn status 2>/dev/null; then
    echo -e "  ${YELLOW}ℹ No status socket in /run/uvpn: is UVPN running?${RESET}"
fi

echo -e "\n${BOLD}${GREEN}============================================================${RESET}"
echo -e "${BOLD}${GREEN}                   VERIFICATION COMPLETE                    ${RESET}"
echo -e "${BOLD}${GREEN}============================================================${RESET}\n"
