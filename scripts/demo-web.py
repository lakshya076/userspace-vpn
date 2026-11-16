#!/usr/bin/env python3
"""demo-web.py - Live visual web traffic monitor for UVPN classroom demos.

Run this on Machine A (Server) in a separate terminal:
    python3 scripts/demo-web.py
"""
import sys
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 8080
HOST = "0.0.0.0"

GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override default noisy logger with our own styled logging
        pass

    def do_GET(self):
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        now = datetime.now().strftime("%H:%M:%S")

        is_tunnel = client_ip.startswith("10.8.0.")
        origin_badge = f"{GREEN}[TUNNEL TRAFFIC: uvpn0]{RESET}" if is_tunnel else f"{YELLOW}[NON-TUNNEL TRAFFIC]{RESET}"

        print(f"\n{BOLD}{CYAN}------------------------------------------------------------{RESET}")
        print(f"{BOLD}[{now}] NEW INCOMING HTTP REQUEST {RESET}{origin_badge}")
        print(f"  • Source IP    : {BOLD}{client_ip}:{client_port}{RESET}")
        print(f"  • HTTP Method  : {BOLD}{self.command} {self.path}{RESET}")
        print(f"  • User-Agent   : {self.headers.get('User-Agent', 'Unknown')}")
        print(f"  • Verification : {'SUCCESS: Traffic routed through UVPN Tunnel!' if is_tunnel else 'Direct local connection'}")
        print(f"{BOLD}{CYAN}------------------------------------------------------------{RESET}\n")

        # HTML response for browser and formatted text for curl
        user_agent = self.headers.get("User-Agent", "").lower()
        if "curl" in user_agent or "wget" in user_agent:
            body = (
                f"\n=======================================================\n"
                f"   SECURE USERSPACE VPN (UVPN) - LIVE TRAFFIC VERIFIED \n"
                f"=======================================================\n"
                f" Server Time   : {now}\n"
                f" Your IP       : {client_ip}\n"
                f" Route Status  : {'[VERIFIED] Routed through UVPN Tunnel (10.8.0.x)' if is_tunnel else '[UNVERIFIED] Non-tunnel IP'}\n"
                f" Encryption    : ChaCha20-Poly1305 (AEAD)\n"
                f" Forwarding    : Linux TUN -> UDP 51820 -> Decrypt -> TUN\n"
                f"=======================================================\n\n"
            ).encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        else:
            body = f"""<!DOCTYPE html>
<html>
<head>
  <title>UVPN Demo Dashboard</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }}
    .card {{ background: #1e293b; border-radius: 12px; padding: 32px; max-width: 640px; margin: auto; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }}
    h1 {{ color: #38bdf8; margin-top: 0; font-size: 24px; }}
    .badge {{ display: inline-block; padding: 6px 14px; border-radius: 9999px; font-weight: bold; font-size: 14px; background: {'#059669' if is_tunnel else '#d97706'}; color: white; }}
    .field {{ margin: 16px 0; font-size: 15px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
    .label {{ color: #94a3b8; width: 140px; display: inline-block; font-weight: 500; }}
    .value {{ color: #f1f5f9; font-weight: 600; }}
    .tech {{ margin-top: 24px; font-size: 13px; color: #64748b; line-height: 1.6; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Secure Userspace VPN (UVPN)</h1>
    <div style="margin-bottom: 20px;">
      <span class="badge">{'✓ TUNNEL VERIFIED (10.8.0.x)' if is_tunnel else '⚠ NON-TUNNEL CONNECTION'}</span>
    </div>
    <div class="field"><span class="label">Client IP:</span><span class="value">{client_ip}</span></div>
    <div class="field"><span class="label">Server Time:</span><span class="value">{now}</span></div>
    <div class="field"><span class="label">Tunnel Cipher:</span><span class="value">ChaCha20-Poly1305 (256-bit AEAD)</span></div>
    <div class="field"><span class="label">Key Exchange:</span><span class="value">Ephemeral X25519 (Forward Secrecy)</span></div>
    <div class="tech">
      Packets read from client TUN device <code>uvpn0</code>, authenticated & encrypted in userspace, transported over UDP port 51820, and decrypted here on the server.
    </div>
  </div>
</body>
</html>""".encode("utf-8")
            content_type = "text/html; charset=utf-8"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = HTTPServer((HOST, PORT), DemoHandler)
    print(f"\n{BOLD}{GREEN}============================================================{RESET}")
    print(f"{BOLD}{GREEN}      UVPN DEMO WEB SERVER LISTENING ON PORT {PORT}        {RESET}")
    print(f"{BOLD}{GREEN}============================================================{RESET}")
    print(f"Listening on: {CYAN}http://10.8.0.1:{PORT}{RESET} (via VPN Tunnel)")
    print(f"Waiting for client requests from 10.8.0.2...")
    print(f"Press {YELLOW}Ctrl+C{RESET} to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDemo web server stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
