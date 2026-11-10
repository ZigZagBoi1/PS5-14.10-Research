"""
PS5 13.60 Jailbreak Host Server

Serves the 1-click jailbreak page and handles payload delivery.
Also includes a DNS responder that redirects the PS5 user guide
to this server, so opening "User's Guide" on PS5 lands here.

Usage:
    python server.py                    # HTTP on :80, DNS on :53
    python server.py --port 8080        # Custom HTTP port
    python server.py --no-dns           # HTTP only, no DNS
    python server.py --ps5-ip 10.0.0.96 # Override PS5 IP

Requirements: Python 3.7+ (stdlib only, no pip packages)
"""
import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "www"
ETAHEN_PATH = WEB_ROOT / "etahen" / "etaHEN.bin"
PAYLOADS_DIR = ROOT / "research_payloads"
RESULTS_DIR = ROOT / "research_results"

# PS5 user guide domains that we intercept
REDIRECT_DOMAINS = {
    b"manuals.playstation.net",
    b"www.playstation.com",
    b"store.playstation.com",
}

# Real DNS server to forward non-intercepted queries
UPSTREAM_DNS = "8.8.8.8"


class JailbreakHandler(SimpleHTTPRequestHandler):
    """Serves the jailbreak page and handles API calls."""

    def __init__(self, *args, ps5_ip="10.0.0.96", server_ip="10.0.0.80",
                 research_port=9100, **kwargs):
        self.ps5_ip = ps5_ip
        self.server_ip = server_ip
        self.research_port = research_port
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def log_message(self, format, *args):
        # Colorized logging
        msg = format % args
        if "200" in msg or "301" in msg:
            print(f"\033[32m[HTTP]\033[0m {self.client_address[0]} {msg}")
        elif "404" in msg or "500" in msg:
            print(f"\033[31m[HTTP]\033[0m {self.client_address[0]} {msg}")
        else:
            print(f"\033[36m[HTTP]\033[0m {self.client_address[0]} {msg}")

    def do_GET(self):
        path = urlparse(self.path).path

        # Root serves jailbreak page
        if path in ("/", "/index.html"):
            return super().do_GET()

        # Research tools page
        if path == "/research":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            research_page = ROOT / "research.html"
            if research_page.exists():
                self.wfile.write(research_page.read_bytes())
            else:
                self.wfile.write(b"<html><body><h1>Research tools coming soon</h1></body></html>")
            return

        # Status API
        if path == "/api/status":
            payloads = sorted(PAYLOADS_DIR.glob("*.lua")) if PAYLOADS_DIR.exists() else []
            self.send_json({
                "server": "jailbreak-host",
                "ps5_ip": self.ps5_ip,
                "etahen_available": ETAHEN_PATH.exists(),
                "etahen_size": ETAHEN_PATH.stat().st_size if ETAHEN_PATH.exists() else 0,
                "research_port": self.research_port,
                "research_payloads": [p.stem for p in payloads],
                "research_payload_count": len(payloads),
            })
            return

        # Research results listing
        if path == "/api/research/results":
            results = []
            if RESULTS_DIR.exists():
                for f in sorted(RESULTS_DIR.glob("*.txt"), reverse=True)[:50]:
                    results.append({
                        "name": f.stem,
                        "size": f.stat().st_size,
                        "time": f.stat().st_mtime,
                    })
            self.send_json({"results": results})
            return

        # Serve static files (Relapse, etaHEN, etc)
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if path == "/api/etahen/send":
            return self.handle_etahen_send(body)

        if path == "/api/research/connect":
            return self.handle_research_connect(body)

        if path == "/api/research/deploy":
            return self.handle_research_deploy(body)

        if path == "/api/research/run":
            return self.handle_research_run(body)

        self.send_error(404, "Not found")

    def handle_etahen_send(self, body):
        """Send etaHEN payload to the PS5 ELF loader."""
        try:
            if not ETAHEN_PATH.exists():
                self.send_json({"sent": False, "error": "etaHEN.bin not found. Run setup.ps1 first."}, 500)
                return

            payload = ETAHEN_PATH.read_bytes()
            print(f"\033[33m[etaHEN]\033[0m Sending {len(payload)} bytes to {self.ps5_ip}:9021")

            # etaHEN is sent to the ELF loader on port 9021
            # Format: 8-byte LE length prefix + payload
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            try:
                sock.connect((self.ps5_ip, 9021))
                sock.sendall(struct.pack("<Q", len(payload)))
                sock.sendall(payload)
                # Wait for ack
                try:
                    ack = sock.recv(8)
                    print(f"\033[32m[etaHEN]\033[0m Payload delivered, ack={ack.hex() if ack else 'none'}")
                except socket.timeout:
                    print(f"\033[33m[etaHEN]\033[0m Payload sent, no ack (this is normal)")
                self.send_json({"sent": True, "size": len(payload)})
            except ConnectionRefusedError:
                self.send_json({"sent": False, "error": "PS5 ELF loader not ready on port 9021. Run Relapse first."}, 503)
            except socket.timeout:
                self.send_json({"sent": False, "error": "Connection to PS5 timed out."}, 504)
            finally:
                sock.close()

        except Exception as e:
            self.send_json({"sent": False, "error": str(e)}, 500)

    def handle_research_connect(self, body):
        """Check if the research app is connected."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                sock.connect((self.ps5_ip, self.research_port))
                sock.close()
                self.send_json({"connected": True})
            except (ConnectionRefusedError, socket.timeout):
                self.send_json({"connected": False})
        except Exception as e:
            self.send_json({"connected": False, "error": str(e)})

    def handle_research_deploy(self, body):
        """Send all research payloads to the PS5 Lua loader sequentially.

        After etaHEN gives us kernel R/W, this sends each research
        payload one at a time, collecting results between runs.
        The PS5 spawns a fresh process per connection, so each
        payload runs independently.
        """
        try:
            if not PAYLOADS_DIR.exists():
                self.send_json({"deployed": False, "error": "No research_payloads directory"}, 500)
                return

            payloads = sorted(PAYLOADS_DIR.glob("*.lua"))
            if not payloads:
                self.send_json({"deployed": False, "error": "No .lua payloads found"}, 500)
                return

            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            results = []

            for payload_path in payloads:
                name = payload_path.stem
                lua_src = payload_path.read_text(encoding="utf-8")
                print(f"\033[33m[Research]\033[0m Deploying {name} ({len(lua_src)} bytes)")

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(120)
                    sock.connect((self.ps5_ip, 9026))

                    encoded = lua_src.encode("utf-8")
                    sock.sendall(struct.pack("<Q", len(encoded)))
                    sock.sendall(encoded)

                    output_parts = []
                    while True:
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            output_parts.append(chunk.decode("utf-8", errors="replace"))
                        except socket.timeout:
                            break
                        except ConnectionResetError:
                            break

                    sock.close()
                    output = "".join(output_parts)

                    ts = time.strftime("%Y%m%d_%H%M%S")
                    result_path = RESULTS_DIR / f"{name}_{ts}.txt"
                    result_path.write_text(output, encoding="utf-8")

                    results.append({"name": name, "success": True, "lines": len(output.split("\n"))})
                    print(f"\033[32m[Research]\033[0m {name}: {len(output)} bytes output")

                except Exception as e:
                    results.append({"name": name, "success": False, "error": str(e)})
                    print(f"\033[31m[Research]\033[0m {name}: {e}")

                time.sleep(2)

            self.send_json({"deployed": True, "payloads": len(payloads), "results": results})

        except Exception as e:
            self.send_json({"deployed": False, "error": str(e)}, 500)

    def handle_research_run(self, body):
        """Run a single named payload or custom Lua script."""
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}

        payload_name = data.get("payload")
        custom_script = data.get("script")

        if not payload_name and not custom_script:
            self.send_json({"error": "Provide 'payload' name or 'script' source"}, 400)
            return

        if payload_name:
            path = PAYLOADS_DIR / f"{payload_name}.lua"
            if not path.exists():
                path = PAYLOADS_DIR / payload_name
            if not path.exists():
                self.send_json({"error": f"Payload not found: {payload_name}"}, 404)
                return
            lua_src = path.read_text(encoding="utf-8")
        else:
            lua_src = custom_script

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(120)
            sock.connect((self.ps5_ip, 9026))

            encoded = lua_src.encode("utf-8")
            sock.sendall(struct.pack("<Q", len(encoded)))
            sock.sendall(encoded)

            output_parts = []
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    output_parts.append(chunk.decode("utf-8", errors="replace"))
                except socket.timeout:
                    break
                except ConnectionResetError:
                    break

            sock.close()
            output = "".join(output_parts)

            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            name = payload_name or "custom"
            result_path = RESULTS_DIR / f"{name}_{ts}.txt"
            result_path.write_text(output, encoding="utf-8")

            self.send_json({"success": True, "output": output, "saved": str(result_path)})

        except ConnectionRefusedError:
            self.send_json({"success": False, "error": "Lua loader not ready on port 9026"}, 503)
        except socket.timeout:
            self.send_json({"success": False, "error": "Timeout"}, 504)
        except Exception as e:
            self.send_json({"success": False, "error": str(e)}, 500)

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# === DNS Responder ===
# Intercepts PS5 user guide lookups and redirects them to this server

def build_dns_response(query, redirect_ip):
    """Build a DNS response that redirects matched domains to our server."""
    # Parse the query
    if len(query) < 12:
        return None

    txn_id = query[:2]
    flags = b"\x81\x80"  # Standard response, no error
    questions = struct.unpack("!H", query[4:6])[0]
    answers = 0

    # Parse the question section to get the domain
    pos = 12
    labels = []
    while pos < len(query):
        length = query[pos]
        if length == 0:
            pos += 1
            break
        labels.append(query[pos + 1 : pos + 1 + length])
        pos += 1 + length

    if pos + 4 > len(query):
        return None

    qtype = struct.unpack("!H", query[pos : pos + 2])[0]
    qclass = struct.unpack("!H", query[pos + 2 : pos + 4])[0]

    domain = b".".join(labels).lower()

    # Check if this domain should be redirected
    should_redirect = False
    for rd in REDIRECT_DOMAINS:
        if domain == rd or domain.endswith(b"." + rd):
            should_redirect = True
            break

    if should_redirect and qtype == 1:  # A record
        print(f"\033[35m[DNS]\033[0m Redirecting {domain.decode()} -> {redirect_ip}")
        answers = 1

        # Build response
        response = txn_id + flags
        response += struct.pack("!H", questions)  # QDCOUNT
        response += struct.pack("!H", answers)     # ANCOUNT
        response += struct.pack("!HH", 0, 0)       # NSCOUNT, ARCOUNT

        # Echo the question
        response += query[12 : pos + 4]

        # Add answer: pointer to name in question + A record
        response += b"\xc0\x0c"  # Pointer to offset 12 (the domain name)
        response += struct.pack("!H", 1)   # Type A
        response += struct.pack("!H", 1)   # Class IN
        response += struct.pack("!I", 300) # TTL
        response += struct.pack("!H", 4)   # Data length
        response += socket.inet_aton(redirect_ip)

        return response

    # Forward to upstream DNS for everything else
    return None


def forward_dns(query):
    """Forward a DNS query to the upstream resolver."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(query, (UPSTREAM_DNS, 53))
        response, _ = sock.recvfrom(4096)
        sock.close()
        return response
    except Exception:
        return None


def dns_server(server_ip, bind_ip="0.0.0.0", port=53):
    """Simple DNS responder that intercepts PS5 user guide lookups."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((bind_ip, port))
    except PermissionError:
        print(f"\033[31m[DNS]\033[0m Cannot bind to port {port} (need admin/root). "
              f"Run as admin or use --no-dns and set DNS manually.")
        return
    except OSError as e:
        print(f"\033[31m[DNS]\033[0m Cannot bind: {e}")
        return

    print(f"\033[35m[DNS]\033[0m Listening on {bind_ip}:{port}")
    print(f"\033[35m[DNS]\033[0m Redirecting PS5 guide domains to {server_ip}")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            response = build_dns_response(data, server_ip)
            if response:
                sock.sendto(response, addr)
            else:
                # Forward to upstream
                upstream = forward_dns(data)
                if upstream:
                    sock.sendto(upstream, addr)
        except Exception as e:
            print(f"\033[31m[DNS]\033[0m Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="PS5 13.60 Jailbreak Host")
    parser.add_argument("--port", type=int, default=80, help="HTTP port (default: 80)")
    parser.add_argument("--dns-port", type=int, default=53, help="DNS port (default: 53)")
    parser.add_argument("--no-dns", action="store_true", help="Disable DNS responder")
    parser.add_argument("--ps5-ip", default="10.0.0.96", help="PS5 IP address")
    parser.add_argument("--server-ip", default="10.0.0.80", help="This server's IP")
    parser.add_argument("--research-port", type=int, default=9100, help="Research app port")
    args = parser.parse_args()

    # Ensure web root exists
    WEB_ROOT.mkdir(exist_ok=True)

    # Copy index.html to web root if not there
    src_index = ROOT / "index.html"
    dst_index = WEB_ROOT / "index.html"
    if src_index.exists() and not dst_index.exists():
        dst_index.write_bytes(src_index.read_bytes())

    print()
    print("  PS5 13.60 Jailbreak Host")
    print("  ========================")
    print(f"  HTTP server:  http://{args.server_ip}:{args.port}/")
    print(f"  PS5 target:   {args.ps5_ip}")
    print(f"  etaHEN:       {'found' if ETAHEN_PATH.exists() else 'MISSING - run setup.ps1'}")
    print(f"  DNS redirect: {'enabled' if not args.no_dns else 'disabled'}")
    print()

    if not args.no_dns:
        dns_thread = threading.Thread(
            target=dns_server,
            args=(args.server_ip, "0.0.0.0", args.dns_port),
            daemon=True,
        )
        dns_thread.start()

    # Create handler factory with config
    def handler_factory(*handler_args, **handler_kwargs):
        return JailbreakHandler(
            *handler_args,
            ps5_ip=args.ps5_ip,
            server_ip=args.server_ip,
            research_port=args.research_port,
            **handler_kwargs,
        )

    httpd = ThreadedHTTPServer(("0.0.0.0", args.port), handler_factory)
    print(f"\033[32m[HTTP]\033[0m Listening on 0.0.0.0:{args.port}")
    print(f"\033[32m[HTTP]\033[0m Open http://{args.server_ip}:{args.port}/ on your PS5 browser")
    print()

    if not args.no_dns:
        print("  PS5 Setup:")
        print(f"  1. Settings > Network > Set Up > DNS > Manual")
        print(f"     Primary: {args.server_ip}  |  Secondary: 8.8.8.8")
        print(f"  2. Open 'User's Guide / Helpful Info' from Settings")
        print(f"  3. Press the Jailbreak button")
        print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        httpd.shutdown()


if __name__ == "__main__":
    main()
