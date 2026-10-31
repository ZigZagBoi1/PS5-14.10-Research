#!/usr/bin/env python3
"""HTTPS + DNS server for PS5 browser probes.

Serves HTML/JS probes to the PS5 browser via DNS spoofing.
Logs beacon callbacks to stdout and a timestamped file.

Usage:
    # Full setup (DNS + HTTPS, run as admin for port 53/443):
    python3 tools/browser_runner/serve.py --dns

    # HTTPS only (set PS5 DNS manually):
    python3 tools/browser_runner/serve.py

    # Serve a specific probe as the landing page:
    python3 tools/browser_runner/serve.py --dns --probe p568

    # Plain HTTP for local testing:
    python3 tools/browser_runner/serve.py --no-tls --port 8080

PS5 setup:
    1. Go to Settings > Network > Set Up Internet Connection
    2. Set DNS to Manual, Primary DNS = this PC's IP
    3. Open the PS5 browser (User Guide from any game)
    4. It loads our probe instead of the real page

If --cert/--key are omitted, generates a self-signed cert for
manuals.playstation.net (requires openssl in PATH).
"""

import argparse
import datetime
import http.server
import os
import pathlib
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit, parse_qs, unquote

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent.parent

PHASE13 = PROJECT / 'probes' / 'phase13_webkit'
PHASE23 = PROJECT / 'probes' / 'phase23_info_leak'

# Static routes: path -> file on disk
STATIC = {
    '/p550.html': ROOT / 'p550.html',
    '/p550.js': PHASE13 / 'p550-canvas-uaf-transform-leak.js',
    '/fuzz.html': ROOT / 'fuzz.html',
}

# Auto-discover probes: any pNNN.html in browser_runner or pNNN.js in probe dirs
for html_file in ROOT.glob('p*.html'):
    route = '/' + html_file.name
    if route not in STATIC:
        STATIC[route] = html_file

for js_file in PHASE13.glob('p*.js'):
    name = js_file.stem.split('-')[0] if '-' in js_file.stem else js_file.stem
    route = '/' + name + '.js'
    if route not in STATIC:
        STATIC[route] = js_file

for js_file in PHASE23.glob('p*.js'):
    name = js_file.stem
    route = '/' + name + '.js'
    if route not in STATIC:
        STATIC[route] = js_file

MIME = {'.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json'}

LOG_DIR = ROOT / 'beacon_logs'


def generate_self_signed(certfile, keyfile):
    if shutil.which('openssl') is None:
        print('openssl not found — provide --cert and --key manually', file=sys.stderr)
        sys.exit(1)
    print('Generating self-signed cert for ps5.np.playstation.net ...')
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', str(keyfile), '-out', str(certfile),
        '-days', '365', '-subj', '/CN=ps5.np.playstation.net',
        '-addext', 'subjectAltName=DNS:ps5.np.playstation.net,DNS:manuals.playstation.net,DNS:*.np.playstation.net',
    ], check=True)
    print(f'Cert: {certfile}\nKey:  {keyfile}')


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    server_version = 'PS5Probe/1.0'
    log_file = None
    log_lock = threading.Lock()

    def log_message(self, fmt, *args):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        print(f'[{ts}] {self.client_address[0]} {fmt % args}')

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path

        # PS5 User Guide redirect: /document/xx/ps5/foo -> /foo
        if path.startswith('/document/') and '/ps5/' in path:
            suffix = path.split('/ps5/', 1)[1]
            path = '/' + suffix

        # Beacon: old format /beacon?m=msg
        if path == '/beacon':
            qs = parse_qs(parsed.query)
            msg = qs.get('m', [''])[0]
            self._log_beacon(msg)
            self._send_pixel()
            return

        # Beacon: new format /beacon/P567-TAG-extra?t=123
        # Used by phase 23 probes via new Image().src
        if path.startswith('/beacon/'):
            tag = unquote(path[len('/beacon/'):])
            self._log_beacon(tag)
            self._send_pixel()
            return

        # Landing page: specific probe or index
        if path == '/' or path == '/probes':
            landing = getattr(self, 'landing_probe', None)
            if landing and path == '/':
                target = STATIC.get(landing)
                if target and target.is_file():
                    self._serve_file(target)
                    return
            self._serve_index()
            return

        # Static routes
        target = STATIC.get(path)
        if target and target.is_file():
            self._serve_file(target)
            return

        # Fuzz cases
        if path.startswith('/fuzzcases/'):
            fuzz_path = ROOT / path.lstrip('/')
            if fuzz_path.is_file():
                self._serve_file(fuzz_path)
                return

        self.send_error(404, 'Not found')

    def _send_pixel(self):
        # 1x1 transparent GIF for Image.src beacons
        gif = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
        self.send_response(200)
        self.send_header('Content-Type', 'image/gif')
        self.send_header('Content-Length', str(len(gif)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(gif)

    def _serve_file(self, filepath):
        data = filepath.read_bytes()
        ext = filepath.suffix
        mime = MIME.get(ext, 'application/octet-stream')
        self.send_response(200)
        self.send_header('Content-Type', mime + '; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def _serve_index(self):
        probes = sorted(k for k in STATIC if k.endswith('.html') and k != '/fuzz.html')
        rows = []
        for p in probes:
            name = p.lstrip('/')
            rows.append(f'<li><a href="{p}">{name}</a></li>')
        html = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PS5 Probe Server</title>
<style>body{{background:#111;color:#eee;font-family:monospace;padding:20px}}
a{{color:#0af}}</style></head>
<body><h2>PS5 WebKit Probe Server</h2>
<p>Available probes:</p><ul>{"".join(rows)}</ul>
<p><a href="/fuzz.html">Fuzz runner</a></p>
</body></html>'''
        data = html.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        parsed = urlsplit(self.path)
        if parsed.path.startswith('/beacon'):
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(min(length, 4096)).decode('utf-8', errors='replace') if length > 0 else ''
            tag = parsed.path.replace('/beacon/', '').replace('/beacon', '')
            msg = f'{tag}: {body}' if tag else body
            self._log_beacon(msg)
            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self.send_error(404, 'Not found')

    def _log_beacon(self, msg):
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        line = f'[{ts}] BEACON {self.client_address[0]}: {msg}'
        print(f'\033[33m{line}\033[0m')
        with self.log_lock:
            if self.log_file:
                self.log_file.write(line + '\n')
                self.log_file.flush()


# ── DNS responder ──────────────────────────────────────────────
# Minimal UDP DNS server that answers A queries for spoofed domains
# with the server's own IP. All other queries get NXDOMAIN.

SPOOF_DOMAINS = {
    b'manuals.playstation.net',
    b'ps5.np.playstation.net',
}


class DNSHandler(socketserver.BaseRequestHandler):
    spoof_ip = '127.0.0.1'

    def handle(self):
        data, sock = self.request
        try:
            resp = self._build_response(data)
            if resp:
                sock.sendto(resp, self.client_address)
        except Exception:
            pass

    def _build_response(self, data):
        if len(data) < 12:
            return None
        txid = data[:2]
        flags = struct.unpack('!H', data[2:4])[0]
        qdcount = struct.unpack('!H', data[4:6])[0]
        if qdcount < 1:
            return None

        # Parse the question
        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            labels.append(data[offset:offset + length])
            offset += length

        if offset + 4 > len(data):
            return None

        qtype = struct.unpack('!H', data[offset:offset + 2])[0]
        qclass = struct.unpack('!H', data[offset + 2:offset + 4])[0]
        qname = b'.'.join(labels).lower()
        question = data[12:offset + 4]

        ts = datetime.datetime.now().strftime('%H:%M:%S')

        if qtype == 1 and qname in SPOOF_DOMAINS:
            # A record → spoof to our IP
            ip_bytes = socket.inet_aton(self.spoof_ip)
            print(f'[{ts}] DNS {self.client_address[0]}: {qname.decode()} -> {self.spoof_ip}')
            # Header: QR=1, AA=1, RA=1, RCODE=0
            resp_flags = 0x8580
            header = txid + struct.pack('!HHHHH', resp_flags, 1, 1, 0, 0)
            # Answer: pointer to question name, A record, TTL=60, 4 bytes
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + ip_bytes
            return header + question + answer
        else:
            # Pass-through: forward to real DNS (8.8.8.8)
            try:
                fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                fwd.settimeout(3)
                fwd.sendto(data, ('8.8.8.8', 53))
                resp, _ = fwd.recvfrom(4096)
                fwd.close()
                return resp
            except Exception:
                # NXDOMAIN fallback
                resp_flags = 0x8583
                header = txid + struct.pack('!HHHHH', resp_flags, 1, 0, 0, 0)
                return header + question


def start_dns(host, spoof_ip):
    DNSHandler.spoof_ip = spoof_ip
    server = socketserver.UDPServer((host, 53), DNSHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f'DNS server listening on {host}:53 (spoofing to {spoof_ip})')
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--cert', help='TLS certificate PEM')
    parser.add_argument('--key', help='TLS private key PEM')
    parser.add_argument('--no-tls', action='store_true', help='Plain HTTP (for testing)')
    parser.add_argument('--dns', action='store_true', help='Start built-in DNS server on port 53')
    parser.add_argument('--probe', help='Probe to serve as landing page (e.g. p567, p568)')
    args = parser.parse_args()

    LOG_DIR.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    log_path = LOG_DIR / f'beacons_{ts}.log'
    ProbeHandler.log_file = open(log_path, 'a')

    # Set landing page
    if args.probe:
        landing = f'/{args.probe}.html'
        if landing in STATIC:
            ProbeHandler.landing_probe = landing
        else:
            print(f'Warning: {landing} not found in routes, using index', file=sys.stderr)
            ProbeHandler.landing_probe = None
    else:
        ProbeHandler.landing_probe = None

    certfile = args.cert
    keyfile = args.key

    if not args.no_tls and not certfile:
        certfile = str(ROOT / 'server.crt')
        keyfile = str(ROOT / 'server.key')
        if not os.path.exists(certfile):
            generate_self_signed(certfile, keyfile)

    ip = args.host if args.host != '0.0.0.0' else socket.gethostbyname(socket.gethostname())

    if args.dns:
        try:
            start_dns(args.host, ip)
        except PermissionError:
            print('DNS requires admin/root (port 53). Run as admin or use --no-dns.', file=sys.stderr)
            print('Without DNS: set PS5 DNS manually to point to this PC.', file=sys.stderr)
        except OSError as e:
            print(f'DNS failed: {e}', file=sys.stderr)

    server = http.server.HTTPServer((args.host, args.port), ProbeHandler)

    if not args.no_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        proto = 'https'
    else:
        proto = 'http'

    print()
    print('=' * 60)
    print('  PS5 WebKit Probe Server')
    print('=' * 60)
    print(f'  HTTPS: {proto}://{ip}:{args.port}/')
    print(f'  Beacon log: {log_path}')
    if args.dns:
        print(f'  DNS: spoofing manuals.playstation.net -> {ip}')
    print()
    print('  PS5 Setup:')
    print(f'    1. Set PS5 DNS to {ip}')
    print('    2. Open any game, press PS > User Guide')
    print('    3. The probe loads automatically')
    print()
    if args.probe:
        print(f'  Landing: /{args.probe}.html')
    else:
        print(f'  Landing: probe index (pick from list)')
    print(f'  Available: {", ".join(sorted(k.lstrip("/") for k in STATIC if k.endswith(".html")))}')
    print('=' * 60)
    print('Ctrl+C to stop\n')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
    finally:
        ProbeHandler.log_file.close()


if __name__ == '__main__':
    main()
