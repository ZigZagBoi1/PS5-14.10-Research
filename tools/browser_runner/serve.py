#!/usr/bin/env python3
"""Minimal HTTPS server for PS5 browser probes.

Serves HTML/JS from tools/browser_runner/ and probes/phase13_webkit/,
logs beacon GET requests to stdout and a timestamped file.

Usage:
    python3 tools/browser_runner/serve.py --cert cert.pem --key key.pem [--port 443]

If --cert/--key are omitted, generates a self-signed cert for
ps5.np.playstation.net + manuals.playstation.net (requires no extra deps).
"""

import argparse
import datetime
import http.server
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit, parse_qs

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent.parent

STATIC = {
    '/': PROJECT / 'probes' / 'phase13_webkit' / 'p568-refcount-monitor.html',
    '/p550.html': ROOT / 'p550.html',
    '/p550.js': PROJECT / 'probes' / 'phase13_webkit' / 'p550-canvas-uaf-transform-leak.js',
    '/p563.html': ROOT / 'p563.html',
    '/p563.js': PROJECT / 'probes' / 'phase13_webkit' / 'p563-canvas-crosstype-reclaim.js',
    '/fuzz.html': ROOT / 'fuzz.html',
}

# Auto-serve any probe HTML from probes/phase13_webkit/ by filename
WEBKIT_PROBES = PROJECT / 'probes' / 'phase13_webkit'
for _p in WEBKIT_PROBES.glob('*.html'):
    _key = '/' + _p.name
    if _key not in STATIC:
        STATIC[_key] = _p

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

        if path.startswith('/document/') and '/ps5/' in path:
            suffix = path.split('/ps5/', 1)[1]
            path = '/' + suffix

        if path.startswith('/beacon'):
            qs = parse_qs(parsed.query)
            msg = qs.get('m', [''])[0]
            self._log_beacon(msg)
            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            return

        target = STATIC.get(path)
        if target and target.is_file():
            data = target.read_bytes()
            ext = target.suffix
            mime = MIME.get(ext, 'application/octet-stream')
            self.send_response(200)
            self.send_header('Content-Type', mime + '; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(data)
            return

        if path.startswith('/fuzzcases/'):
            fuzz_path = ROOT / path.lstrip('/')
            if fuzz_path.is_file():
                data = fuzz_path.read_bytes()
                ext = fuzz_path.suffix
                mime = MIME.get(ext, 'application/octet-stream')
                self.send_response(200)
                self.send_header('Content-Type', mime + '; charset=utf-8')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(data)
                return

        self.send_error(404, 'Not found')

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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--cert', help='TLS certificate PEM')
    parser.add_argument('--key', help='TLS private key PEM')
    parser.add_argument('--no-tls', action='store_true', help='Plain HTTP (for testing)')
    args = parser.parse_args()

    LOG_DIR.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    log_path = LOG_DIR / f'beacons_{ts}.log'
    ProbeHandler.log_file = open(log_path, 'a')

    certfile = args.cert
    keyfile = args.key

    if not args.no_tls and not certfile:
        certfile = str(ROOT / 'server.crt')
        keyfile = str(ROOT / 'server.key')
        if not os.path.exists(certfile):
            generate_self_signed(certfile, keyfile)

    server = http.server.HTTPServer((args.host, args.port), ProbeHandler)

    if not args.no_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        for spec in ('ALL:@SECLEVEL=0', 'DEFAULT:@SECLEVEL=0', 'ALL'):
            try:
                ctx.set_ciphers(spec)
                break
            except ssl.SSLError:
                continue
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, ssl.SSLError):
            pass
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        proto = 'https'
    else:
        proto = 'http'

    ip = args.host if args.host != '0.0.0.0' else socket.gethostbyname(socket.gethostname())
    print(f'Serving p550 at {proto}://{ip}:{args.port}/')
    print(f'Beacon log: {log_path}')
    print(f'Set PS5 DNS to point ps5.np.playstation.net -> {ip}')
    print('Ctrl+C to stop')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
    finally:
        ProbeHandler.log_file.close()


if __name__ == '__main__':
    main()
