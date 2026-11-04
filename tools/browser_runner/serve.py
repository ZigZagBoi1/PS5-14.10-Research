#!/usr/bin/env python3
"""Minimal HTTPS+DNS server for PS5 browser probes.

Serves HTML/JS from tools/browser_runner/ and probes/phase13_webkit/,
answers DNS queries for the User's Guide domains (A record -> this host),
and logs beacon GET requests to stdout and a timestamped file.

Usage:
    python3 tools/browser_runner/serve.py [--port 443] [--no-dns] [--no-tls]
        [--cert cert.pem --key key.pem] [--upstream 1.1.1.1]

DNS: hijacks ps5.np.playstation.net and manuals.playstation.net to this
host; every other name is forwarded to --upstream so the guide's envelope
fetches still resolve. Disable with --no-dns.

TLS: uses --cert/--key if given; otherwise reuses server.crt/server.key or
generates a self-signed cert for ps5.np.playstation.net + manuals.playstation.net
(openssl if present, else pure-Python via the cryptography package).
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
from urllib.parse import urlsplit, parse_qs

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent.parent

STATIC = {
    '/': ROOT / 'p550.html',
    '/p550.html': ROOT / 'p550.html',
    '/p550.js': PROJECT / 'probes' / 'phase13_webkit' / 'p550-canvas-uaf-transform-leak.js',
    '/fuzz.html': ROOT / 'fuzz.html',
}

MIME = {'.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json'}

LOG_DIR = ROOT / 'beacon_logs'

# Domains the 14.10 User's Guide actually queries (docs/BROWSER_ENTRY_INFRA_2026-10-19.md).
# envelope*.np.dl.playstation.net must keep resolving, so it is forwarded, not hijacked.
DNS_HIJACK = {'ps5.np.playstation.net', 'manuals.playstation.net'}
DNS_TTL = 60


def generate_self_signed(certfile, keyfile):
    if shutil.which('openssl') is not None:
        print('Generating self-signed cert for ps5.np.playstation.net ...')
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(keyfile), '-out', str(certfile),
            '-days', '365', '-subj', '/CN=ps5.np.playstation.net',
            '-addext', 'subjectAltName=DNS:ps5.np.playstation.net,DNS:manuals.playstation.net,DNS:*.np.playstation.net',
        ], check=True)
    else:
        generate_self_signed_crypto(certfile, keyfile)
    print(f'Cert: {certfile}\nKey:  {keyfile}')


def generate_self_signed_crypto(certfile, keyfile):
    """Self-signed cert without openssl, via the cryptography package."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ps5.np.playstation.net')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName('ps5.np.playstation.net'),
            x509.DNSName('manuals.playstation.net'),
            x509.DNSName('*.np.playstation.net'),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pathlib.Path(certfile).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pathlib.Path(keyfile).write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))


def parse_dns_query(data):
    """Parse the first question of a UDP DNS query.

    Returns (qid, question_bytes, name) with question_bytes the raw
    question section to echo back, or None if the packet is malformed.
    """
    if len(data) < 12:
        return None
    qid, _flags, qdcount, _, _, _ = struct.unpack('>HHHHHH', data[:12])
    if qdcount < 1:
        return None
    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:  # compression pointer: unsupported in queries
            return None
        offset += 1
        if offset + length > len(data):
            return None
        labels.append(data[offset:offset + length].decode('ascii', 'replace'))
        offset += length
    else:
        return None
    if offset + 4 > len(data):
        return None
    return qid, data[12:offset + 4], '.'.join(labels).lower()


def build_dns_response(qid, question_bytes, ip=None):
    """Build a DNS response. With ip -> one A record; without -> NXDOMAIN."""
    if ip is None:
        flags = 0x8183  # QR + RD + RA + NXDOMAIN
        answer = b''
    else:
        flags = 0x8180  # QR + RD + RA
        answer = (
            b'\xc0\x0c'
            + struct.pack('>HHIH', 1, 1, DNS_TTL, 4)
            + socket.inet_aton(ip)
        )
    header = struct.pack('>HHHHHH', qid, flags, 1, 1 if ip else 0, 0, 0)
    return header + question_bytes + answer


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        parsed = parse_dns_query(data)
        if parsed is None:
            return
        qid, question_bytes, name = parsed
        server = self.server
        if name in DNS_HIJACK:
            print(f'[DNS] {name} -> {server.host_ip} (hijacked)')
            sock.sendto(build_dns_response(qid, question_bytes, server.host_ip), self.client_address)
            return
        try:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.settimeout(3)
            upstream.sendto(data, (server.upstream, 53))
            reply, _ = upstream.recvfrom(4096)
            sock.sendto(reply, self.client_address)
        except OSError:
            sock.sendto(build_dns_response(qid, question_bytes), self.client_address)


class DNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, address, host_ip, upstream):
        self.host_ip = host_ip
        self.upstream = upstream
        super().__init__(address, DNSHandler)


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

        if path == '/beacon':
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

        if path.startswith('/probe/'):
            name = pathlib.Path(path).name
            probe_path = PROJECT / 'probes' / 'phase13_webkit' / name
            if probe_path.is_file():
                data = probe_path.read_bytes()
                mime = MIME.get(probe_path.suffix, 'application/octet-stream')
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
    parser.add_argument('--no-dns', action='store_true', help='Do not run the DNS responder')
    parser.add_argument('--dns-port', type=int, default=53)
    parser.add_argument('--upstream', default='1.1.1.1', help='Upstream DNS for non-hijacked names')
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

    host_ip = socket.gethostbyname(socket.gethostname()) if args.host == '0.0.0.0' else args.host

    dns_thread = None
    if not args.no_dns:
        try:
            dns_server = DNSServer(('0.0.0.0', args.dns_port), host_ip, args.upstream)
            dns_thread = threading.Thread(target=dns_server.serve_forever, daemon=True)
            dns_thread.start()
            print(f'DNS: hijacking {", ".join(sorted(DNS_HIJACK))} -> {host_ip} (udp/{args.dns_port}),'
                  f' other names -> {args.upstream}')
        except OSError as exc:
            print(f'DNS responder not started: {exc}', file=sys.stderr)
            print('Use --no-dns if another resolver owns udp/53.', file=sys.stderr)

    server = http.server.HTTPServer((args.host, args.port), ProbeHandler)

    if not args.no_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        proto = 'https'
    else:
        proto = 'http'

    print(f'Serving probes at {proto}://{host_ip}:{args.port}/  (/document/<lang>/ps5/<probe> -> /probe/<probe>)')
    print(f'Beacon log: {log_path}')
    print(f'Set PS5 DNS (primary) to {host_ip} on the network profile in use; IPv6 off.')
    print('Ctrl+C to stop')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
    finally:
        ProbeHandler.log_file.close()


if __name__ == '__main__':
    main()
