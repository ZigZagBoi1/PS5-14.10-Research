#!/usr/bin/env python3
"""Minimal HTTPS server for PS5 browser probes.

Serves HTML/JS from tools/browser_runner/ and probes/phase13_webkit/,
captures beacons in authoritative JSONL and best-effort compatibility text.

Usage:
    python3 tools/browser_runner/serve.py --cert cert.pem --key key.pem [--port 443]

If --cert/--key are omitted, generates a self-signed cert for
ps5.np.playstation.net + manuals.playstation.net (requires no extra deps).
"""

import argparse
from contextlib import contextmanager
import datetime
import http.server
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import threading
import time
import re
from urllib.parse import urlsplit

try:
    from .capture import CaptureWriter, MAX_BODY_BYTES, decode_request
except ImportError:  # direct CLI
    from capture import CaptureWriter, MAX_BODY_BYTES, decode_request

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent.parent

STATIC = {
    '/': PROJECT / 'probes' / 'phase13_webkit' / 'p671-private-fields-seal-freeze.html',
    '/p660': PROJECT / 'probes' / 'phase13_webkit' / 'p660-webkit-fingerprint-2026.html',
    '/p659': PROJECT / 'probes' / 'phase13_webkit' / 'p659-yarr-backreference-oob-leak.html',
    '/p658': PROJECT / 'probes' / 'phase13_webkit' / 'p658-statestack-realloc-alias.html',
    '/p657': PROJECT / 'probes' / 'phase13_webkit' / 'p657-apng-overread-leak.html',
    '/p656': PROJECT / 'probes' / 'phase13_webkit' / 'p656-two-phase-forge-test.html',
    '/p655': PROJECT / 'probes' / 'phase13_webkit' / 'p655-iframe-gc-trigger.html',
    '/p654': PROJECT / 'probes' / 'phase13_webkit' / 'p654-ffload-gc-leak.html',
    '/p653': PROJECT / 'probes' / 'phase13_webkit' / 'p653-gc-freelist-leak.html',
    '/p652': PROJECT / 'probes' / 'phase13_webkit' / 'p652-load1-determinism.html',
    '/p651': PROJECT / 'probes' / 'phase13_webkit' / 'p651-two-phase-address-leak.html',
    '/p650': PROJECT / 'probes' / 'phase13_webkit' / 'p650-setter-first.html',
    '/p649j': PROJECT / 'probes' / 'phase13_webkit' / 'p649j-field-diagnostic.html',
    '/p649i': PROJECT / 'probes' / 'phase13_webkit' / 'p649i-uniform-pattern.html',
    '/p649h': PROJECT / 'probes' / 'phase13_webkit' / 'p649h-keepalive-forge.html',
    '/p649g': PROJECT / 'probes' / 'phase13_webkit' / 'p649g-wide-zone1.html',
    '/p649f': PROJECT / 'probes' / 'phase13_webkit' / 'p649f-hybrid-patternB.html',
    '/p649e': PROJECT / 'probes' / 'phase13_webkit' / 'p649e-hybrid-forge.html',
    '/p649d': PROJECT / 'probes' / 'phase13_webkit' / 'p649d-getter-only-forge.html',
    '/p649c': PROJECT / 'probes' / 'phase13_webkit' / 'p649c-save-offset-discovery.html',
    '/p649b': PROJECT / 'probes' / 'phase13_webkit' / 'p649b-canvas-forge-alive.html',
    '/p649': PROJECT / 'probes' / 'phase13_webkit' / 'p649-canvas-forge-alive.html',
    '/p648': PROJECT / 'probes' / 'phase13_webkit' / 'p648-daz-denormal-test.html',
    '/p647': PROJECT / 'probes' / 'phase13_webkit' / 'p647-canvas2d-layout-map.html',
    '/p646': PROJECT / 'probes' / 'phase13_webkit' / 'p646-cve-2019-8623-licm-uninit.html',
    '/p645': PROJECT / 'probes' / 'phase13_webkit' / 'p645-cve-2020-9802-arithnegate-oob.html',
    '/p644': PROJECT / 'probes' / 'phase13_webkit' / 'p644-cve-2021-1789-enumerator-oob.html',
    '/p643v1': PROJECT / 'probes' / 'phase13_webkit' / 'p643-cve-2018-4233-createthis.html',
    '/p643': PROJECT / 'probes' / 'phase13_webkit' / 'p643-cve-2018-4233-createthis.html',
    '/p643v2': PROJECT / 'probes' / 'phase13_webkit' / 'p643-cve-2018-4233-createthis-v2.html',
    '/p642': PROJECT / 'probes' / 'phase13_webkit' / 'p642-relapse-primitives-test.html',
    '/p641': PROJECT / 'probes' / 'phase13_webkit' / 'p641-canvas2d-uaf-stale-read.html',
    '/p640': PROJECT / 'probes' / 'phase13_webkit' / 'p640-cross-realm-double-habt.html',
    '/p639': PROJECT / 'probes' / 'phase13_webkit' / 'p639-habt-hole-write-discriminator.html',
    '/p638': PROJECT / 'probes' / 'phase13_webkit' / 'p638-cve-2025-31277-escalate.html',
    '/p637': PROJECT / 'probes' / 'phase13_webkit' / 'p637-cve-2025-31277-regexp-habt.html',
    '/p636': PROJECT / 'probes' / 'phase13_webkit' / 'p636-isoheap-gigacage-jit-verify.html',
    '/p589': PROJECT / 'probes' / 'phase13_webkit' / 'p589-alpha-fontfaceset-trigger.html',
    '/p590': PROJECT / 'probes' / 'phase13_webkit' / 'p590-two-uaf-test.html',
    '/p621': PROJECT / 'probes' / 'phase13_webkit' / 'p621-cve-2024-44308-dfg-putbyval.html',
    '/p622': PROJECT / 'probes' / 'phase13_webkit' / 'p622-cve-2023-41993-type-confusion.html',
    '/p619': PROJECT / 'probes' / 'phase13_webkit' / 'p619-webgl-rtc-api-survey.html',
    '/p620': PROJECT / 'probes' / 'phase13_webkit' / 'p620-section-f-crash-backtrace.html',
    '/launcher.html': ROOT / 'launcher.html',
    '/p550.html': ROOT / 'p550.html',
    '/p550.js': PROJECT / 'probes' / 'phase13_webkit' / 'p550-canvas-uaf-transform-leak.js',
    '/p553.js': PROJECT / 'probes' / 'phase13_webkit' / 'p553-canvas-uaf-write-confirm.js',
    '/fuzz.html': ROOT / 'fuzz.html',
}

MIME = {'.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.png': 'image/png', '.json': 'application/json', '.webp': 'image/webp'}

LOG_DIR = ROOT / 'beacon_logs'


_LOG_ESCAPES = str.maketrans({
    '\r': '\\r',
    '\n': '\\n',
    '\v': '\\v',
    '\f': '\\f',
    '\x1c': '\\x1c',
    '\x1d': '\\x1d',
    '\x1e': '\\x1e',
    '\x85': '\\x85',
    '\u2028': '\\u2028',
    '\u2029': '\\u2029',
})


def _escape_log_value(value):
    """Keep one beacon record on one log line for every splitlines() break."""
    return str(value).translate(_LOG_ESCAPES)


def _safe_file(base, relative):
    """Resolve a request path under base, rejecting traversal and symlinks."""
    base = base.resolve()
    candidate = (base / relative).resolve()
    if candidate != base and base not in candidate.parents:
        return None
    return candidate if candidate.is_file() else None


def generate_self_signed(certfile, keyfile):
    if shutil.which('openssl') is None:
        _safe_print('openssl not found â€” provide --cert and --key manually', file=sys.stderr)
        sys.exit(1)
    _safe_print('Generating self-signed cert for ps5.np.playstation.net ...')
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', str(keyfile), '-out', str(certfile),
        '-days', '365', '-subj', '/CN=ps5.np.playstation.net',
        '-addext', 'subjectAltName=DNS:ps5.np.playstation.net,DNS:manuals.playstation.net,DNS:*.np.playstation.net',
    ], check=True)
    _safe_print(f'Cert: {certfile}\nKey:  {keyfile}')


# Exact display policy from PR #231 (cccff399); JSONL remains reversible.
_LOG_ESCAPES = str.maketrans({
    '\r': '\\r', '\n': '\\n', '\v': '\\v', '\f': '\\f',
    '\x1c': '\\x1c', '\x1d': '\\x1d', '\x1e': '\\x1e',
    '\x85': '\\x85', '\u2028': '\\u2028', '\u2029': '\\u2029',
})


def _escape_log_value(value):
    """Keep one beacon record on one log line for every splitlines() break."""
    return str(value).translate(_LOG_ESCAPES)


def _safe_print(*values, **kwargs):
    try:
        print(*values, **kwargs)
    except Exception:
        pass  # Display is never a required capture sink.


def _remember_error(server, error):
    if getattr(server, 'first_error', None) is None:
        server.first_error = error
    server.capture_failed = True


_CLIENT_DISCONNECTS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)


class _ResponseDisconnected(Exception):
    """Only raised for a known disconnect from a response's output write."""
    def __init__(self, error):
        super().__init__(str(error))
        self.error = error


class _ResponseOutput:
    """Delegate output; distinguish send failures from response preparation."""
    def __init__(self, output):
        self.output = output

    def write(self, data):
        try:
            return self.output.write(data)
        except _CLIENT_DISCONNECTS as exc:
            raise _ResponseDisconnected(exc) from exc

    def __getattr__(self, name):
        return getattr(self.output, name)


class CaptureHTTPServer(http.server.HTTPServer):
    """Serial request processing; each server owns exactly one capture."""
    def __init__(self, address, handler, *, capture, log_file=None):
        self.capture = capture
        self.log_file = log_file
        self.capture_failed = False
        self.first_error = None
        self.secondary_error = None
        self.response_error = None
        super().__init__(address, handler)

    def handle_error(self, request, client_address):
        # HTTPServer normally prints and discards an unexpected handler exception.
        _remember_error(self, sys.exc_info()[1])
        _safe_print('Request failed; capture will remain unclosed.', file=sys.stderr)


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    server_version = 'PS5Probe/1.0'
    timeout = 5.0  # socket/header idle timeout; not an overall header deadline
    body_read_timeout = 5.0
    body_deadline = 10.0
    log_file = None  # retained for compatibility with standalone display consumers
    log_lock = threading.Lock()

    def parse_request(self):
        parsed = super().parse_request()
        if parsed:
            if self.request_version == 'HTTP/0.9':
                self.request_version = 'HTTP/1.0'  # send an explicit error response
                self._reply(400)
                return False
            # BaseHTTPRequestHandler normalizes leading // in self.path.
            # Retain the original target token, before routing or URL decoding.
            self.raw_target = self.raw_requestline.split()[1].decode('iso-8859-1')
            self.close_connection = True  # no unread body can become a later request
        return parsed

    def log_message(self, fmt, *args):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        _safe_print(f'[{ts}] {self.client_address[0]} {_escape_log_value(fmt % args)}')

    def send_error(self, code, message=None, explain=None):
        # Base send_error also logs, formats HTML, encodes bytes and builds
        # headers. Only exceptions identified by the actual output write are
        # optional transport errors; preparation/internal failures remain fatal.
        with self._static_response_output():
            super().send_error(code, message, explain)

    def _reply(self, status):
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
        except OSError as exc:
            # Primary evidence may already exist. A failed transmission is not
            # evidence that the browser received nothing or that a retry is new.
            if getattr(self.server, 'response_error', None) is None:
                self.server.response_error = exc

    @contextmanager
    def _static_response_output(self):
        """Share send-only classification for static and inherited error replies."""
        output = self.wfile
        self.wfile = _ResponseOutput(output)
        try:
            yield
        except _ResponseDisconnected as disconnect:
            self.close_connection = True
            if getattr(self.server, 'response_error', None) is None:
                self.server.response_error = disconnect.error
        finally:
            self.wfile = output

    def _capture_beacon(self):
        if self.headers.defects or self.headers.get_all('Transfer-Encoding'):
            self._reply(400)
            return
        if self.headers.get_all('Expect'):
            self._reply(400)  # no 100-continue/expectation negotiation
            return
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) > 1:
            self._reply(400)  # includes equal duplicates
            return
        if not lengths and self.command == 'POST':
            self._reply(411)
            return
        length = None
        if lengths:
            value = lengths[0].strip(' \t')
            if not re.fullmatch(r'[0-9]+', value):
                self._reply(400)
                return
            digits = value.lstrip('0') or '0'
            if len(digits) > 5 or int(digits) > MAX_BODY_BYTES:
                self._reply(413)
                return
            length = int(digits)
        if self.command == 'GET' and length:
            self._reply(400)
            return
        body = bytearray()
        previous_timeout = self.connection.gettimeout()
        deadline = time.monotonic() + self.body_deadline
        try:
            while len(body) < (length or 0):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('overall body deadline')
                self.connection.settimeout(min(self.body_read_timeout, remaining))
                chunk = self.rfile.read1(min(8192, length - len(body)))
                if time.monotonic() >= deadline:
                    raise TimeoutError('overall body deadline')
                if not chunk:
                    self._reply(400)
                    return
                body.extend(chunk)
        except TimeoutError:
            self._reply(408)
            return
        except OSError:
            self._reply(400)
            return
        finally:
            try:
                self.connection.settimeout(previous_timeout)
            except OSError:
                pass
        request = decode_request(self.command, self.raw_target, bytes(body),
                                 declared_length=length)
        if request.status != 'accepted':
            self._reply(400)
            return
        capture = getattr(self.server, 'capture', None)
        if capture is None or getattr(self.server, 'capture_failed', False):
            _remember_error(self.server, OSError('authoritative capture unavailable'))
            self._reply(503)
            return
        try:
            capture.append(request)
        except BaseException as exc:
            _remember_error(self.server, exc)
            if not isinstance(exc, Exception):
                raise
            self._reply(500)
            return
        # Best-effort projection, with no dependency on stdout or text-file health.
        if request.format in ('tagged_d', 'post_body'):
            value = request.measurement
            if value is None:
                value = f'<binary {len(body)} bytes; see JSONL>'
            message = f'{request.tag}: {value}' if request.tag is not None else value
        else:
            message = request.measurement
        try:
            self._log_beacon(message)
        except Exception as exc:
            if getattr(self.server, 'secondary_error', None) is None:
                self.server.secondary_error = exc
            _safe_print('Secondary beacon log failed; JSONL retained.', file=sys.stderr)
        self._reply(204)

    def do_GET(self):
        try:
            parsed = urlsplit(self.raw_target)
        except ValueError:
            self._reply(400)
            return
        path = parsed.path
        if path in ('/beacon', '/beacon.php') or path.startswith('/beacon/'):
            self._capture_beacon()
            return

        if path.startswith('/document/') and '/ps5/' in path:
            suffix = path.split('/ps5/', 1)[1]
            path = '/' + suffix

        # v674-kit payloads (cobrajet302gt delivery): exact filenames only, no traversal
        if path.startswith('/payloads/'):
            name = path.split('/payloads/', 1)[1]
            allowed = {
                'v674_ctrl.png', 'v674_leak.png', 'v674_trunc.png',
                'v674_apng_ctrl.png', 'v674_apng_slack.png',
                'v674_apng_trunc.png', 'v674_multiidat.png',
            }
            if name in allowed:
                kit = ROOT / 'v674-kit' / 'payloads' / name
                if kit.is_file():
                    data = kit.read_bytes()
                    self.send_response(200)
                    self.send_header('Content-Type', 'image/png')
                    self.send_header('Content-Length', str(len(data)))
                    self.send_header('Cache-Control', 'no-store')
                    self.end_headers()
                    self.wfile.write(data)
                    return

        target = STATIC.get(path)
        if target and target.is_file():
            data = target.read_bytes()
            ext = target.suffix
            mime = MIME.get(ext, 'application/octet-stream')
            with self._static_response_output():
                self.send_response(200)
                self.send_header('Content-Type', mime + '; charset=utf-8')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(data)
            return

        if path.startswith('/webp-poc/'):
            wp_path = _safe_file(ROOT / 'webp-poc', path[len('/webp-poc/'):])
            if wp_path:
                data = wp_path.read_bytes()
                ext = wp_path.suffix
                mime = MIME.get(ext, 'application/octet-stream')
                with self._static_response_output():
                    self.send_response(200)
                    self.send_header('Content-Type', mime)
                    self.send_header('Content-Length', str(len(data)))
                    self.send_header('Cache-Control', 'no-store')
                    self.end_headers()
                    self.wfile.write(data)
                return

        if path.startswith('/fuzzcases/'):
            fuzz_path = _safe_file(ROOT / 'fuzzcases', path[len('/fuzzcases/'):])
            if fuzz_path:
                data = fuzz_path.read_bytes()
                ext = fuzz_path.suffix
                mime = MIME.get(ext, 'application/octet-stream')
                with self._static_response_output():
                    self.send_response(200)
                    self.send_header('Content-Type', mime + '; charset=utf-8')
                    self.send_header('Content-Length', str(len(data)))
                    self.send_header('Cache-Control', 'no-store')
                    self.end_headers()
                    self.wfile.write(data)
                return

        probe_file = _safe_file(
            PROJECT / 'probes' / 'phase13_webkit', path.lstrip('/')
        )
        if probe_file:
            data = probe_file.read_bytes()
            ext = probe_file.suffix
            mime = MIME.get(ext, 'application/octet-stream')
            with self._static_response_output():
                self.send_response(200)
                self.send_header('Content-Type', mime + '; charset=utf-8')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(data)
            return

        self.send_error(404, 'Not found')  # send_error owns its output boundary

    def do_POST(self):
        try:
            path = urlsplit(self.raw_target).path
        except ValueError:
            self._reply(400)
            return
        if path in ('/beacon', '/beacon.php') or path.startswith('/beacon/'):
            self._capture_beacon()
        else:
            self._reply(404)

    def _log_beacon(self, msg):
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        line = f'[{ts}] BEACON {self.client_address[0]}: {_escape_log_value(msg)}'
        _safe_print(f'\033[33m{line}\033[0m')
        server = getattr(self, 'server', None)
        stream = getattr(server, 'log_file', self.log_file)
        with self.log_lock:
            if stream is not None:
                if stream.write(line + '\n') != len(line) + 1:
                    raise OSError('short secondary log write')
                stream.flush()


def run(args):
    """Own acquisition lifecycle; raise the first error after releasing resources."""
    capture = server = text = None
    first_error = None
    normal = False
    try:
        capture = CaptureWriter.create(LOG_DIR)
        log_path = LOG_DIR / f'beacons_{capture.capture_id}.log'
        try:
            text = open(log_path, 'x', encoding='utf-8')
        except OSError:
            _safe_print('Secondary beacon log unavailable; JSONL required.', file=sys.stderr)
        server = CaptureHTTPServer((args.host, args.port), ProbeHandler,
                                   capture=capture, log_file=text)
        if not args.no_tls:
            certfile = args.cert or str(ROOT / 'server.crt')
            keyfile = args.key or str(ROOT / 'server.key')
            if not args.cert and not os.path.exists(certfile):
                generate_self_signed(certfile, keyfile)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
        proto = 'http' if args.no_tls else 'https'
        _safe_print(f'Serving {proto}://{args.host}:{server.server_port}/')
        _safe_print(f'Authoritative capture: {capture.path}')
        _safe_print(f'Secondary beacon log: {log_path if text else "unavailable"}')
        server.serve_forever()
        normal = True
    except BaseException as exc:
        first_error = getattr(server, 'first_error', None) or exc
    finally:
        first_error = first_error or getattr(server, 'first_error', None)
        if server is not None:
            try:
                server.server_close()  # serial serving has stopped before capture closes
            except BaseException as exc:
                first_error = first_error or exc
        if capture is not None:
            try:
                if normal and first_error is None:
                    capture.close()  # exactly one close attempt, never retried on failure
                else:
                    capture.abort()
            except BaseException as exc:
                first_error = first_error or exc
        if text is not None:
            try:
                text.close()
            except Exception:
                _safe_print('Secondary beacon log close failed.', file=sys.stderr)
    if first_error is not None:
        raise first_error


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--cert', help='TLS certificate PEM')
    parser.add_argument('--key', help='TLS private key PEM')
    parser.add_argument('--no-tls', action='store_true', help='Plain HTTP (for testing)')
    parser.add_argument('--default', help='Probe file served at / (relative to tools/browser_runner or probes/phase13_webkit)')
    args = parser.parse_args()
    if args.default:
        cand = ROOT / args.default
        if not cand.is_file():
            cand = PROJECT / 'probes' / 'phase13_webkit' / args.default
        if not cand.is_file():
            parser.error(f'--default {args.default}: not found')
        STATIC['/'] = cand
    try:
        run(args)
    except KeyboardInterrupt:
        _safe_print('Interrupted: retained capture is unclosed; delivery remains UNKNOWN.')
        return 130
    return 0


if __name__ == '__main__':
    sys.exit(main())

