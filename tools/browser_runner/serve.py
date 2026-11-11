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
import json
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import re
from urllib.parse import parse_qs, urlsplit

try:
    from .capture import CaptureWriter, MAX_BODY_BYTES, decode_request
except ImportError:  # direct CLI
    from capture import CaptureWriter, MAX_BODY_BYTES, decode_request

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent.parent

STATIC = {
    '/': ROOT / 'redirect.html',
    '/p804': PROJECT / 'probes' / 'phase13_webkit' / 'p804-vtable-verify.html',
    '/p807': PROJECT / 'probes' / 'phase13_webkit' / 'p807-base-discovery.html',
    '/p691': PROJECT / 'probes' / 'phase13_webkit' / 'p691-walk-forge-fixed.html',
    '/p690': PROJECT / 'probes' / 'phase13_webkit' / 'p690-walk-forge-oracle.html',
    '/p689': PROJECT / 'probes' / 'phase13_webkit' / 'p689-walk-trigger-oracle.html',
    '/p688-full': PROJECT / 'probes' / 'phase13_webkit' / 'p688-freelist-exhaustion.html',
    '/p686': PROJECT / 'probes' / 'phase13_webkit' / 'p686-fontface-impl-bisect.html',
    '/p688': PROJECT / 'probes' / 'phase13_webkit' / 'p688-freelist-exhaustion.html',
    '/p688b': PROJECT / 'probes' / 'phase13_webkit' / 'p688b-freelist-exhaust-leak.html',
    '/p685': PROJECT / 'probes' / 'phase13_webkit' / 'p685-fontface-walk-dispatch.html',
    '/p684': PROJECT / 'probes' / 'phase13_webkit' / 'p684-canvas-ab-identify-reclaimer.html',
    '/p683': PROJECT / 'probes' / 'phase13_webkit' / 'p683-canvas-ab-property-sweep.html',
    '/p687': PROJECT / 'probes' / 'phase13_webkit' / 'p687-canvas-ab-safe-access.html',
    '/p681': PROJECT / 'probes' / 'phase13_webkit' / 'p681-canvas-ab-reclaim-arbread.html',
    '/p680': PROJECT / 'probes' / 'phase13_webkit' / 'p680-fontface-leak-canvas-read.html',
    '/p679': PROJECT / 'probes' / 'phase13_webkit' / 'p679-double-uaf-cross-type.html',
    '/p678': PROJECT / 'probes' / 'phase13_webkit' / 'p678-canvas-uaf-pattern-leak.html',
    '/p677': PROJECT / 'probes' / 'phase13_webkit' / 'p677-canvas-uaf-getimagedata-leak.html',
    '/p676': PROJECT / 'probes' / 'phase13_webkit' / 'p676-resizable-ab-heap-leak.html',
    '/p675': PROJECT / 'probes' / 'phase13_webkit' / 'p675-datalist-uaf-click.html',
    '/p674': PROJECT / 'probes' / 'phase13_webkit' / 'p674-multi-cve-safari26-27.html',
    '/p673': PROJECT / 'probes' / 'phase13_webkit' / 'p673-transformstream-type-confusion.html',
    '/p672': PROJECT / 'probes' / 'phase13_webkit' / 'p672-wasm-sab-feature-detect.html',
    '/p671': PROJECT / 'probes' / 'phase13_webkit' / 'p671-private-fields-seal-freeze.html',
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

MIME = {'.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.webp': 'image/webp'}

LOG_DIR = ROOT / 'beacon_logs'

# p686 census state: tracked server-side because a crash restart invalidates
# the stored T/impl (they are heap addresses of the dead process). The page
# polls /p686state BEFORE beaoning its own START; a pending START with no
# ALIVE since means the previous load died -> that load must re-prime.
P686_STATE = {'pendingArm': None, 'alive': False, 'armFrom': None,
                'mode': None}
# START records the arm and clears alive; ALIVE sets it. A query that finds a
# pending arm with alive still False is reporting that arm's load died.
# The page never advances the arm from the death report: an arm load stores
# its successor before it runs, and a dead prime is retried at the same label.
# Only the operator (GET /p686reset=1) clears the state.

# p688 freelist exhaustion state: simpler than p686 — no death detection
# needed for the base probe, but the page can request mode=reclaim via
# /p688reset=1&mode=reclaim to isolate freelist behavior.
P688_STATE = {'pendingArm': None, 'alive': False, 'armFrom': None,
                'mode': None}

# p689 walk-trigger oracle state: same shape as p686. A crash restart
# invalidates the leaked T/W pair (heap addresses of the dead process), so
# the page polls /p689state before beaconing its own START; a pending arm
# with alive still False means that arm's load died and the next load must
# re-prime.
P689_STATE = {'pendingArm': None, 'alive': False, 'armFrom': None,
                'mode': None}

P690_STATE = {'pendingArm': None, 'alive': False, 'armFrom': None,
                'mode': None}

P807_STATE = {
    'phase': 'idle',      # idle | coarse | fine | header | base-coarse | base-fine | base-scan | done
    'scanAddr': None,     # current scan address (int)
    'lastOk': None,       # last address that returned data (int)
    'lastCrash': None,    # last address that crashed (int)
    'vp': None,           # VP from walk chain (int)
    's2': None,           # s2 (lowest code addr) from walk chain (int)
    'base': None,         # discovered base address (int)
    'rva': None,          # VP - base once found (int)
    'step': 0x400000,     # current step size
    'done': False,
    'armed': None,        # address armed for current read
    'armDelta': None,     # VP - armed address (survives ASLR re-randomization)
    'okDelta': None,      # VP - lastOk (VP-relative, survives reboot)
    'crashDelta': None,   # VP - lastCrash (VP-relative)
    'boundary': None,     # VP - .text/.rodata boundary (VP-relative delta, set after header phase)
    'alive': False,       # reset on ARM, set on ALIVE
}


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


def _reset_requested(parsed, name):
    """Accept the documented path form and the operator query form exactly."""
    if parsed.path == "/" + name + "=1":
        return True
    return parse_qs(parsed.query).get(name) == ["1"]


def generate_self_signed(certfile, keyfile):
    if shutil.which('openssl') is None:
        _safe_print('openssl not found — provide --cert and --key manually', file=sys.stderr)
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

        if path == '/p686state':
            died = (not P686_STATE['alive']) and P686_STATE['pendingArm'] is not None
            body = json.dumps({'died': died, 'deadArm': P686_STATE['pendingArm'],
                               'armFrom': P686_STATE['armFrom'],
                               'mode': P686_STATE['mode']}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            return

        # p686 operator reset: GET /p686reset=1 clears the census state, so a
        # new campaign can start without touching the console. The page calls
        # it once at its load cap, together with its own localStorage reset.
        if _reset_requested(parsed, 'p686reset'):
            qs = parse_qs(parsed.query)
            P686_STATE['pendingArm'] = None
            P686_STATE['alive'] = False
            # Operator rewind: `&arm=N` forces the next page load to restart
            # the arm series at index N; `&arm=clear` drops the override. The
            # page consumes it once and then clears it itself.
            if 'arm' in qs:
                raw = qs['arm'][0]
                if raw == 'clear':
                    P686_STATE['armFrom'] = None
                else:
                    try:
                        P686_STATE['armFrom'] = int(raw, 0)
                    except ValueError:
                        pass
            if 'mode' in qs:
                P686_STATE['mode'] = qs['mode'][0]
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', 2)
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(b'OK')
            return

        # p688 freelist exhaustion state: GET /p688state
        if path == '/p688state':
            died = (not P688_STATE['alive']) and P688_STATE['pendingArm'] is not None
            body = json.dumps({'died': died, 'deadArm': P688_STATE['pendingArm'],
                               'armFrom': P688_STATE['armFrom'],
                               'mode': P688_STATE['mode']}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            return

        # p688 operator reset: GET /p688reset=1
        if _reset_requested(parsed, 'p688reset'):
            qs = parse_qs(parsed.query)
            P688_STATE['pendingArm'] = None
            P688_STATE['alive'] = False
            if 'arm' in qs:
                raw = qs['arm'][0]
                if raw == 'clear':
                    P688_STATE['armFrom'] = None
                else:
                    try:
                        P688_STATE['armFrom'] = int(raw, 0)
                    except ValueError:
                        pass
            if 'mode' in qs:
                P688_STATE['mode'] = qs['mode'][0]
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', 2)
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(b'OK')
            return

        # p689 walk-trigger oracle state: GET /p689state
        if path == '/p689state':
            died = (not P689_STATE['alive']) and P689_STATE['pendingArm'] is not None
            body = json.dumps({'died': died, 'deadArm': P689_STATE['pendingArm'],
                               'armFrom': P689_STATE['armFrom'],
                               'mode': P689_STATE['mode']}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            return

        # p689 operator reset / rewind: GET /p689reset=1[&arm=N|&arm=clear]
        if _reset_requested(parsed, 'p689reset'):
            qs = parse_qs(parsed.query)
            P689_STATE['pendingArm'] = None
            P689_STATE['alive'] = False
            if 'arm' in qs:
                raw = qs['arm'][0]
                if raw == 'clear':
                    P689_STATE['armFrom'] = None
                else:
                    try:
                        P689_STATE['armFrom'] = int(raw, 0)
                    except ValueError:
                        pass
            if 'mode' in qs:
                P689_STATE['mode'] = qs['mode'][0]
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', 2)
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(b'OK')
            return

        # p690 walk-forge-oracle state: GET /p690state
        if path == '/p690state':
            died = (not P690_STATE['alive']) and P690_STATE['pendingArm'] is not None
            body = json.dumps({'died': died, 'deadArm': P690_STATE['pendingArm'],
                               'armFrom': P690_STATE['armFrom'],
                               'mode': P690_STATE['mode']}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            return

        # p690 operator reset: GET /p690reset=1
        if _reset_requested(parsed, 'p690reset'):
            qs = parse_qs(parsed.query)
            P690_STATE['pendingArm'] = None
            P690_STATE['alive'] = False
            if 'arm' in qs:
                raw = qs['arm'][0]
                if raw == 'clear':
                    P690_STATE['armFrom'] = None
                else:
                    try:
                        P690_STATE['armFrom'] = int(raw, 0)
                    except ValueError:
                        pass
            if 'mode' in qs:
                P690_STATE['mode'] = qs['mode'][0]
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', 2)
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(b'OK')
            return

        # p807 base discovery state: GET /p807state (also /p710state for compat)
        if path in ('/p807state', '/p710state'):
            died = (P807_STATE['armed'] is not None and not P807_STATE['alive']
                    and P807_STATE['phase'] != 'idle')
            body = json.dumps({
                'phase': P807_STATE['phase'],
                'scanAddr': hex(P807_STATE['scanAddr']) if P807_STATE['scanAddr'] is not None else None,
                'lastOk': hex(P807_STATE['lastOk']) if P807_STATE['lastOk'] is not None else None,
                'lastCrash': hex(P807_STATE['lastCrash']) if P807_STATE['lastCrash'] is not None else None,
                'vp': hex(P807_STATE['vp']) if P807_STATE['vp'] is not None else None,
                's2': hex(P807_STATE['s2']) if P807_STATE['s2'] is not None else None,
                'base': hex(P807_STATE['base']) if P807_STATE['base'] is not None else None,
                'rva': hex(P807_STATE['rva']) if P807_STATE['rva'] is not None else None,
                'step': P807_STATE['step'],
                'done': P807_STATE['done'],
                'died': died,
                'deadArm': hex(P807_STATE['armed']) if died and P807_STATE['armed'] is not None else None,
                'armDelta': P807_STATE['armDelta'],
                'okDelta': P807_STATE['okDelta'],
                'crashDelta': P807_STATE['crashDelta'],
                'boundary': P807_STATE['boundary'],
            }).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            return

        # p807 reset: GET /p807reset (also /p710reset for compat)
        if path in ('/p807reset', '/p710reset'):
            P807_STATE.update({'phase': 'idle', 'scanAddr': None, 'lastOk': None,
                'lastCrash': None, 'vp': None, 's2': None, 'base': None,
                'rva': None, 'step': 0x400000, 'done': False, 'armed': None,
                'armDelta': None, 'okDelta': None, 'crashDelta': None,
                'boundary': None, 'alive': False})
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', 2)
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(b'OK')
            return

        if path == '/beacon' or path.startswith('/beacon/'):
            if path == '/beacon':
                qs = parse_qs(parsed.query)
                msg = qs.get('m', [''])[0]
            else:
                from urllib.parse import unquote
                msg = unquote(path[len('/beacon/'):])
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
        try:
            if msg.startswith('P686-START'):
                m = re.search(r'arm=(-?\d+)', msg)
                P686_STATE['pendingArm'] = int(m.group(1)) if m else None
                P686_STATE['alive'] = False
            elif msg.startswith('P686-ALIVE'):
                P686_STATE['alive'] = True
            elif msg.startswith('P688-START'):
                m = re.search(r'arm=(-?\d+)', msg)
                P688_STATE['pendingArm'] = int(m.group(1)) if m else None
                P688_STATE['alive'] = False
            elif msg.startswith('P688-ALIVE'):
                P688_STATE['alive'] = True
            elif msg.startswith('P689-START'):
                m = re.search(r'arm=(-?\d+)', msg)
                P689_STATE['pendingArm'] = int(m.group(1)) if m else None
                P689_STATE['alive'] = False
            elif msg.startswith('P689-ALIVE'):
                P689_STATE['alive'] = True
            elif msg.startswith('P690-START'):
                m = re.search(r'arm=(-?\d+)', msg)
                P690_STATE['pendingArm'] = int(m.group(1)) if m else None
                P690_STATE['alive'] = False
            elif msg.startswith('P690-ALIVE'):
                P690_STATE['alive'] = True
            elif msg.startswith('P807-ARM-'):
                if P807_STATE['armed'] is not None and not P807_STATE['alive']:
                    P807_STATE['lastCrash'] = P807_STATE['armed']
                m = re.search(r'addr=(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['armed'] = int(m.group(1), 16)
                    P807_STATE['alive'] = False
            elif msg.startswith('P807-ALIVE'):
                P807_STATE['alive'] = True
            elif msg.startswith('P807-READ-'):
                m = re.search(r'addr=(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['lastOk'] = int(m.group(1), 16)
                    P807_STATE['alive'] = True
            elif msg.startswith('P807-VP-'):
                m = re.search(r'VP=(0x[0-9a-fA-F]+),s2=(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['vp'] = int(m.group(1), 16)
                    P807_STATE['s2'] = int(m.group(2), 16)
            elif msg.startswith('P807-PHASE-'):
                m = re.search(r'PHASE-([\w-]+)', msg)
                if m:
                    P807_STATE['phase'] = m.group(1)
            elif msg.startswith('P807-BASE-'):
                m = re.search(r'BASE-(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['base'] = int(m.group(1), 16)
                    P807_STATE['done'] = True
                    P807_STATE['phase'] = 'done'
            elif msg.startswith('P807-STEP-'):
                m = re.search(r'STEP-(\d+)', msg)
                if m:
                    P807_STATE['step'] = int(m.group(1))
            elif msg.startswith('P807-SCAN-'):
                m = re.search(r'SCAN-(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['scanAddr'] = int(m.group(1), 16)
            elif msg.startswith('P807-LASTCRASH-'):
                m = re.search(r'LASTCRASH-(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['lastCrash'] = int(m.group(1), 16)
            elif msg.startswith('P807-OKDELTA-'):
                m = re.search(r'OKDELTA-(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['okDelta'] = int(m.group(1), 16)
            elif msg.startswith('P807-CRASHDELTA-'):
                m = re.search(r'CRASHDELTA-(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['crashDelta'] = int(m.group(1), 16)
            elif msg.startswith('P807-ARMDELTA-'):
                m = re.search(r'ARMDELTA-(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['armDelta'] = int(m.group(1), 16)
            elif msg.startswith('P807-BSAVE-'):
                m = re.search(r'BSAVE-(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['boundary'] = int(m.group(1), 16)
            elif msg.startswith('P807-RVA-'):
                m = re.search(r'RVA-(0x[0-9a-fA-F]+)', msg)
                if m:
                    P807_STATE['rva'] = int(m.group(1), 16)
        except Exception:
            pass
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
    args = parser.parse_args()
    try:
        run(args)
    except KeyboardInterrupt:
        _safe_print('Interrupted: retained capture is unclosed; delivery remains UNKNOWN.')
        return 130
    return 0


if __name__ == '__main__':
    sys.exit(main())
