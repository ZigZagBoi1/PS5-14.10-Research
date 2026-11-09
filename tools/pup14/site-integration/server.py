"""Bounded local browser diagnostics and append-only telemetry; Python stdlib only."""
import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
MAX_BODY = 32768
RATE_LIMIT = 240
MAX_RELAPSE_LOG_LINES = 500
MAX_DUMP_FILE_BYTES = 679 * 48
DUMP_FILE_SIZES = {'kernel_base.json': 256, 'sysent_raw.bin': MAX_DUMP_FILE_BYTES}
SYSENT_RVA = 0xE6E5C0
HV_PAYLOAD_SHA256 = '0c43dcd8a6119726f7245b45bca6b5c227ad4b4aeeadb6fa3a22e3f82448533f'
HV_PAYLOAD_BYTES = 177256
HV_UPSTREAM_COMMIT = 'ea04f7132b837087f552c57261cb800481a3a910'
HV_READY_TTL = 600
PUP_SOURCE_SHA256 = '9f3a0b8811c00ab52b092d2e9f0f13dd4515f018361ff38e4be43fd8c18b21de'
PUP_SOURCE_BYTES = 1418890240
PUP_LAN_ELF_SHA256 = 'e94b04204021cf6e2c97f85d1523c1bde50e84c7e8885964e66f5610812c8994'
RELAPSE_START = 'Start Relapse selected'
RELAPSE_READY = 'Relapse cleanup complete; HV delivery ready.'
EVENTS = {'run_start', 'test_started', 'test_result', 'checkpoint_ack', 'heartbeat', 'javascript_error', 'run_completed', 'run_failed', 'page_hidden'}
TERMINAL = {'run_completed', 'run_failed'}
SUITES = {
    'messaging': {'experiment': 'browser-messaging', 'revision': 'messaging-001', 'test_ids': ['worker_messaging']},
    'context': {'experiment': 'browser-context', 'revision': 'context-001', 'test_ids': ['worker_context']},
    'baseline': {'experiment': 'browser-baseline', 'revision': 'baseline-002',
                 'test_ids': ['environment', 'api_presence', 'typedarray_dataview', 'bounded_allocation', 'exceptions', 'bigint', 'structured_clone', 'wasm_presence', 'network_health', 'timing']},
    'phase2': {'experiment': 'browser-phase2', 'revision': 'phase2-001',
               'test_ids': ['js_compatibility', 'buffer_views', 'wasm_diagnostics', 'microtask_order', 'error_propagation', 'clock_precision', 'http_repeats', 'webkit_api_matrix']},
    'ssvprobe': {'experiment': 'browser-ssvprobe', 'revision': 'ssvprobe-002',
                 'test_ids': ['ssv_history_basic', 'ssv_duplicate_ref', 'ssv_bigint_below_boundary', 'ssv_bigint_at_boundary', 'ssv_bigint_above_boundary', 'ssv_canary_after_probe']},
    'transformstream_feature': {'experiment': 'browser-transformstream-feature', 'revision': 'ts-feature-001',
                                'test_ids': ['transformstream_exposure']},
    'transformstream_regression': {'experiment': 'browser-transformstream-regression', 'revision': 'ts-regression-001',
                                   'test_ids': ['transformstream_plain_object']},
    'datalist_uaf_probe': {'experiment': 'webkit-datalist-lifetime', 'revision': 'datalist-lifetime-001',
                           'test_ids': ['datalist_button_type_change']},
}

def stamp():
    return datetime.now(timezone.utc).isoformat()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def validate_event(value):
    if not isinstance(value, dict) or set(value) != {'run_id', 'seq', 'event', 'details', 'client_time'}:
        raise ValueError('Event fields do not match schema')
    if not isinstance(value['run_id'], str) or not re.fullmatch(r'[a-f0-9-]{36}', value['run_id']):
        raise ValueError('Invalid run ID')
    if type(value['seq']) is not int or not 1 <= value['seq'] <= 1000:
        raise ValueError('Invalid sequence')
    if not isinstance(value['event'], str) or value['event'] not in EVENTS:
        raise ValueError('Invalid event name')
    if not isinstance(value['details'], dict):
        raise ValueError('Details must be an object')
    if not isinstance(value['client_time'], str):
        raise ValueError('Invalid timestamp')
    dt = datetime.fromisoformat(value['client_time'].replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    canonical(value)  # Reject NaN/infinity and non-serializable input.
    if value['event'] == 'test_result':
        d = value['details']
        if not isinstance(d.get('id'), str) or len(d['id']) > 100 or d.get('status') not in {'PASS', 'FAIL', 'UNSUPPORTED', 'SKIPPED', 'UNEXPECTED_RESULT', 'EXCEPTION', 'TIMEOUT'}:
            raise ValueError('Invalid test result')
        if type(d.get('elapsed_ms')) not in (int, float) or not 0 <= d['elapsed_ms'] <= 60000:
            raise ValueError('Invalid duration')
    return value

def validate_relapse_diagnostics(value):
    if not isinstance(value, dict) or set(value) != {'session_id', 'firmware', 'lines'}:
        raise ValueError('Diagnostic fields do not match schema')
    session_id = value['session_id']
    try:
        if not isinstance(session_id, str) or str(uuid.UUID(session_id)) != session_id:
            raise ValueError('Invalid session ID')
    except (ValueError, AttributeError):
        raise ValueError('Invalid session ID')
    firmware = value['firmware']
    if not isinstance(firmware, str) or len(firmware) > 32 or not re.fullmatch(r'[0-9]+\.[0-9]{1,2}|unknown', firmware):
        raise ValueError('Invalid firmware label')
    lines = value['lines']
    if not isinstance(lines, list) or not 1 <= len(lines) <= 20:
        raise ValueError('Diagnostic batch must contain 1..20 lines')

    validated = []
    for line in lines:
        if not isinstance(line, dict) or set(line) != {'seq', 'level', 'message', 'client_time'}:
            raise ValueError('Diagnostic line fields do not match schema')
        seq = line['seq']
        if type(seq) is not int or not 1 <= seq <= MAX_RELAPSE_LOG_LINES:
            raise ValueError('Invalid diagnostic sequence')
        level = line['level']
        if level not in {'info', 'success', 'error', 'log'}:
            raise ValueError('Invalid diagnostic level')
        message = line['message']
        if not isinstance(message, str) or not message or len(message) > 800:
            raise ValueError('Invalid diagnostic message')
        message = re.sub(r'\b0x[0-9a-f]{6,16}\b', '0x[redacted]', message, flags=re.IGNORECASE)
        message = ''.join(ch for ch in message if ch in '\t' or ord(ch) >= 0x20)[:800]
        client_time = line['client_time']
        if not isinstance(client_time, str) or len(client_time) > 64:
            raise ValueError('Invalid client timestamp')
        dt = datetime.fromisoformat(client_time.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError('Client timestamp must include timezone')
        validated.append({'seq': seq, 'level': level, 'message': message, 'client_time': client_time})

    if any(validated[i]['seq'] + 1 != validated[i + 1]['seq'] for i in range(len(validated) - 1)):
        raise ValueError('Diagnostic sequences must be consecutive')
    return session_id, firmware, validated

def source_version():
    files = {}
    for directory in ('server', 'web', 'experiments', 'dashboard'):
        for path in sorted((ROOT / directory).rglob('*')):
            if path.is_file() and path.suffix in ('.py', '.js', '.html', '.css', '.json', '.elf', '.bin') and '__pycache__' not in path.parts:
                files[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'revision': 'hosting-audit-008', 'source_sha256': hashlib.sha256(canonical(files)).hexdigest(), 'files': files, 'git_commit': None, 'git_note': 'Source hashes include the served Relapse integration, offsets, and loader payloads.'}

def summarize(meta, events):
    end = next((e for e in reversed(events) if e['event'] in TERMINAL), None)
    last = events[-1] if events else None
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(last['received_at_utc'] if last else meta['created_at_utc'])).total_seconds()
    confirmed = [e['details'].get('ack_seq') for e in events if e['event'] == 'checkpoint_ack']
    checkpoints = [e for e in events if e['event'] not in {'heartbeat', 'checkpoint_ack', 'page_hidden'}]
    terminal_details = end['details'] if end else None
    return dict(meta, outcome=('completed_browser_suite' if end and end['event'] == 'run_completed' else 'browser_reported_failure' if end else 'incomplete_unknown' if age > 15 else 'active_or_pending'),
                evidence_kind='browser_reported_observation', hardware_verified=False,
                last_stored_checkpoint=checkpoints[-1]['seq'] if checkpoints else None,
                last_client_confirmed_checkpoint=confirmed[-1] if confirmed else None,
                heartbeat_age_seconds=round(age, 2),
                server_duration_ms=round((datetime.fromisoformat(end['received_at_utc']) - datetime.fromisoformat(meta['created_at_utc'])).total_seconds() * 1000, 2) if end else None,
                results=[e['details'] for e in events if e['event'] == 'test_result'],
                terminal_event_details=terminal_details,
                probe_classification=terminal_details.get('classification') if meta.get('suite') == 'datalist_uaf_probe' and isinstance(terminal_details, dict) else None,
                probe_observation=terminal_details.get('raw_observation') if meta.get('suite') == 'datalist_uaf_probe' and isinstance(terminal_details, dict) else None,
                caveat='Missing telemetry does not distinguish navigation, connectivity loss, hang or crash. Browser tests do not demonstrate privileged execution.')

class Collector(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, data_dir, rate_limit=RATE_LIMIT, public_origin=None, dashboard_key=None):
        self.data_dir = Path(data_dir)
        (self.data_dir / 'runs').mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.tokens = {}
        self.rates = {}
        self.rate_limit = rate_limit
        self.public_origin = public_origin
        self.dashboard_key = dashboard_key
        # The diagnostics quota covers telemetry, not the separately stored PUP
        # source or decrypted PUP output (each can exceed this quota alone).
        self.storage_bytes = sum(
            p.stat().st_size
            for name in ('runs', 'relapse-diagnostics', 'dumps')
            for p in (self.data_dir / name).rglob('*') if p.is_file()
        )
        self.max_storage_bytes = 128 * 1024 * 1024
        self.relapse_diagnostics_dir = self.data_dir / 'relapse-diagnostics'
        self.relapse_diagnostics_dir.mkdir(parents=True, exist_ok=True)
        self.dumps_dir = self.data_dir / 'dumps'
        self.dumps_dir.mkdir(parents=True, exist_ok=True)
        self.dump_sessions = {}
        self.relapse_last_seq = {}
        self.relapse_digests = {}
        self.relapse_runs = {}
        self.hv_inflight = set()
        self.workers = threading.BoundedSemaphore(16)
        self.version = source_version()
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.workers.release()

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(8)
        return sock, addr

    def run_data(self, run_id):
        if not re.fullmatch(r'[a-f0-9-]{36}', run_id):
            raise ValueError('Invalid run ID')
        folder = self.data_dir / 'runs' / run_id
        meta = json.loads((folder / 'metadata.json').read_text(encoding='utf-8'))
        events = [json.loads(line) for line in (folder / 'events.jsonl').read_text(encoding='utf-8').splitlines() if line] if (folder / 'events.jsonl').exists() else []
        return meta, events

    def observe_relapse(self, target, session_id, firmware, lines):
        """Called under lock, only after new diagnostic lines are durable.

        This is browser-reported workflow state, not a kernel/HV attestation.
        Server restarts deliberately require a new completed Relapse run.
        """
        if firmware != '13.60':
            return
        for line in lines:
            if line['message'] == RELAPSE_START:
                self.relapse_runs[target] = {'session_id': session_id, 'ready_at': None, 'transfer_state': None}
            run = self.relapse_runs.get(target)
            if run and run['session_id'] == session_id and line['message'] == RELAPSE_READY:
                run['ready_at'] = time.monotonic()

    def current_relapse(self, target):
        """Caller holds lock; readiness is short-lived and tied to the console IP."""
        run = self.relapse_runs.get(target)
        if not run or run['ready_at'] is None or time.monotonic() - run['ready_at'] > HV_READY_TTL:
            return None
        return run

class Handler(BaseHTTPRequestHandler):
    server_version = 'PS5Research/0.2'
    def log_message(self, fmt, *args):
        # Do not print authorization tokens or query strings.
        print(stamp(), self.client_address[0], fmt % args)

    def route(self):
        path = urlsplit(self.path).path
        return path[4:] or '/' if path == '/ps5' or path.startswith('/ps5/') else path

    def send_bytes(self, status, data, mime, allow_same_origin_frame=False):
        self.send_response(status)
        frame_policy = "'self'" if allow_same_origin_frame else "'none'"
        x_frame_options = 'SAMEORIGIN' if allow_same_origin_frame else 'DENY'
        for key, value in {'Content-Type': mime, 'Content-Length': str(len(data)), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': x_frame_options, 'Content-Security-Policy': f"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors {frame_policy}"}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def respond(self, status, obj):
        if status >= 400 and self.command == 'POST' and not getattr(self, '_body_consumed', False):
            # Drain bounded rejected bodies before closing so Windows does not reset
            # the socket and discard the error response due to unread request data.
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if 0 < length <= MAX_BODY * 2:
                    self.rfile.read(length)
            except (ValueError, OSError):
                pass
            self.close_connection = True
        self.send_bytes(status, canonical(obj), 'application/json; charset=utf-8')

    def origin_allowed(self):
        host = self.headers.get('Host', '')
        if self.server.public_origin:
            parsed = urlsplit(self.server.public_origin)
            if host == parsed.netloc and self.client_address[0] == '127.0.0.1':
                origin = self.headers.get('Origin')
                return not origin or origin == self.server.public_origin
        port = self.server.server_port
        allowed = {f'127.0.0.1:{port}', f'localhost:{port}', f'{self.server.server_address[0]}:{port}'}
        if host not in allowed:
            return False
        origin = self.headers.get('Origin')
        return not origin or origin == 'http://' + host

    def dashboard_allowed(self):
        if self.server.dashboard_key is None:
            return True
        return secrets.compare_digest(self.headers.get('X-Dashboard-Key', ''), self.server.dashboard_key)

    def client_ip(self):
        if self.server.public_origin and self.client_address[0] == '127.0.0.1':
            try:
                return str(ipaddress.ip_address(self.headers.get('X-Real-IP', '')))
            except ValueError:
                pass
        return self.client_address[0]

    def hv_client(self, require_origin=True):
        """Restrict HV requests to a LAN PS5 reporting firmware 13.60."""
        origin = self.headers.get('Origin')
        if (not self.server.public_origin or (origin and origin != self.server.public_origin)
                or (require_origin and origin != self.server.public_origin)):
            return None
        user_agent = self.headers.get('User-Agent', '')
        if not user_agent.startswith('Mozilla/5.0 (PlayStation; PlayStation 5/13.60)'):
            return None
        try:
            address = ipaddress.ip_address(self.client_ip())
        except ValueError:
            return None
        if address not in ipaddress.ip_network('10.0.0.0/24') or address == ipaddress.ip_address('10.0.0.80'):
            return None
        return str(address)

    def relapse_diagnostics_client(self):
        """Accept automatic Relapse logs only from a PS5 on the home LAN."""
        origin = self.headers.get('Origin')
        if self.server.public_origin and origin != self.server.public_origin:
            return None
        user_agent = self.headers.get('User-Agent', '')
        if not user_agent.startswith('Mozilla/5.0 (PlayStation; PlayStation 5/'):
            return None
        try:
            address = ipaddress.ip_address(self.client_ip())
        except ValueError:
            return None
        if address not in ipaddress.ip_network('10.0.0.0/24') or address == ipaddress.ip_address('10.0.0.80'):
            return None
        return str(address)

    def dump_session(self, create=False):
        target = self.relapse_diagnostics_client()
        session_id = self.headers.get('X-Session')
        if not target or not session_id:
            return None, None
        try:
            if str(uuid.UUID(session_id)) != session_id:
                return None, None
        except (ValueError, AttributeError):
            return None, None
        if create:
            self.server.dump_sessions.setdefault(session_id, {'target': target, 'chunks': {}, 'created': time.monotonic()})
        item = self.server.dump_sessions.get(session_id)
        return (session_id, item) if item and item['target'] == target else (None, None)

    def receive_dump(self):
        session_id, session = self.dump_session(create=True)
        if not session:
            return self.respond(403, {'error': 'Dump receiver is restricted to the current PS5 Relapse session.'})
        filename = self.headers.get('X-Filename', '')
        if filename not in DUMP_FILE_SIZES:
            return self.respond(400, {'error': 'Unsupported dump file.'})
        if self.headers.get('Content-Encoding') or self.headers.get('Transfer-Encoding'):
            return self.respond(400, {'error': 'Encoded request bodies are not accepted.'})
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            length = -1
        chunk = self.headers.get('X-Chunk')
        if filename == 'sysent_raw.bin':
            match = re.fullmatch(r'([1-8])/8', chunk or '')
            if not match:
                return self.respond(400, {'error': 'Sysent chunks must be numbered 1/8 through 8/8.'})
            index = int(match.group(1))
            expected = 4096 if index < 8 else MAX_DUMP_FILE_BYTES - 4096 * 7
            if length != expected:
                return self.respond(400, {'error': 'Sysent chunk size is invalid.'})
        elif chunk is not None or not 0 < length <= DUMP_FILE_SIZES[filename]:
            return self.respond(400, {'error': 'Kernel-base file size or headers are invalid.'})
        self._body_consumed = True
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError('Truncated dump body')
        if filename == 'kernel_base.json':
            value = json.loads(body.decode('utf-8'))
            if (not isinstance(value, dict) or value.get('firmware') != '13.60'
                    or not re.fullmatch(r'0x[0-9a-fA-F]{1,16}', str(value.get('kernel_base', '')))):
                raise ValueError('Kernel base metadata is invalid')
            body = canonical({'firmware': '13.60', 'kernel_base': value['kernel_base']})
            if len(body) > DUMP_FILE_SIZES[filename]:
                raise ValueError('Kernel base metadata is too large')
        with self.server.lock:
            directory = self.server.dumps_dir / session_id
            directory.mkdir(parents=True, exist_ok=True)
            if filename == 'kernel_base.json':
                if self.server.storage_bytes + len(body) > self.server.max_storage_bytes:
                    return self.respond(507, {'error': 'Dump storage budget reached.'})
                path = directory / filename
                if path.exists():
                    return self.respond(409, {'error': 'Kernel base was already saved for this session.'})
                path.write_bytes(body)
                self.server.storage_bytes += len(body)
            else:
                index = int(chunk.split('/')[0])
                previous = session['chunks'].get(index)
                if previous is not None:
                    if previous != body:
                        return self.respond(409, {'error': 'This chunk number already has different content.'})
                    return self.respond(200, {'ok': True, 'duplicate': True, 'session_id': session_id})
                if self.server.storage_bytes + len(body) > self.server.max_storage_bytes:
                    return self.respond(507, {'error': 'Dump storage budget reached.'})
                session['chunks'][index] = body
                self.server.storage_bytes += len(body)
                if len(session['chunks']) == 8:
                    raw = b''.join(session['chunks'][i] for i in range(1, 9))
                    if len(raw) != MAX_DUMP_FILE_BYTES:
                        raise ValueError('Assembled sysent size is invalid')
                    base_value = json.loads((directory / 'kernel_base.json').read_text(encoding='utf-8'))['kernel_base']
                    base = int(base_value, 16)
                    entries = []
                    for syscall_num in range(679):
                        offset = syscall_num * 48
                        narg = int.from_bytes(raw[offset:offset + 4], 'little')
                        call = int.from_bytes(raw[offset + 8:offset + 16], 'little')
                        entries.append({'num': syscall_num, 'narg': narg,
                                        'sy_call': f'0x{call:x}',
                                        'sy_call_off': f'0x{call - base:x}' if call else '0x0'})
                    index_data = canonical({'firmware': '13.60', 'kernel_base': base_value,
                                            'sysent_rva': hex(SYSENT_RVA), 'entries': entries})
                    if self.server.storage_bytes + len(raw) + len(index_data) > self.server.max_storage_bytes:
                        del session['chunks'][index]
                        self.server.storage_bytes -= len(body)
                        return self.respond(507, {'error': 'Dump storage budget reached.'})
                    (directory / filename).write_bytes(raw)
                    (directory / 'sysent_index.json').write_bytes(index_data)
                    self.server.storage_bytes += len(raw) + len(index_data)
        return self.respond(200, {'ok': True, 'session_id': session_id, 'file': filename,
                                  'received_chunks': len(session['chunks']), 'complete': len(session['chunks']) == 8})

    def dump_status(self, session_id):
        target = self.relapse_diagnostics_client()
        if not target or not session_id or not re.fullmatch(r'[a-f0-9-]{36}', session_id):
            return self.respond(403, {'error': 'Dump status is restricted to the current PS5 session.'})
        with self.server.lock:
            session = self.server.dump_sessions.get(session_id)
            if not session or session['target'] != target:
                return self.respond(404, {'error': 'Unknown dump session.'})
            folder = self.server.dumps_dir / session_id
            files = [{'name': path.name, 'bytes': path.stat().st_size} for path in sorted(folder.iterdir()) if path.is_file()]
        complete = any(item['name'] == 'sysent_index.json' for item in files)
        return self.respond(200, {'session_id': session_id, 'complete': complete, 'files': files})

    def download_dump(self, session_id, filename):
        target = self.relapse_diagnostics_client()
        if not target or not re.fullmatch(r'[a-f0-9-]{36}', session_id or '') or filename not in {'kernel_base.json', 'sysent_raw.bin', 'sysent_index.json'}:
            return self.respond(403, {'error': 'Dump download is restricted to the current PS5 session.'})
        with self.server.lock:
            session = self.server.dump_sessions.get(session_id)
            path = self.server.dumps_dir / session_id / filename
            if not session or session['target'] != target or not path.is_file():
                return self.respond(404, {'error': 'Dump file is not ready.'})
            data = path.read_bytes()
        self.send_bytes(200, data, 'application/octet-stream' if filename.endswith('.bin') else 'application/json; charset=utf-8')

    def store_relapse_diagnostics(self, value):
        target = self.relapse_diagnostics_client()
        if not target:
            return self.respond(403, {'error': 'Relapse diagnostics are accepted only from a PS5 on the local network.'})
        session_id, firmware, lines = validate_relapse_diagnostics(value)
        path = self.server.relapse_diagnostics_dir / f'{session_id}.jsonl'

        with self.server.lock:
            last_seq = self.server.relapse_last_seq.get(session_id, 0)
            known = self.server.relapse_digests.setdefault(session_id, {})
            additions = []
            added_lines = []
            new_digests = {}
            for line in lines:
                normalized = dict(line, session_id=session_id, firmware=firmware)
                digest = hashlib.sha256(canonical(normalized)).hexdigest()
                if line['seq'] <= last_seq:
                    if known.get(line['seq']) != digest:
                        return self.respond(409, {'error': 'Diagnostic sequence was already stored with different content.'})
                    continue
                if line['seq'] != last_seq + 1:
                    return self.respond(409, {'error': 'Diagnostic sequence is out of order.'})
                entry = dict(normalized, client_ip=target, received_at_utc=stamp())
                additions.append(canonical(entry) + b'\n')
                added_lines.append(line)
                new_digests[line['seq']] = digest
                last_seq = line['seq']

            byte_count = sum(map(len, additions))
            if self.server.storage_bytes + byte_count > self.server.max_storage_bytes:
                return self.respond(507, {'error': 'Server diagnostics storage budget reached.'})
            if additions:
                with path.open('ab') as output:
                    for encoded in additions:
                        output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
                self.server.storage_bytes += byte_count
                self.server.relapse_last_seq[session_id] = last_seq
                known.update(new_digests)
                self.server.observe_relapse(target, session_id, firmware, added_lines)

        return self.respond(200, {'ok': True, 'session_id': session_id, 'received': len(lines)})

    def hv_payload(self):
        return ROOT / 'private' / 'hv' / 'byepervisor_reborn.elf'

    def verified_hv_payload(self):
        payload = self.hv_payload().read_bytes()
        if len(payload) != HV_PAYLOAD_BYTES or hashlib.sha256(payload).hexdigest() != HV_PAYLOAD_SHA256:
            raise ValueError('HV payload does not match the pinned 13.60 build')
        return payload

    def send_hv_payload(self, value):
        target = self.hv_client()
        if not target:
            return self.respond(403, {'error': 'The HV sender is available only from a PS5 on the local network.'})
        if (not isinstance(value, dict) or set(value) != {'firmware', 'elfldr_ready', 'relapse_session_id'}
                or value.get('firmware') != '13.60' or value.get('elfldr_ready') is not True
                or not isinstance(value.get('relapse_session_id'), str)):
            return self.respond(400, {'error': 'A completed 13.60 Relapse session is required before HV delivery.'})

        try:
            payload = self.verified_hv_payload()
        except (OSError, ValueError):
            return self.respond(503, {'error': 'The server HV payload is missing or does not match the pinned 13.60 build.'})
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        if source_version() != self.server.version:
            return self.respond(409, {'error': 'Hosting files changed after server startup. Finish deployment and restart the service before a new console session.'})

        with self.server.lock:
            run = self.server.current_relapse(target)
            if not run or run['session_id'] != value['relapse_session_id']:
                return self.respond(409, {'error': 'Relapse completion is missing, expired, or belongs to another console session.'})
            if run['transfer_state'] or target in self.server.hv_inflight:
                return self.respond(409, {'error': 'An HV delivery was already attempted. Check the console and restart it before a new chain.'})
            # Consume readiness BEFORE connecting. An uncertain/partial send
            # must never be automatically replayed into the same console state.
            run['transfer_state'] = 'sending'
            self.server.hv_inflight.add(target)

        try:
            with socket.create_connection((target, 9021), timeout=5) as console:
                console.settimeout(10)
                console.sendall(payload)
                console.shutdown(socket.SHUT_WR)
        except OSError as exc:
            with self.server.lock:
                run['transfer_state'] = 'uncertain'
            print(f'[HV] delivery uncertain target={target} session={run["session_id"]} code={type(exc).__name__}', flush=True)
            return self.respond(502, {'error': 'HV delivery is uncertain. Check the console; restart it before a new chain. This session remains locked.', 'delivery_uncertain': True})
        finally:
            with self.server.lock:
                self.server.hv_inflight.discard(target)

        with self.server.lock:
            run['transfer_state'] = 'sent'

        print(f'[HV] payload sent target={target} session={run["session_id"]} bytes={len(payload)} sha256={payload_sha256}', flush=True)
        return self.respond(200, {'sent': True, 'firmware': '13.60', 'target': target, 'port': 9021,
                                  'bytes_sent': len(payload), 'sha256': payload_sha256,
                                  'hv_confirmed': False,
                                  'message': 'The payload was sent to the ELF loader. Follow the Byepervisor instructions shown on the PS5; this does not confirm the HV bypass.'})

    def verified_etahen_payload(self):
        payload = (ROOT / 'private' / 'etahen' / 'etaHEN.elf').read_bytes()
        if len(payload) != 36746616 or hashlib.sha256(payload).hexdigest() != '46c161473b27d12f1fa5e2d1d10466ce587db841ed9e8d71a219424d8fcf637f':
            raise ValueError('etaHEN payload does not match the pinned build')
        return payload

    def send_pup_payload(self, value):
        target = self.hv_client()
        if not target:
            return self.respond(403, {'error': 'PUP research delivery is available only from a 13.60 PS5 on the local network.'})
        if (not isinstance(value, dict) or set(value) != {'firmware', 'elfldr_ready', 'relapse_session_id'}
                or value.get('firmware') != '13.60' or value.get('elfldr_ready') is not True
                or not isinstance(value.get('relapse_session_id'), str)):
            return self.respond(400, {'error': 'A completed 13.60 Relapse session is required.'})
        payload_path = ROOT / 'private' / 'pup14' / 'PS5_1410_RESEARCH_LAN.elf'
        pup_path = self.server.data_dir / 'pup-source' / 'PS5UPDATE_14.10_RECOVERY.PUP'
        unpacker = ROOT / 'private' / 'pup14' / 'pup_unpacker_linux'
        try:
            payload = payload_path.read_bytes()
            if hashlib.sha256(payload).hexdigest() != PUP_LAN_ELF_SHA256:
                raise ValueError('PUP research ELF hash mismatch')
            if pup_path.stat().st_size != PUP_SOURCE_BYTES or not unpacker.is_file():
                raise ValueError('PUP source or unpacker missing')
        except (OSError, ValueError):
            return self.respond(503, {'error': 'The pinned research package is incomplete on the server.'})
        if source_version() != self.server.version:
            return self.respond(409, {'error': 'Hosting files changed after server startup. Restart the service first.'})
        with self.server.lock:
            run = self.server.current_relapse(target)
            if not run or run['session_id'] != value['relapse_session_id']:
                return self.respond(409, {'error': 'Relapse completion is missing or belongs to another session.'})
            if run['transfer_state'] or target in self.server.hv_inflight:
                return self.respond(409, {'error': 'A payload delivery was already attempted in this session.'})
            run['transfer_state'] = 'sending_pup'
            self.server.hv_inflight.add(target)
        session_id = run['session_id']
        runs_dir = self.server.data_dir / 'pup-runs'
        runs_dir.mkdir(parents=True, exist_ok=True)
        out = runs_dir / session_id
        resume = False
        for candidate in sorted(runs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not candidate.is_dir() or not (candidate / 'block_receipts.jsonl').is_file():
                continue
            try:
                marker = json.loads((candidate / 'receipt_source.json').read_text(encoding='ascii'))
                previous = json.loads((candidate / 'status.json').read_text(encoding='utf-8'))
            except (OSError, ValueError):
                continue
            if (marker == {'source_sha256': PUP_SOURCE_SHA256, 'expected_console_ip': target}
                    and previous.get('stage') in ('failed', 'payload_failed')):
                out = candidate
                resume = True
                break
        with self.server.lock:
            run['pup_out'] = str(out)
        log_path = runs_dir / (session_id + '.bridge.log')
        bridge = None
        try:
            with log_path.open('wb') as bridge_log:
                bridge = subprocess.Popen(
                    [sys.executable, str(ROOT / 'server' / 'pup_bridge.py'),
                     '--source', str(pup_path), '--out', str(out), '--unpacker', str(unpacker),
                     '--bind', '10.0.0.80', '--expect-ip', target] + (['--resume'] if resume else []),
                    stdin=subprocess.DEVNULL, stdout=bridge_log, stderr=subprocess.STDOUT,
                    start_new_session=True)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if bridge.poll() is not None:
                    raise RuntimeError('PUP receiver exited before listening')
                state_path = out / 'status.json'
                if state_path.is_file():
                    try:
                        if json.loads(state_path.read_text(encoding='utf-8')).get('stage') == 'listening':
                            break
                    except (OSError, ValueError):
                        pass
                time.sleep(0.2)
            else:
                raise RuntimeError('PUP receiver did not become ready')
            with socket.create_connection((target, 9021), timeout=5) as console:
                console.settimeout(10)
                console.sendall(payload)
                console.shutdown(socket.SHUT_WR)
        except (OSError, RuntimeError) as exc:
            if bridge and bridge.poll() is None:
                bridge.terminate()
            with self.server.lock:
                run['transfer_state'] = 'uncertain'
            print(f'[PUP14] delivery uncertain target={target} session={session_id} code={type(exc).__name__}', flush=True)
            return self.respond(502, {'error': 'Research ELF delivery was uncertain. Check the console and receiver log; this session remains locked.'})
        finally:
            with self.server.lock:
                self.server.hv_inflight.discard(target)
        with self.server.lock:
            run['transfer_state'] = 'pup_sent'
        print(f'[PUP14] ELF sent target={target} session={session_id} sha256={PUP_LAN_ELF_SHA256}', flush=True)
        return self.respond(200, {'sent': True, 'session_id': session_id,
                                  'message': 'Research ELF sent. Receiver status will show whether decryption and extraction finish.'})

    def pup_status(self, session_id):
        target = self.hv_client(require_origin=False)
        if not target:
            return self.respond(403, {'error': 'Local 13.60 PS5 required.'})
        try:
            if str(uuid.UUID(session_id)) != session_id:
                raise ValueError('Invalid session ID')
        except (ValueError, AttributeError):
            return self.respond(400, {'error': 'Invalid session ID.'})
        with self.server.lock:
            run = self.server.relapse_runs.get(target)
            if not run or run['session_id'] != session_id:
                return self.respond(403, {'error': 'Session does not belong to this console.'})
        state_path = Path(run.get('pup_out', self.server.data_dir / 'pup-runs' / session_id)) / 'status.json'
        try:
            state = json.loads(state_path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            state = {'stage': 'starting'}
        run_dir = state_path.parent
        if state.get('stage') == 'decrypting':
            state['output_bytes'] = sum(
                path.stat().st_size for path in run_dir.glob('PS5_1410_PS5UPDATE*.PUP.dec')
                if path.is_file()
            )
            log_path = run_dir / 'PS5_1410_RESEARCH.log'
            try:
                with log_path.open('rb') as log:
                    log.seek(max(0, log_path.stat().st_size - 2048))
                    lines = log.read().decode('utf-8', 'replace').splitlines()
                state['progress_line'] = lines[-1].strip()[:160] if lines else ''
            except OSError:
                state['progress_line'] = ''
        return self.respond(200, {'session_id': session_id, 'state': state})

    def pup_eligibility(self):
        target = self.hv_client(require_origin=False)
        if not target:
            return self.respond(403, {'error': 'Local 13.60 PS5 required.'})
        with self.server.lock:
            run = self.server.current_relapse(target)
            ready = bool(run and not run['transfer_state'] and target not in self.server.hv_inflight)
            session_id = run['session_id'] if ready else None
            transfer_state = run['transfer_state'] if run else None
        return self.respond(200, {'relapse_ready': ready, 'relapse_session_id': session_id,
                                  'transfer_state': transfer_state})

    def send_etahen_payload(self, value):
        target = self.hv_client()
        if not target:
            return self.respond(403, {'error': 'The etaHEN sender is available only from a PS5 on the local network.'})
        if (not isinstance(value, dict) or set(value) != {'firmware', 'elfldr_ready', 'relapse_session_id'}
                or value.get('firmware') != '13.60' or value.get('elfldr_ready') is not True
                or not isinstance(value.get('relapse_session_id'), str)):
            return self.respond(400, {'error': 'A completed 13.60 Relapse session is required before etaHEN delivery.'})

        try:
            payload = self.verified_etahen_payload()
            shadow = (ROOT / 'private' / 'etahen' / 'shadowmountplus.elf').read_bytes()
            if hashlib.sha256(shadow).hexdigest() != '0d54a8467ec3544e1c7b365c9f100b2bf42bf4633cb768bde7c8f16b6cfb5375':
                raise ValueError('ShadowMount build mismatch')
        except (OSError, ValueError):
            return self.respond(503, {'error': 'The server etaHEN payload is missing or does not match the pinned 13.60 build.'})
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        if source_version() != self.server.version:
            return self.respond(409, {'error': 'Hosting files changed after server startup. Finish deployment and restart the service before a new console session.'})

        with self.server.lock:
            run = self.server.current_relapse(target)
            if not run or run['session_id'] != value['relapse_session_id']:
                return self.respond(409, {'error': 'Relapse completion is missing, expired, or belongs to another console session.'})
            if run['transfer_state'] or target in self.server.hv_inflight:
                return self.respond(409, {'error': 'An etaHEN delivery was already attempted. Check the console and restart it before a new chain.'})
            # Consume readiness BEFORE connecting. An uncertain/partial send
            # must never be automatically replayed into the same console state.
            run['transfer_state'] = 'sending'
            self.server.hv_inflight.add(target)

        try:
            with socket.create_connection((target, 9021), timeout=5) as console:
                console.settimeout(10)
                console.sendall(payload)
                console.shutdown(socket.SHUT_WR)
            time.sleep(3)
            with socket.create_connection((target, 9021), timeout=5) as console:
                console.settimeout(10)
                console.sendall(shadow)
                console.shutdown(socket.SHUT_WR)
        except OSError as exc:
            with self.server.lock:
                run['transfer_state'] = 'uncertain'
            print(f'[etaHEN] delivery uncertain target={target} session={run["session_id"]} code={type(exc).__name__}', flush=True)
            return self.respond(502, {'error': 'etaHEN or ShadowMount delivery is uncertain. Check the console; restart it before a new chain. This session remains locked.', 'delivery_uncertain': True})
        finally:
            with self.server.lock:
                self.server.hv_inflight.discard(target)

        with self.server.lock:
            run['transfer_state'] = 'sent'

        print(f'[etaHEN] payload sent target={target} session={run["session_id"]} bytes={len(payload)} sha256={payload_sha256}', flush=True)
        return self.respond(200, {'sent': True, 'firmware': '13.60', 'target': target, 'port': 9021,
                                  'bytes_sent': len(payload), 'sha256': payload_sha256,
                                  'runtime_confirmed': False, 'shadowmount_sent': True,
                                  'message': 'The payload was sent to the ELF loader. Wait for etaHEN to finish on the PS5, then check for etaHEN Toolbox before opening homebrew.'})

    def do_GET(self):
        if not self.origin_allowed():
            return self.respond(403, {'error': 'Host or origin rejected'})
        path = self.route()
        query = urlsplit(self.path).query
        if path == '/api/pup/eligibility':
            return self.pup_eligibility()
        if path == '/api/pup/status':
            from urllib.parse import parse_qs
            return self.pup_status(parse_qs(query).get('session_id', [''])[0])
        if path == '/api/dump/status':
            from urllib.parse import parse_qs
            return self.dump_status(parse_qs(query).get('session_id', [''])[0])
        match = re.fullmatch(r'/api/dump/([a-f0-9-]{36})/([A-Za-z0-9_.-]+)', path)
        if match:
            return self.download_dump(match.group(1), match.group(2))
        static = {'/': ('web/index.html', 'text/html'), '/index.html': ('web/index.html', 'text/html'), '/relapse/': ('web/index.html', 'text/html'), '/relapse': ('web/index.html', 'text/html'), '/research.css': ('web/research.css', 'text/css'), '/diagnostics': ('web/diagnostics.html', 'text/html'), '/app.js': ('web/app.js', 'application/javascript'), '/ui.css': ('web/ui.css', 'text/css'), '/experiment.js': ('experiments/baseline.js', 'application/javascript'), '/dashboard': ('dashboard/index.html', 'text/html'), '/dashboard.js': ('dashboard/dashboard.js', 'application/javascript')}
        static['/phase2.js'] = ('experiments/phase2.js', 'application/javascript')
        static['/phase2'] = ('web/diagnostics.html', 'text/html')
        static['/context'] = ('web/diagnostics.html', 'text/html')
        static['/context.js'] = ('experiments/context.js', 'application/javascript')
        static['/context-worker.js'] = ('web/context-worker.js', 'application/javascript')
        static['/messaging'] = ('web/diagnostics.html', 'text/html')
        static['/messaging.js'] = ('experiments/messaging.js', 'application/javascript')
        static['/messaging-worker.js'] = ('web/messaging-worker.js', 'application/javascript')
        static['/ssvprobe'] = ('web/diagnostics.html', 'text/html')
        static['/ssvprobe.js'] = ('experiments/ssvprobe.js', 'application/javascript')
        static['/transformstream-feature'] = ('web/transformstream-feature.html', 'text/html')
        static['/transformstream-feature.js'] = ('web/transformstream-feature.js', 'application/javascript')
        static['/transformstream-regression'] = ('web/transformstream-regression.html', 'text/html')
        static['/transformstream-regression.js'] = ('web/transformstream-regression.js', 'application/javascript')
        static['/transformstream-regression-case'] = ('web/transformstream-regression-case.html', 'text/html')
        static['/transformstream-regression-case.js'] = ('web/transformstream-regression-case.js', 'application/javascript')
        static['/datalist-uaf-probe'] = ('web/datalist-uaf-probe.html', 'text/html')
        static['/datalist-uaf-probe.js'] = ('web/datalist-uaf-probe.js', 'application/javascript')
        static['/hv'] = ('web/hv.html', 'text/html')
        static['/hv.js'] = ('web/hv.js', 'application/javascript')
        static['/hv.css'] = ('web/hv.css', 'text/css')
        static['/hv-promo.css'] = ('web/hv-promo.css', 'text/css')
        static['/comparison.js'] = ('dashboard/comparison.js', 'application/javascript')
        if path in static:
            filename, mime = static[path]
            return self.send_bytes(200, (ROOT / filename).read_bytes(), mime + '; charset=utf-8', allow_same_origin_frame=path == '/transformstream-regression-case')
        if path in ('/health', '/api/health'):
            return self.respond(200, {'ok': True, 'server_utc': stamp(), 'version': self.server.version})
        if path == '/api/hv/status':
            target = self.hv_client(require_origin=False)
            if not target:
                return self.respond(403, {'error': 'The HV sender is available only from a PS5 on the local network.'})
            try:
                payload = self.verified_hv_payload()
            except (OSError, ValueError):
                return self.respond(503, {'error': 'The server HV payload is missing or does not match the pinned 13.60 build.'})
            with self.server.lock:
                run = self.server.current_relapse(target)
                ready = bool(run and not run['transfer_state'] and target not in self.server.hv_inflight)
                session_id = run['session_id'] if ready else None
                transfer_state = run['transfer_state'] if run else None
            return self.respond(200, {'eligible': True, 'firmware': '13.60', 'target': target,
                                      'payload_bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                                      'upstream_commit': HV_UPSTREAM_COMMIT, 'relapse_ready': ready,
                                      'relapse_session_id': session_id, 'transfer_state': transfer_state,
                                      'loader_port': 9021, 'hv_confirmed': False})
        if path == '/api/config':
            return self.respond(200, {'experiment': 'browser-baseline', 'version': self.server.version, 'parameters': {'allocation_bytes': 1048576, 'timing_samples': 5, 'request_timeout_ms': 5000}})
        if path == '/api/runs':
            if not self.dashboard_allowed():
                return self.respond(401, {'error': 'Dashboard access key required'})
            with self.server.lock:
                folders = sorted((self.server.data_dir / 'runs').iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[:100]
                items = [summarize(*self.server.run_data(p.name)) for p in folders if p.is_dir()]
            return self.respond(200, {'runs': items})
        if path.startswith('/api/run/'):
            if not self.dashboard_allowed():
                return self.respond(401, {'error': 'Dashboard access key required'})
            try:
                with self.server.lock:
                    meta, events = self.server.run_data(path.rsplit('/', 1)[-1])
                return self.respond(200, {'summary': summarize(meta, events), 'events': events})
            except (ValueError, FileNotFoundError):
                return self.respond(404, {'error': 'Unknown run'})
        return self.respond(404, {'error': 'Not found'})

    def read_json(self):
        length = int(self.headers.get('Content-Length', '-1'))
        if not 0 < length <= MAX_BODY:
            raise OverflowError('Body must be 1..32768 bytes')
        self._body_consumed = True
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError('Truncated body')
        if self.headers.get('Content-Encoding') or self.headers.get('Transfer-Encoding'):
            raise ValueError('Encoded or chunked bodies are not accepted')
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise ValueError('Content-Type must be application/json')
        return json.loads(body.decode('utf-8'), parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))

    def do_POST(self):
        if not self.origin_allowed():
            return self.respond(403, {'error': 'Host or origin rejected'})
        now = time.monotonic()
        with self.server.lock:
            self.server.rates = {ip: q for ip, q in self.server.rates.items() if q and now - q[-1] < 60}
            q = self.server.rates.setdefault(self.client_ip(), deque())
            while q and now - q[0] >= 60:
                q.popleft()
            limited = len(q) >= self.server.rate_limit
            if not limited:
                q.append(now)
        if limited:
            self.close_connection = True
            return self.respond(429, {'error': 'Request limit reached'})
        try:
            path = self.route()
            if path == '/dump':
                try:
                    return self.receive_dump()
                except OverflowError as exc:
                    self.close_connection = True
                    return self.respond(413, {'error': str(exc)})
                except (ValueError, TypeError, UnicodeDecodeError, RecursionError) as exc:
                    self.close_connection = True
                    return self.respond(400, {'error': str(exc)})
            value = self.read_json()
            if path == '/api/pup/send':
                return self.send_pup_payload(value)
            if path == '/api/etahen/send':
                return self.send_etahen_payload(value)
            if path == '/api/hv/send':
                return self.send_hv_payload(value)
            if path == '/api/relapse/diagnostics':
                return self.store_relapse_diagnostics(value)
            if path == '/api/run':
                if not isinstance(value, dict) or set(value) not in ({'origin_label', 'firmware', 'model', 'user_agent'}, {'origin_label', 'firmware', 'model', 'user_agent', 'suite'}) or value['origin_label'] not in ('desktop_simulation', 'ps5_hardware_reported') or any(not isinstance(v, str) or len(v) > 1024 for v in value.values()):
                    raise ValueError('Invalid run metadata')
                suite = value.get('suite', 'baseline')
                if suite not in SUITES:
                    raise ValueError('Unknown diagnostic suite')
                run_id, token = str(uuid.uuid4()), secrets.token_urlsafe(32)
                meta = dict(value, run_id=run_id, created_at_utc=stamp(), version=self.server.version, metadata_verification='unverified_self_report', experiment='browser-baseline', random_seed=secrets.randbits(32), parameters={'allocation_bytes': 1048576, 'timing_samples': 5})
                meta.update(suite=suite, experiment=SUITES[suite]['experiment'],
                            suite_revision=SUITES[suite]['revision'], expected_test_ids=SUITES[suite]['test_ids'])
                if suite == 'phase2':
                    meta['parameters'] = {'buffer_bytes': 32, 'wasm_module_bytes': 8, 'clock_reads': 128, 'timer_samples': 5, 'health_requests': 3, 'test_timeout_ms': 3000, 'http_repeats_timeout_ms': 18000, 'request_timeout_ms': 5000}
                if suite == 'context':
                    meta['parameters'] = {'workers': 1, 'messages': 1, 'worker_deadline_ms': 2000, 'test_timeout_ms': 3000, 'compilation_attempts': 0}
                if suite == 'messaging':
                    meta['parameters'] = {'workers': 1, 'messages': 2, 'buffer_bytes': 32, 'worker_deadline_ms': 2000, 'test_timeout_ms': 3000, 'compilation_attempts': 0}
                if suite == 'ssvprobe':
                    meta['parameters'] = {'tests': 6, 'bigint_counts': [252, 254, 300], 'max_graph_elements': 302, 'test_timeout_ms': 3000, 'sequential': True, 'resource_exhaustion': False}
                if suite == 'transformstream_feature':
                    meta['parameters'] = {'checks': 1, 'constructor_calls': 0, 'iterator_mutations': 0}
                if suite == 'transformstream_regression':
                    meta['parameters'] = {'cases': 1, 'case': 'plain-object substitution', 'constructor_calls': 1,
                                          'iterator_overrides': 1, 'buffer_allocation_bytes': 0,
                                          'soft_deadline_ms': 5000, 'automatic_retry': False}
                if suite == 'datalist_uaf_probe':
                    meta['parameters'] = {'attempts': 1, 'max_click_wait_ms': 30000, 'resource_allocations': 'fixed DOM only',
                                          'forced_gc': False, 'heap_churn': False, 'automatic_retry': False,
                                          'security_conclusion_on_survival': 'none'}
                with self.server.lock:
                    if self.server.storage_bytes >= self.server.max_storage_bytes:
                        return self.respond(507, {'error': 'Collector storage budget reached; preserve/export existing data'})
                    if len(self.server.tokens) >= 1000:
                        return self.respond(429, {'error': 'Session run limit reached; preserve data and restart server'})
                    if source_version() != self.server.version:
                        return self.respond(409, {'error': 'Source changed on disk; restart server for a new version'})
                    folder = self.server.data_dir / 'runs' / run_id
                    folder.mkdir()
                    encoded_meta = canonical(meta)
                    (folder / 'metadata.json').write_bytes(encoded_meta)
                    self.server.storage_bytes += len(encoded_meta)
                    self.server.tokens[run_id] = token
                return self.respond(201, dict(meta, token=token))
            if path != '/api/event':
                return self.respond(404, {'error': 'Not found'})
            validate_event(value)
            run_id = value['run_id']
            token = self.headers.get('Authorization', '').removeprefix('Bearer ')
            with self.server.lock:
                expected = self.server.tokens.get(run_id)
                if not expected or not secrets.compare_digest(token, expected):
                    return self.respond(403, {'error': 'Unknown run or invalid token; start a new run after server restart'})
                meta, existing = self.server.run_data(run_id)
                if meta['version'] != source_version():
                    return self.respond(409, {'error': 'Source changed; start a new run'})
                digest = hashlib.sha256(canonical(value)).hexdigest()
                previous = next((e for e in existing if e['seq'] == value['seq']), None)
                if previous:
                    if previous['sha256'] != digest:
                        return self.respond(409, {'error': 'Sequence already stored with different content'})
                    return self.respond(200, {'ok': True, 'seq': previous['seq'], 'sha256': digest, 'duplicate': True})
                if value['seq'] != len(existing) + 1:
                    return self.respond(409, {'error': 'Sequence must be consecutive'})
                if any(e['event'] in TERMINAL for e in existing) and value['event'] not in ('checkpoint_ack', 'page_hidden'):
                    return self.respond(409, {'error': 'Run already ended'})
                if value['event'] == 'checkpoint_ack' and not any(e['seq'] == value['details'].get('ack_seq') for e in existing):
                    raise ValueError('Acknowledgment references missing checkpoint')
                item = dict(value, received_at_utc=stamp(), sha256=digest, schema_version=1)
                encoded = canonical(item) + b'\n'
                if self.server.storage_bytes + len(encoded) * 2 > self.server.max_storage_bytes:
                    return self.respond(507, {'error': 'Collector storage budget reached; preserve/export existing data'})
                with (self.server.data_dir / 'runs' / run_id / 'events.jsonl').open('ab') as output:
                    output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
                with (self.server.data_dir / 'events.jsonl').open('ab') as output:
                    output.write(encoded)
                self.server.storage_bytes += len(encoded) * 2
            return self.respond(200, {'ok': True, 'seq': value['seq'], 'sha256': digest})
        except OverflowError as exc:
            self.close_connection = True
            return self.respond(413, {'error': str(exc)})
        except (ValueError, TypeError, UnicodeDecodeError, RecursionError) as exc:
            self.close_connection = True
            return self.respond(400, {'error': str(exc)})

def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1', help='Loopback default; explicitly choose laptop LAN IPv4 for PS5 tests')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--data-dir', type=Path, default=ROOT / 'data')
    parser.add_argument('--public-origin', help='Exact HTTPS origin, accepted only from the loopback reverse proxy')
    parser.add_argument('--dashboard-key-file', type=Path, help='Private file containing dashboard access key')
    args = parser.parse_args(argv)
    address = ipaddress.ip_address(args.host)
    if address.version != 4 or not (address.is_private or address.is_loopback) or address.is_unspecified:
        parser.error('Choose an explicit private/loopback IPv4, not a public or wildcard bind')
    if args.public_origin:
        parsed = urlsplit(args.public_origin)
        if args.host != '127.0.0.1' or parsed.scheme != 'https' or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or not args.dashboard_key_file:
            parser.error('Public origin requires loopback binding, an exact HTTPS origin and a dashboard key file')
    return args

def main():
    args = arguments()
    key = args.dashboard_key_file.read_text(encoding='utf-8').strip() if args.dashboard_key_file else None
    if key is not None and len(key) < 32:
        raise ValueError('Dashboard access key must contain at least 32 characters')
    with Collector((args.host, args.port), args.data_dir, public_origin=args.public_origin, dashboard_key=key) as server:
        print(f'Browser research: http://{args.host}:{server.server_port}/ps5/', flush=True)
        print(f'Dashboard: http://{args.host}:{server.server_port}/ps5/dashboard', flush=True)
        print(f'Append-only data: {args.data_dir}', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('Stopped.')

if __name__ == '__main__':
    main()
