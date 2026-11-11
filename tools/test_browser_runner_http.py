"""Offline HTTP fixtures; opt-in loopback tests never contact external hosts."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from tools.browser_runner import serve
from tools.browser_runner.capture import CaptureError, CaptureWriter, decode_request
from tools.browser_runner.verify_capture import verify_capture


class MemorySocket:
    def __init__(self, request, *, fail_response=False, reader=None):
        self.input = reader or io.BytesIO(request)
        self.output = io.BytesIO()
        self.timeout = None
        self.fail_response = fail_response
        self.before_response = None

    def makefile(self, mode, *args):
        return self.input

    def sendall(self, data):
        if self.before_response:
            self.before_response()
        if self.fail_response:
            raise BrokenPipeError('injected response failure')
        self.output.write(data)

    def settimeout(self, timeout):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout


class FaultSink(io.BytesIO):
    def __init__(self, fault):
        super().__init__()
        self.fault = fault
        self.writes = 0

    def write(self, data):
        self.writes += 1
        if self.writes == 2:
            if self.fault == 'write':
                raise OSError('injected write failure')
            if self.fault == 'short':
                super().write(data[:7])
                return 7
        return super().write(data)

    def flush(self):
        if self.writes == 2 and self.fault == 'flush':
            raise OSError('injected flush failure')
        return super().flush()


class HttpFixtureTests(unittest.TestCase):
    def setUp(self):
        self.sink = io.BytesIO()
        self.writer = CaptureWriter(self.sink)
        self.server = SimpleNamespace(capture=self.writer, log_file=io.StringIO(),
                                      capture_failed=False, first_error=None,
                                      response_error=None, secondary_error=None)

    def request(self, target='/beacon/T', *, method='GET', headers=b'', body=b'',
                fail_response=False, reader=None, stdout=None, handler=serve.ProbeHandler,
                before_response=None):
        wire = method.encode()+b' '+target.encode('iso-8859-1')+b' HTTP/1.1\r\nHost: localhost\r\n'+headers+b'\r\n'+body
        sock = MemorySocket(wire, fail_response=fail_response, reader=reader)
        sock.before_response = before_response
        with contextlib.redirect_stdout(stdout or io.StringIO()):
            handler(sock, ('192.0.2.1', 1234), self.server)
        raw = sock.output.getvalue()
        self.last_response = raw
        if not raw:
            return None
        # Existing static responses use HTTP/1.0 implicit close; capture replies
        # explicitly announce close. Neither permits another request here.
        self.assertTrue(b'Connection: close\r\n' in raw or raw.startswith(b'HTTP/1.0 '))
        return int(raw.split(b' ', 2)[1])

    def rows(self):
        return [json.loads(line) for line in self.sink.getvalue().split(b'\n') if line]

    def events(self):
        return [r['request'] for r in self.rows() if r['record_type'] == 'event']

    def test_state_reset_path_and_query_forms(self):
        cases = [
            ('p686reset', serve.P686_STATE),
            ('p688reset', serve.P688_STATE),
            ('p689reset', serve.P689_STATE),
            ('p690reset', serve.P690_STATE),
        ]
        for name, state in cases:
            original = dict(state)
            try:
                state.update(pendingArm=7, alive=True, armFrom=None, mode=None)
                self.assertEqual(self.request('/%s=1' % name), 200)
                self.assertEqual(state, {'pendingArm': None, 'alive': False,
                                         'armFrom': None, 'mode': None})

                state.update(pendingArm=8, alive=True, armFrom=None, mode=None)
                self.assertEqual(
                    self.request('/?%s=1&arm=3&mode=reclaim' % name), 200)
                self.assertEqual(state['pendingArm'], None)
                self.assertFalse(state['alive'])
                self.assertEqual(state['armFrom'], 3)
                self.assertEqual(state['mode'], 'reclaim')

                state.update(pendingArm=9, alive=True, armFrom=4, mode='keep')
                self.assertEqual(self.request('/not-a-route?note=%s=1' % name), 404)
                self.assertEqual(state['pendingArm'], 9)
                self.assertTrue(state['alive'])
                self.assertEqual(state['armFrom'], 4)
                self.assertEqual(state['mode'], 'keep')
            finally:
                state.clear()
                state.update(original)

    def test_original_p560_tagged_d(self):
        target='/beacon/P560-B-POST?d=1%2C2%2C3%2C4'
        self.assertEqual(self.request(target), 204)
        q=self.events()[0]
        self.assertEqual((q['raw_target'],q['tag'],q['measurement']),
                         (target,'P560-B-POST','1,2,3,4'))
        self.assertEqual(q['query'], [['d','1,2,3,4']])
        self.assertIn('BEACON 192.0.2.1: P560-B-POST: 1,2,3,4', self.server.log_file.getvalue())

    def test_legacy_and_path_formats(self):
        for target, expected in [('/beacon?m=hello+world','hello world'),
                                 ('/beacon/a%2Fb%3Fc','a/b?c'),('/beacon?m=','')]:
            self.assertEqual(self.request(target),204)
            self.assertEqual(self.events()[-1]['measurement'],expected)

    def test_php_alias_and_empty_sendbeacon(self):
        for target, expected in [('/beacon.php?tag=P573-BOOT','P573-BOOT'),
                                 ('/beacon/full%20message','full message'),
                                 ('/beacon?m=query','query')]:
            self.assertEqual(self.request(target,method='POST',headers=b'Content-Length: 0\r\n'),204)
            self.assertEqual(self.events()[-1]['measurement'],expected)

    def test_5000_byte_body_retained(self):
        self.assertEqual(self.request(method='POST',headers=b'Content-Length: 5000\r\n',body=b'x'*5000),204)
        self.assertEqual(base64.b64decode(self.events()[0]['body_base64']),b'x'*5000)
        self.assertEqual(self.events()[0]['body_length'],5000)

    def test_binary_and_invalid_utf8_retained(self):
        body=b'\x00\xff\xc0\xaf\r\n\\n'
        self.assertEqual(self.request(method='POST',headers=b'Content-Length: 8\r\n',body=body),204)
        self.assertEqual(base64.b64decode(self.events()[0]['body_base64']),b'\x00\xff\xc0\xaf\r\n\\n')
        self.assertIsNone(self.events()[0]['measurement'])
        self.assertIn('<binary 8 bytes; see JSONL>',self.server.log_file.getvalue())

    def test_exact_64k_and_one_over(self):
        body=bytes(range(256))*256
        self.assertEqual(self.request(method='POST',headers=b'Content-Length: 65536\r\n',body=body),204)
        self.assertEqual(base64.b64decode(self.events()[0]['body_base64']),body)
        self.assertEqual(self.request(method='POST',headers=b'Content-Length: 65537\r\n',body=body+b'!'),413)
        self.assertEqual(len(self.events()),1)

    def test_eof_short_rejected(self):
        self.assertEqual(self.request(method='POST',headers=b'Content-Length: 10\r\n',body=b'abc'),400)
        self.assertEqual(self.events(),[])

    def test_duplicate_conflicting_and_invalid_lengths(self):
        for value in [b'Content-Length: 1\r\nContent-Length: 1\r\n',
                      b'Content-Length: 1\r\nContent-Length: 2\r\n',
                      b'Content-Length: -1\r\n',b'Content-Length: nope\r\n',
                      b'Content-Length: +1\r\n',b'Content-Length: 1, 1\r\n',
                      b'Content-Length: 1.0\r\n',b'Content-Length:\r\n',
                      b'Content-Length: 1\r\n 2\r\n']:
            with self.subTest(value=value):
                self.assertEqual(self.request(method='POST',headers=value,body=b'x'),400)
        self.assertEqual(self.events(),[])

    def test_missing_length(self):
        self.assertEqual(self.request(method='POST'),411)
        self.assertEqual(self.events(),[])

    def test_huge_decimal_length_is_413_not_conversion_error(self):
        self.assertEqual(self.request(method='POST',headers=b'Content-Length: '+b'9'*5000+b'\r\n'),413)

    def test_leading_zero_length_and_get_zero(self):
        self.assertEqual(self.request(method='POST',headers=b'Content-Length: 0001\r\n',body=b'x'),204)
        self.assertEqual(self.events()[0]['declared_length'],1)
        self.assertEqual(self.request(headers=b'Content-Length: 0\r\n'),204)

    def test_transfer_encoding_and_expect_rejected(self):
        for headers in [b'Transfer-Encoding: chunked\r\n',b'Transfer-Encoding: identity\r\nContent-Length: 1\r\n',b'Expect: 100-continue\r\nContent-Length: 1\r\n']:
            self.assertEqual(self.request(method='POST',headers=headers,body=b'x'),400)
        self.assertEqual(self.events(),[])

    def test_get_with_declared_body_rejected_without_capture(self):
        self.assertEqual(self.request(headers=b'Content-Length: 1\r\n',body=b'x'),400)
        self.assertEqual(self.events(),[])

    def test_rejected_unread_body_cannot_pipeline(self):
        self.assertEqual(self.request(method='POST',headers=b'Content-Length: -1\r\n',body=b'GET /beacon/forged HTTP/1.1\r\nHost: localhost\r\n\r\n'),400)
        self.assertEqual(self.events(),[])

    def test_bytes_beyond_declared_body_are_not_another_request(self):
        self.assertEqual(self.request(method='POST',headers=b'Content-Length: 1\r\n',
                                      body=b'xGET /beacon/forged HTTP/1.1\r\nHost: localhost\r\n\r\n'),204)
        self.assertEqual(len(self.events()),1)
        self.assertEqual(base64.b64decode(self.events()[0]['body_base64']),b'x')

    def test_duplicate_and_ambiguous_queries(self):
        for target in ['/beacon/T?d=x&d=y','/beacon?m=x&m=y','/beacon/T?m=x','/beacon?m','/beacon/T?d=%FF']:
            self.assertEqual(self.request(target),400)
        self.assertEqual(self.events(),[])

    def test_unknown_metadata_and_empty_data(self):
        target='/beacon/T?d=&flag&flag=&x=a%26b&n=1'
        self.assertEqual(self.request(target),204)
        self.assertEqual(self.events()[0]['query'],[['d',''],['flag',None],['flag',''],['x','a&b'],['n','1']])

    def test_not_a_beacon_route(self):
        self.assertEqual(self.request('/beaconish'),404)
        self.assertEqual(self.request('/beaconish',method='POST'),404)
        self.assertEqual(self.events(),[])

    def test_legacy_http09_rejected_explicitly(self):
        reader=io.BytesIO(b'GET /beacon/T\r\n\r\n')
        self.assertEqual(self.request(reader=reader),400)
        self.assertEqual(self.events(),[])

    def test_raw_leading_double_slash_not_normalized_into_beacon(self):
        self.assertEqual(self.request('//example/beacon/T'),400)
        self.assertEqual(self.events(),[])

    def test_missing_sink(self):
        self.server.capture=None
        self.assertEqual(self.request(),503)
        self.assertIsNotNone(self.server.first_error)

    def test_unexpected_handler_error_marks_acquisition_failed(self):
        first=RuntimeError('unexpected handler failure')
        try:
            raise first
        except RuntimeError:
            with contextlib.redirect_stderr(io.StringIO()):
                serve.CaptureHTTPServer.handle_error(self.server,None,None)
        self.assertIs(self.server.first_error,first)
        self.assertEqual(self.request(),503)
        self.assertEqual(self.events(),[])

    def test_write_short_and_flush_errors_never_success(self):
        for fault in ['write','short','flush']:
            with self.subTest(fault=fault):
                sink=FaultSink(fault);self.server.capture=CaptureWriter(sink)
                self.server.capture_failed=False;self.server.first_error=None
                self.assertEqual(self.request(),500)
                first=self.server.first_error
                self.assertEqual(self.request(),503)
                self.assertIs(self.server.first_error,first)
                self.assertNotIn(b'"record_type":"close"',sink.getvalue())

    def test_flush_happens_before_response(self):
        observed=[]
        class Sink(io.BytesIO):
            def flush(self): observed.append('flush');super().flush()
        self.server.capture=CaptureWriter(Sink());observed.clear()
        self.assertEqual(self.request(before_response=lambda:observed.append('response')),204)
        self.assertEqual(observed,['flush','response'])

    def test_broken_stdout_and_access_log_are_optional(self):
        class Broken:
            def write(self,value):raise BrokenPipeError('closed stdout')
            def flush(self):pass
        self.assertEqual(self.request(stdout=Broken()),204)
        self.assertEqual(self.events()[0]['measurement'],'T')

    def test_secondary_file_write_flush_and_short_errors_optional(self):
        for fault in ['write','flush','short']:
            class Secondary(io.StringIO):
                def write(self,value):
                    if fault=='write':raise OSError('secondary write')
                    if fault=='short':return 1
                    return super().write(value)
                def flush(self):
                    if fault=='flush':raise OSError('secondary flush')
            self.server.log_file=Secondary();self.server.secondary_error=None
            with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(self.request(),204)
            self.assertIsNotNone(self.server.secondary_error)
            self.assertFalse(self.server.capture_failed)
        self.assertEqual(len(self.events()),3)

    def test_response_write_failure_keeps_event_and_retry(self):
        self.assertIsNone(self.request(fail_response=True))
        self.assertIsNotNone(self.server.response_error)
        self.assertEqual(self.request(),204)
        self.assertEqual([r['measurement'] for r in self.events()],['T','T'])
        self.assertFalse(self.server.capture_failed)

    def test_exact_pr231_ten_separator_policy(self):
        value='\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029'
        self.assertEqual(serve._escape_log_value(value),r'\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029')
        self.assertEqual(self.request('/beacon?m=caf%C3%A9%0A%5Cn'),204)
        self.assertEqual(self.events()[0]['measurement'],'caf\u00e9\n\\n')
        self.assertEqual(len(self.server.log_file.getvalue().splitlines()),1)
        self.assertIn('caf\u00e9\\n\\n',self.server.log_file.getvalue())

    def test_static_alias_and_containment(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'literal.html';p.write_bytes(b'literal static bytes')
            with mock.patch.dict(serve.STATIC,{'/local':p}):
                self.assertEqual(self.request('/local'),200)
                self.assertTrue(self.last_response.endswith(b'literal static bytes'))
                self.assertEqual(self.request('/document/en/ps5/local'),200)
                self.assertTrue(self.last_response.endswith(b'literal static bytes'))
            self.assertEqual(self.request('/../../../../etc/passwd'),404)
            self.assertEqual(self.request('/webp-poc/../../../../etc/passwd'),404)
        self.assertEqual(self.events(),[])

    def test_overall_deadline_with_deterministic_trickle(self):
        class Trickle(io.BytesIO):
            def read1(self,n):return b'x'
        # Header parser reads from this same stream, then body read1 trickles.
        reader=Trickle(b'POST /beacon/T HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\n')
        with mock.patch.object(serve.time,'monotonic',side_effect=[0,0,4,4,8,8,11]):
            self.assertEqual(self.request(reader=reader),408)
        self.assertEqual(self.events(),[])

    def test_socket_idle_timeout(self):
        class TimeoutReader(io.BytesIO):
            def read1(self,n):raise TimeoutError('read timeout')
        reader=TimeoutReader(b'POST /beacon/T HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\n')
        self.assertEqual(self.request(reader=reader),408)
        self.assertEqual(self.events(),[])


class StaticTransportTests(unittest.TestCase):
    """Real stdlib dispatch and production error policy, without a listener."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='static-transport-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / 'dummy.html'
        self.file.write_bytes(b'ordinary static bytes')
        self.sink = io.BytesIO()
        self.writer = CaptureWriter(self.sink)
        self.server = serve.CaptureHTTPServer.__new__(serve.CaptureHTTPServer)
        self.server.RequestHandlerClass = serve.ProbeHandler
        self.server.capture = self.writer
        self.server.log_file = io.StringIO()
        self.server.capture_failed = False
        self.server.first_error = None
        self.server.response_error = None
        self.server.secondary_error = None
        self.server.verify_request = lambda *args: True

    def dispatch(self, target='/static-fixture', *, fail_at=None, error=None):
        class Request(MemorySocket):
            sends = 0

            def sendall(request, data):
                request.sends += 1
                if request.sends == fail_at:
                    raise error
                super().sendall(data)

            def shutdown(request, *args):
                pass

            def close(request):
                pass

        request = Request(b'GET ' + target.encode() + b' HTTP/1.1\r\nHost: localhost\r\n\r\n')
        self.server.get_request = lambda: (request, ('192.0.2.55', 1234))
        with mock.patch.dict(serve.STATIC, {'/static-fixture': self.file}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.server._handle_request_noblock()
        return request

    def assert_healthy_beacon(self):
        request = self.dispatch('/beacon/P560-B-POST?d=1%2C2%2C3%2C4')
        self.assertIn(b' 204 ', request.output.getvalue())
        self.assertFalse(self.server.capture_failed)
        self.assertIsNone(self.server.first_error)
        self.assertFalse(self.writer._failed)
        events = [json.loads(line) for line in self.sink.getvalue().splitlines()
                  if json.loads(line)['record_type'] == 'event']
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['sequence'], 1)
        self.assertEqual(events[0]['request']['tag'], 'P560-B-POST')
        self.assertEqual(events[0]['request']['measurement'], '1,2,3,4')
        self.assertEqual(events[0]['request']['raw_target'],
                         '/beacon/P560-B-POST?d=1%2C2%2C3%2C4')

    def test_header_broken_pipe_keeps_capture_healthy(self):
        error = BrokenPipeError('header send failed')
        request = self.dispatch(fail_at=1, error=error)
        self.assertEqual(request.sends, 1)  # no second error response
        self.assertIs(self.server.response_error, error)
        self.assert_healthy_beacon()

    def test_body_broken_pipe_keeps_capture_healthy(self):
        error = BrokenPipeError('body send failed')
        request = self.dispatch(fail_at=2, error=error)
        self.assertEqual(request.sends, 2)
        self.assertIn(b' 200 ', request.output.getvalue())
        self.assertNotIn(b'ordinary static bytes', request.output.getvalue())
        self.assertIs(self.server.response_error, error)
        self.assert_healthy_beacon()

    def test_reset_and_abort_at_header_and_body_keep_capture_healthy(self):
        for error_type in (ConnectionResetError, ConnectionAbortedError):
            for phase in (1, 2):
                with self.subTest(error=error_type, phase=phase):
                    error = error_type('client disconnected')
                    request = self.dispatch(fail_at=phase, error=error)
                    self.assertEqual(request.sends, phase)
                    self.assertFalse(self.server.capture_failed)
                    self.assertIsNone(self.server.first_error)
        self.assert_healthy_beacon()

    def test_not_found_response_disconnect_keeps_capture_healthy(self):
        request = self.dispatch('/missing-static-file', fail_at=2,
                                error=BrokenPipeError('404 body send failed'))
        self.assertEqual(request.sends, 2)
        self.assertFalse(self.server.capture_failed)
        self.assert_healthy_beacon()

    def test_each_static_source_contains_header_and_body_disconnects(self):
        for relative in ('webp-poc/dummy.html', 'fuzzcases/dummy.html',
                         'project/probes/phase13_webkit/dummy.html'):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'ordinary static bytes')
        with mock.patch.object(serve, 'ROOT', self.root), \
                mock.patch.object(serve, 'PROJECT', self.root / 'project'):
            for target in ('/webp-poc/dummy.html', '/fuzzcases/dummy.html', '/dummy.html'):
                for phase in (1, 2):
                    with self.subTest(target=target, phase=phase):
                        request = self.dispatch(target, fail_at=phase,
                                                error=BrokenPipeError('static disconnect'))
                        self.assertEqual(request.sends, phase)
                        self.assertFalse(self.server.capture_failed)
                        self.assertIsNone(self.server.first_error)
        self.assert_healthy_beacon()

    def test_file_read_errors_are_fatal_even_with_disconnect_error_type(self):
        for error in (OSError('file read failed'), BrokenPipeError('file read failure')):
            with self.subTest(error=type(error)):
                self.server.first_error = None
                self.server.capture_failed = False
                with mock.patch.object(Path, 'read_bytes', side_effect=error):
                    self.dispatch()
                self.assertTrue(self.server.capture_failed)
                self.assertIs(self.server.first_error, error)
                self.assertIsNone(self.server.response_error)
                self.assertIn(b' 503 ', self.dispatch('/beacon/T').output.getvalue())

    def test_unexpected_internal_error_remains_fatal(self):
        error = RuntimeError('unexpected handler logic failure')
        with mock.patch.object(serve.ProbeHandler, 'do_GET', side_effect=error):
            self.dispatch()
        self.assertTrue(self.server.capture_failed)
        self.assertIs(self.server.first_error, error)
        self.assertIn(b' 503 ', self.dispatch('/beacon/T').output.getvalue())

    def test_other_output_oserror_remains_fatal(self):
        error = OSError('unexpected output error')
        self.dispatch(fail_at=1, error=error)
        self.assertTrue(self.server.capture_failed)
        self.assertIs(self.server.first_error, error)
        self.assertIsNone(self.server.response_error)

    def test_primary_fault_then_transport_preserves_fatal_error_and_abort(self):
        for fault in ('short', 'write', 'flush'):
            with self.subTest(fault=fault):
                sink = FaultSink(fault)
                writer = CaptureWriter(sink)
                self.server.capture = writer
                self.server.capture_failed = False
                self.server.first_error = None
                self.server.response_error = None
                request = self.dispatch('/beacon/T')
                self.assertIn(b' 500 ', request.output.getvalue())
                first = self.server.first_error
                self.assertIsInstance(first, CaptureError)
                error = BrokenPipeError('later static disconnect')
                self.dispatch(fail_at=2, error=error)
                self.assertIs(self.server.first_error, first)
                self.assertIs(self.server.response_error, error)
                self.assertTrue(self.server.capture_failed)
                self.assertIn(b' 503 ', self.dispatch('/beacon/T').output.getvalue())
                writer.abort()
                self.assertNotIn(b'"record_type":"close"', sink.getvalue())
                path = self.root / (fault + '.jsonl')
                path.write_bytes(sink.getvalue())
                self.assertEqual(verify_capture(path)['capture_integrity'], 'INCOMPLETE')

    def test_first_response_diagnostic_is_preserved(self):
        first = BrokenPipeError('first header failure')
        self.dispatch(fail_at=1, error=first)
        self.dispatch(fail_at=2, error=ConnectionResetError('later failure'))
        self.assertIs(self.server.response_error, first)
        self.assert_healthy_beacon()

    def test_beacon_response_failure_keeps_persisted_event_and_retry(self):
        error = BrokenPipeError('beacon reply failed')
        request = self.dispatch('/beacon/T?d=7', fail_at=1, error=error)
        self.assertEqual(request.sends, 1)
        self.assertIs(self.server.response_error, error)
        self.assertFalse(self.server.capture_failed)
        self.assertIn(b' 204 ', self.dispatch('/beacon/T?d=7').output.getvalue())
        events = [json.loads(line) for line in self.sink.getvalue().splitlines()[1:]]
        self.assertEqual([r['request']['measurement'] for r in events], ['7', '7'])

    def test_run_gracefully_closes_after_benign_disconnect(self):
        args = SimpleNamespace(host='127.0.0.1', port=0, no_tls=True, cert=None, key=None)
        server = self.server

        def factory(address, handler, **kwargs):
            server.capture = kwargs['capture']
            server.log_file = kwargs['log_file']
            server.server_port = 0
            return server

        def serve_forever():
            self.dispatch(fail_at=2, error=BrokenPipeError('benign body disconnect'))
            self.assertIn(b' 204 ', self.dispatch('/beacon/T?d=1%2C2%2C3%2C4').output.getvalue())

        server.serve_forever = serve_forever
        server.server_close = lambda: None
        with mock.patch.object(serve, 'LOG_DIR', self.root), \
                mock.patch.object(serve, 'CaptureHTTPServer', factory), \
                contextlib.redirect_stdout(io.StringIO()):
            serve.run(args)
        path = next(self.root.glob('capture-*.jsonl'))
        report = verify_capture(path)
        self.assertEqual(report['capture_integrity'], 'VALID')
        records = [json.loads(line) for line in path.read_bytes().splitlines()]
        self.assertEqual([r['record_type'] for r in records], ['open', 'event', 'close'])
        self.assertEqual(records[1]['request']['measurement'], '1,2,3,4')
        self.assertEqual(records[-1]['accepted_count'], 1)
        self.assertIsNone(server.first_error)

    def test_run_aborts_primary_failure_despite_later_benign_disconnect(self):
        args = SimpleNamespace(host='127.0.0.1', port=0, no_tls=True, cert=None, key=None)
        server = self.server
        first_errors = []

        class FailedFlush:
            def __init__(wrapper, sink):
                wrapper.sink = sink

            def write(wrapper, data):
                return wrapper.sink.write(data)

            def flush(wrapper):
                raise OSError('primary event flush failed')

            def close(wrapper):
                wrapper.sink.close()

        def factory(address, handler, **kwargs):
            server.capture = kwargs['capture']
            server.capture._sink = FailedFlush(server.capture._sink)
            server.log_file = kwargs['log_file']
            server.server_port = 0
            return server

        def serve_forever():
            self.assertIn(b' 500 ', self.dispatch('/beacon/T').output.getvalue())
            first_errors.append(server.first_error)
            self.dispatch(fail_at=1, error=BrokenPipeError('later transport failure'))
            self.assertIs(server.first_error, first_errors[0])
            self.assertIn(b' 503 ', self.dispatch('/beacon/T').output.getvalue())

        server.serve_forever = serve_forever
        server.server_close = lambda: None
        with mock.patch.object(serve, 'LOG_DIR', self.root), \
                mock.patch.object(serve, 'CaptureHTTPServer', factory), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(CaptureError) as caught:
                serve.run(args)
        self.assertIs(caught.exception, first_errors[0])
        report = verify_capture(next(self.root.glob('capture-*.jsonl')))
        self.assertEqual(report['capture_integrity'], 'INCOMPLETE')
        self.assertFalse(report['closed'])


class InheritedErrorTests(unittest.TestCase):
    """Real dispatch through base parsing/method errors and production policy."""
    HEAD = b'HEAD /static HTTP/1.1\r\nHost: localhost\r\n\r\n'
    VERSION = b'GET /static HTTP/9.0\r\nHost: localhost\r\n\r\n'
    BEACON = b'GET /beacon/T?d=1%2C2%2C3%2C4 HTTP/1.1\r\nHost: localhost\r\n\r\n'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='inherited-error-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / 'static.html'
        self.file.write_bytes(b'literal static resource')
        self.sink = io.BytesIO()
        self.writer = CaptureWriter(self.sink)
        self.server = serve.CaptureHTTPServer.__new__(serve.CaptureHTTPServer)
        self.server.capture = self.writer
        self.server.capture_failed = False
        self.server.first_error = None
        self.server.response_error = None
        self.server.secondary_error = None
        self.server.log_file = io.StringIO()
        self.server.verify_request = lambda *args: True

    def dispatch(self, raw, *, fail_at=None, error=None, handler=serve.ProbeHandler):
        class Peer(MemorySocket):
            calls = 0

            def sendall(peer, data):
                peer.calls += 1
                peer.writes.append(bytes(data))
                if peer.calls == fail_at:
                    raise error
                super().sendall(data)

            def shutdown(peer, *args):
                pass

            def close(peer):
                pass

        peer = Peer(raw)
        peer.writes = []
        peer.error_calls = []

        class ObservedHandler(handler):
            def send_error(observed, code, message=None, explain=None):
                # Observe the actual parser/dispatcher decision, then delegate
                # all preparation, output and error handling to production.
                peer.error_calls.append((code, observed.request_version))
                return super().send_error(code, message, explain)

        self.server.RequestHandlerClass = ObservedHandler
        self.server.get_request = lambda: (peer, ('192.0.2.7', 1234))
        with mock.patch.dict(serve.STATIC, {'/static': self.file}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.server._handle_request_noblock()
        return peer

    def status(self, peer):
        self.assertTrue(peer.output.getvalue().startswith(b'HTTP/'))
        return int(peer.output.getvalue().split(b' ', 2)[1])

    def assert_error_response(self, raw, expected, *, allow_body_only=False,
                              handler=serve.ProbeHandler):
        peer = self.dispatch(raw, handler=handler)
        self.assertEqual([code for code, _ in peer.error_calls], [expected])
        wire = peer.output.getvalue()
        self.assertEqual(b''.join(peer.writes), wire)
        if peer.error_calls[0][1] == 'HTTP/0.9':
            # Older stdlib parsers may reject an invalid version before
            # assigning request_version. This is an HTML reply, not HTTP 200.
            self.assertTrue(allow_body_only)
            self.assertFalse(wire.startswith(b'HTTP/'))
            body = wire
            self.assertEqual(peer.writes, [body])
        else:
            self.assertEqual(self.status(peer), expected)
            headers, body = wire.split(b'\r\n\r\n', 1)
            self.assertIn(b'\r\nConnection: close', headers)
            self.assertEqual(peer.writes, [headers + b'\r\n\r\n'] + ([body] if body else []))
        if raw.startswith(b'HEAD '):
            self.assertEqual(body, b'')
        else:
            self.assertTrue(body.startswith(b'<!DOCTYPE HTML'))
            self.assertIn(('<p>Error code: %d</p>' % expected).encode('ascii'), body)
        self.assertEqual(peer.calls, len(peer.writes))
        return peer

    def assert_healthy_beacon(self):
        previous = len(self.sink.getvalue().splitlines()) - 1
        peer = self.dispatch(self.BEACON)
        self.assertEqual(self.status(peer), 204)
        self.assertFalse(self.server.capture_failed)
        self.assertIsNone(self.server.first_error)
        rows = [json.loads(x) for x in self.sink.getvalue().splitlines()]
        self.assertEqual(len(rows), previous + 2)
        self.assertEqual(rows[-1]['sequence'], previous + 1)
        self.assertEqual(rows[-1]['request']['raw_target'],
                         '/beacon/T?d=1%2C2%2C3%2C4')
        self.assertEqual(rows[-1]['request']['query'], [['d', '1,2,3,4']])
        self.assertEqual((rows[-1]['request']['tag'], rows[-1]['request']['measurement']),
                         ('T', '1,2,3,4'))

    def test_head_501_and_send_disconnect_recovery(self):
        control = self.dispatch(self.HEAD)
        self.assertEqual(self.status(control), 501)
        self.assertEqual(control.output.getvalue().split(b'\r\n\r\n', 1)[1], b'')
        error = BrokenPipeError('501 header send')
        failed = self.dispatch(self.HEAD, fail_at=1, error=error)
        self.assertEqual(failed.calls, 1)
        self.assertIs(self.server.response_error, error)
        self.assert_healthy_beacon()

    def test_version_505_and_send_disconnect_recovery(self):
        control = self.assert_error_response(self.VERSION, 505, allow_body_only=True)
        for phase in range(1, control.calls + 1):
            error = ConnectionResetError('505 response send')
            first = self.server.response_error or error
            before = self.sink.getvalue()
            failed = self.dispatch(self.VERSION, fail_at=phase, error=error)
            self.assertEqual(failed.calls, phase)
            self.assertEqual(failed.error_calls, control.error_calls)
            self.assertIs(self.server.response_error, first)
            self.assertEqual(self.sink.getvalue(), before)
            self.assert_healthy_beacon()

    def test_known_error_reply_disconnects_at_reachable_header_and_body_sends(self):
        malformed = b'GET /static extra HTTP/1.1\r\n\r\n'
        for raw in (self.VERSION, malformed):
            control = self.assert_error_response(
                raw, 505 if raw == self.VERSION else 400,
                allow_body_only=raw == self.VERSION)
            for phase in range(1, control.calls + 1):
                for kind in (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    with self.subTest(raw=raw, phase=phase, kind=kind):
                        error = kind('send only')
                        first = self.server.response_error or error
                        before = self.sink.getvalue()
                        peer = self.dispatch(raw, fail_at=phase, error=error)
                        self.assertEqual(peer.calls, phase)  # no second response
                        self.assertEqual(peer.error_calls, control.error_calls)
                        self.assertIs(self.server.response_error, first)
                        self.assertEqual(self.sink.getvalue(), before)
                        self.assertFalse(self.server.capture_failed)
                        self.assertIsNone(self.server.first_error)
                        self.assert_healthy_beacon()

    def test_head_never_sends_an_error_body(self):
        peer = self.dispatch(self.HEAD, fail_at=2, error=BrokenPipeError('unreachable body'))
        self.assertEqual(self.status(peer), 501)
        self.assertEqual(peer.calls, 1)
        self.assertIsNone(self.server.response_error)
        self.assert_healthy_beacon()

    def test_other_inherited_rejection_paths_preserve_status_and_recovery(self):
        cases = [
            (b'GET /static extra HTTP/1.1\r\n\r\n', 400),
            (b'GET /static HTTP/1.x\r\n\r\n', 400),
            (b'GET /' + b'x' * 65537 + b' HTTP/1.1\r\n\r\n', 414),
            (b'GET /static HTTP/1.1\r\nX: ' + b'x' * 65537 + b'\r\n\r\n', 431),
            (b'GET /static HTTP/1.1\r\n' + b'X: 1\r\n' * 120 + b'\r\n', 431),
        ]
        for raw, expected in cases:
            with self.subTest(expected=expected, length=len(raw)):
                control = self.assert_error_response(
                    raw, expected, allow_body_only=raw == b'GET /static HTTP/1.x\r\n\r\n')
                for phase in range(1, control.calls + 1):
                    error = ConnectionAbortedError('error reply send')
                    first = self.server.response_error or error
                    before = self.sink.getvalue()
                    peer = self.dispatch(raw, fail_at=phase,
                                         error=error)
                    self.assertEqual(peer.calls, phase)
                    self.assertEqual(peer.error_calls, control.error_calls)
                    self.assertIs(self.server.response_error, first)
                    self.assertEqual(self.sink.getvalue(), before)
                    self.assertFalse(self.server.capture_failed)
                    self.assertIsNone(self.server.first_error)
                    self.assert_healthy_beacon()

    def test_html_preparation_disconnect_types_remain_fatal(self):
        for kind in (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            for raw in (self.HEAD, self.VERSION, b'GET /missing HTTP/1.1\r\n\r\n'):
                with self.subTest(kind=kind, raw=raw):
                    first = kind('HTML preparation failed')

                    class BadFormat:
                        def __mod__(self, values):
                            raise first

                    class Handler(serve.ProbeHandler):
                        error_message_format = BadFormat()

                    self.server.first_error = None
                    self.server.capture_failed = False
                    peer = self.dispatch(raw, handler=Handler)
                    self.assertEqual(peer.calls, 0)
                    self.assertTrue(self.server.capture_failed)
                    self.assertIs(self.server.first_error, first)
                    self.assertIsNone(self.server.response_error)
                    self.assertEqual(self.status(self.dispatch(self.BEACON)), 503)

    def test_header_preparation_failure_is_not_a_send_failure(self):
        for raw in (self.HEAD, b'GET /static HTTP/1.1\r\n\r\n'):
            first = BrokenPipeError('header preparation failure')
            self.server.first_error = None
            self.server.capture_failed = False
            with mock.patch.object(serve.ProbeHandler, 'send_header', side_effect=first):
                peer = self.dispatch(raw)
            self.assertEqual(peer.calls, 0)
            self.assertIs(self.server.first_error, first)
            self.assertTrue(self.server.capture_failed)
            self.assertIsNone(self.server.response_error)

    def test_unexpected_parser_and_file_work_remain_fatal(self):
        first = RuntimeError('unexpected parser logic')
        with mock.patch.object(serve.ProbeHandler, 'parse_request', side_effect=first):
            self.dispatch(self.HEAD)
        self.assertIs(self.server.first_error, first)
        self.assertEqual(self.status(self.dispatch(self.BEACON)), 503)
        self.server.first_error = None
        self.server.capture_failed = False
        first = ConnectionResetError('non-output file read')
        with mock.patch.object(Path, 'read_bytes', side_effect=first):
            self.dispatch(b'GET /static HTTP/1.1\r\n\r\n')
        self.assertIs(self.server.first_error, first)
        self.assertTrue(self.server.capture_failed)
        self.assertIsNone(self.server.response_error)

    def test_generic_output_oserror_remains_fatal(self):
        first = OSError('not a known disconnect')
        peer = self.dispatch(self.VERSION, fail_at=1, error=first)
        self.assertEqual(peer.calls, 1)
        self.assertIs(self.server.first_error, first)
        self.assertTrue(self.server.capture_failed)
        self.assertIsNone(self.server.response_error)
        self.assertEqual(self.status(self.dispatch(self.BEACON)), 503)

    def test_primary_failure_precedence_survives_inherited_reply_disconnect(self):
        for fault in ('short', 'write', 'flush'):
            with self.subTest(fault=fault):
                sink = FaultSink(fault)
                writer = CaptureWriter(sink)
                self.server.capture = writer
                self.server.first_error = None
                self.server.capture_failed = False
                self.server.response_error = None
                primary = self.dispatch(self.BEACON)
                self.assertEqual(self.status(primary), 500)
                self.assertNotIn(b' 204 ', primary.output.getvalue())
                self.assertEqual(primary.calls, 1)
                first = self.server.first_error
                for raw, expected in ((self.HEAD, 501), (self.VERSION, 505)):
                    control = self.assert_error_response(
                        raw, expected, allow_body_only=raw == self.VERSION)
                    for phase in range(1, control.calls + 1):
                        error = BrokenPipeError('later send')
                        response_first = self.server.response_error or error
                        before = sink.getvalue()
                        peer = self.dispatch(raw, fail_at=phase, error=error)
                        self.assertEqual(peer.calls, phase)
                        self.assertEqual(peer.error_calls, control.error_calls)
                        self.assertIs(self.server.response_error, response_first)
                        self.assertIs(self.server.first_error, first)
                        self.assertTrue(self.server.capture_failed)
                        self.assertEqual(sink.getvalue(), before)
                self.assertEqual(self.status(self.dispatch(self.BEACON)), 503)
                writer.abort()
                path = self.root / (fault + '.jsonl')
                path.write_bytes(sink.getvalue())
                self.assertEqual(verify_capture(path)['capture_integrity'], 'INCOMPLETE')

    def test_output_stream_restored_on_success_disconnect_and_preparation_failure(self):
        class Handler(serve.ProbeHandler):
            def send_error(handler, *args, **kwargs):
                original = handler.wfile
                try:
                    return super().send_error(*args, **kwargs)
                finally:
                    handler.server.stream_restored = handler.wfile is original

        self.dispatch(self.HEAD, handler=Handler)
        self.assertTrue(self.server.stream_restored)
        control = self.assert_error_response(self.VERSION, 505, allow_body_only=True,
                                             handler=Handler)
        first = ConnectionResetError('first response diagnostic')
        failed = self.dispatch(self.VERSION, fail_at=control.calls, error=first, handler=Handler)
        self.assertEqual(failed.calls, control.calls)
        self.assertIs(self.server.response_error, first)
        self.assertTrue(self.server.stream_restored)
        self.dispatch(self.HEAD, fail_at=1, error=BrokenPipeError('later'), handler=Handler)
        self.assertTrue(self.server.stream_restored)
        self.assertIs(self.server.response_error, first)
        first = BrokenPipeError('preparation error')
        with mock.patch.object(Handler, 'send_header', side_effect=first):
            self.dispatch(self.HEAD, handler=Handler)
        self.assertTrue(self.server.stream_restored)
        self.assertIs(self.server.first_error, first)

    def test_run_closes_valid_capture_after_inherited_reply_disconnect(self):
        args = SimpleNamespace(host='127.0.0.1', port=0, no_tls=True, cert=None, key=None)
        server = self.server

        def factory(address, handler, **kwargs):
            server.capture = kwargs['capture']
            server.log_file = kwargs['log_file']
            server.server_port = 0
            return server

        def loop():
            self.dispatch(self.HEAD, fail_at=1, error=BrokenPipeError('501 send'))
            control = self.assert_error_response(self.VERSION, 505, allow_body_only=True)
            failed = self.dispatch(self.VERSION, fail_at=control.calls,
                                   error=ConnectionResetError('505 send'))
            self.assertEqual(failed.calls, control.calls)
            self.assertEqual(self.status(self.dispatch(self.BEACON)), 204)

        server.serve_forever = loop
        server.server_close = lambda: None
        with mock.patch.object(serve, 'LOG_DIR', self.root), \
                mock.patch.object(serve, 'CaptureHTTPServer', factory), \
                contextlib.redirect_stdout(io.StringIO()):
            serve.run(args)
        path = next(self.root.glob('capture-*.jsonl'))
        rows = [json.loads(x) for x in path.read_bytes().splitlines()]
        self.assertEqual([r['record_type'] for r in rows], ['open', 'event', 'close'])
        self.assertEqual(rows[1]['request']['measurement'], '1,2,3,4')
        self.assertEqual(rows[-1]['accepted_count'], 1)
        self.assertEqual(verify_capture(path)['capture_integrity'], 'VALID')
        self.assertIsNone(server.first_error)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='capture-lifecycle-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.args=SimpleNamespace(host='127.0.0.1',port=0,no_tls=True,cert=None,key=None)
        self.events=[]
        events=self.events
        class Server:
            def __init__(server,address,handler,**kw):
                server.capture=kw['capture'];server.first_error=None
                server.server_port=1234;server.capture_failed=False
            def serve_forever(server):
                events.append('serve')
                server.capture.append(decode_request('GET','/beacon?m=literal'))
            def server_close(server):events.append('stop-admission')
        self.Server=Server

    def run_fixture(self):
        with mock.patch.object(serve,'LOG_DIR',self.root),mock.patch.object(serve,'CaptureHTTPServer',self.Server),contextlib.redirect_stdout(io.StringIO()):
            serve.run(self.args)

    def report(self):return verify_capture(next(self.root.glob('capture-*.jsonl')))

    def test_normal_shutdown_valid_close_once_after_admission_stops(self):
        original=CaptureWriter.close
        def close(writer):self.events.append('close');return original(writer)
        with mock.patch.object(CaptureWriter,'close',close):self.run_fixture()
        self.assertEqual(self.events,['serve','stop-admission','close'])
        self.assertEqual(self.report()['capture_integrity'],'VALID')
        self.assertEqual(self.report()['accepted_records_verified'],1)

    def test_interrupt_aborts_leaves_incomplete_and_preserves_first(self):
        original=self.Server.serve_forever
        def interrupted(server):original(server);raise KeyboardInterrupt('first interruption')
        self.Server.serve_forever=interrupted
        with mock.patch.object(CaptureWriter,'close',side_effect=AssertionError('must not close')):
            with self.assertRaises(KeyboardInterrupt):self.run_fixture()
        self.assertEqual(self.report()['capture_integrity'],'INCOMPLETE')

    def test_first_capture_error_survives_shutdown_error(self):
        first=CaptureError('first persistence error')
        def failed(server):server.first_error=first;raise RuntimeError('later loop failure')
        def close_failed(server):raise OSError('later server close failure')
        self.Server.serve_forever=failed;self.Server.server_close=close_failed
        with self.assertRaises(CaptureError) as caught:self.run_fixture()
        self.assertIs(caught.exception,first)
        self.assertEqual(self.report()['capture_integrity'],'INCOMPLETE')

    def test_open_failure_prevents_server_creation(self):
        with mock.patch.object(serve.CaptureWriter,'create',side_effect=OSError('no capture')),mock.patch.object(serve,'CaptureHTTPServer') as server:
            with self.assertRaises(OSError):self.run_fixture()
            server.assert_not_called()

    def test_bind_failure_aborts_open_capture(self):
        def fail(*args,**kw):raise OSError('bind failed')
        self.Server=fail
        with self.assertRaises(OSError):self.run_fixture()
        self.assertEqual(self.report()['capture_integrity'],'INCOMPLETE')

    def test_tls_startup_failure_aborts_open_capture(self):
        self.args.no_tls=False;self.args.cert='explicit-cert';self.args.key='explicit-key'
        first=OSError('certificate load failed')
        with mock.patch.object(serve.ssl.SSLContext,'load_cert_chain',side_effect=first):
            with self.assertRaises(OSError) as caught:self.run_fixture()
        self.assertIs(caught.exception,first)
        self.assertEqual(self.events,['stop-admission'])
        self.assertEqual(self.report()['capture_integrity'],'INCOMPLETE')

    def test_close_failure_no_duplicate_close_or_abort(self):
        original=CaptureWriter.close;calls=[]
        def failed(writer):calls.append('close');original(writer);raise OSError('reported close failure')
        with mock.patch.object(CaptureWriter,'close',failed),mock.patch.object(CaptureWriter,'abort',side_effect=AssertionError('duplicate cleanup')):
            with self.assertRaises(OSError):self.run_fixture()
        self.assertEqual(calls,['close'])
        self.assertEqual(self.report()['capture_integrity'],'VALID')

    def test_secondary_open_failure_optional(self):
        with mock.patch('builtins.open',side_effect=OSError('secondary unavailable')),contextlib.redirect_stderr(io.StringIO()):self.run_fixture()
        self.assertEqual(self.report()['capture_integrity'],'VALID')

    def test_secondary_close_failure_optional(self):
        class Secondary(io.StringIO):
            def close(self):raise OSError('secondary close failed')
        with mock.patch('builtins.open',return_value=Secondary()),contextlib.redirect_stderr(io.StringIO()):
            self.run_fixture()
        self.assertEqual(self.report()['capture_integrity'],'VALID')

    def test_server_close_failure_aborts_capture(self):
        def failed(server):raise OSError('server close failed')
        self.Server.server_close=failed
        with self.assertRaisesRegex(OSError,'server close failed'):self.run_fixture()
        self.assertEqual(self.report()['capture_integrity'],'INCOMPLETE')


@unittest.skipUnless(os.environ.get('BROWSER_RUNNER_LOOPBACK_TESTS')=='1',
                     'opt-in loopback only; offline verifier opens no listener')
class LoopbackTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='capture-loopback-')
        self.addCleanup(self.temp.cleanup)
        self.writer=CaptureWriter.create(Path(self.temp.name))
        class Handler(serve.ProbeHandler):
            body_read_timeout=0.2
            body_deadline=0.45
            def log_message(self,*args):pass
            def _log_beacon(self,*args):pass
        try:
            self.server=serve.CaptureHTTPServer(('127.0.0.1',0),Handler,capture=self.writer)
        except BaseException:
            self.writer.abort()
            raise
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.01})
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown();self.thread.join(timeout=3);self.server.server_close();self.writer.close()
        self.assertFalse(self.thread.is_alive())

    def exchange(self,wire):
        with socket.create_connection(self.server.server_address,timeout=2) as client:
            client.sendall(wire);client.shutdown(socket.SHUT_WR)
            response=b''
            while True:
                data=client.recv(8192)
                if not data:break
                response+=data
        return int(response.split(b' ',2)[1])

    def test_real_http_tagged_post_binary_and_eof(self):
        self.assertEqual(self.exchange(b'GET /beacon/P560-B-POST?d=1%2C2%2C3%2C4 HTTP/1.1\r\nHost: localhost\r\n\r\n'),204)
        self.assertEqual(self.exchange(b'POST /beacon/T HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5000\r\n\r\n'+b'x'*5000),204)
        self.assertEqual(self.exchange(b'POST /beacon/T HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n\x00\xffA'),204)
        self.assertEqual(self.exchange(b'POST /beacon/T HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nabc'),400)
        rows=[json.loads(x) for x in self.writer.path.read_bytes().splitlines()][1:]
        self.assertEqual(rows[0]['request']['measurement'],'1,2,3,4')
        self.assertEqual(base64.b64decode(rows[1]['request']['body_base64']),b'x'*5000)
        self.assertEqual(base64.b64decode(rows[2]['request']['body_base64']),b'\x00\xffA')
        self.assertEqual(len(rows),3)

    def test_real_idle_and_trickle_deadlines(self):
        for trickle in [False,True]:
            with self.subTest(trickle=trickle),socket.create_connection(self.server.server_address,timeout=2) as client:
                client.sendall(b'POST /beacon/T HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n')
                start=time.monotonic()
                if trickle:
                    # Keep each idle interval below the read timeout, but exceed total deadline.
                    for _ in range(6):
                        try:client.sendall(b'x')
                        except OSError:break
                        time.sleep(0.1)
                response=client.recv(8192)
                self.assertEqual(int(response.split(b' ',2)[1]),408)
                self.assertLess(time.monotonic()-start,1.8)
        self.assertEqual(len(self.writer.path.read_bytes().splitlines()),1)


@unittest.skipUnless(os.environ.get('BROWSER_RUNNER_LOOPBACK_TESTS')=='1',
                     'opt-in loopback only; offline verifier opens no listener')
class RunLoopbackTests(unittest.TestCase):
    def test_production_run_lifecycle_closes_capture_after_real_http(self):
        with tempfile.TemporaryDirectory(prefix='capture-run-loopback-') as directory:
            root=Path(directory);ready=threading.Event();servers=[];errors=[]
            original=serve.CaptureHTTPServer
            def factory(*args,**kwargs):
                self.assertEqual(len(list(root.glob('capture-*.jsonl'))),1)
                server=original(*args,**kwargs);servers.append(server);ready.set();return server
            args=SimpleNamespace(host='127.0.0.1',port=0,no_tls=True,cert=None,key=None)
            def run():
                try:serve.run(args)
                except BaseException as exc:errors.append(exc);ready.set()
            with mock.patch.object(serve,'LOG_DIR',root),mock.patch.object(serve,'CaptureHTTPServer',factory),contextlib.redirect_stdout(io.StringIO()):
                worker=threading.Thread(target=run);worker.start()
                try:
                    self.assertTrue(ready.wait(3));self.assertFalse(errors)
                    with socket.create_connection(servers[0].server_address,timeout=2) as client:
                        client.sendall(b'GET /beacon/P560-B-POST?d=1%2C2%2C3%2C4 HTTP/1.1\r\nHost: localhost\r\n\r\n')
                        self.assertIn(b' 204 ',client.recv(8192))
                finally:
                    if servers:servers[0].shutdown()
                    worker.join(timeout=3)
                self.assertFalse(worker.is_alive());self.assertFalse(errors)
            report=verify_capture(next(root.glob('capture-*.jsonl')))
            self.assertEqual(report['capture_integrity'],'VALID')
            self.assertEqual(report['accepted_records_verified'],1)
            self.assertEqual(report['delivery_completeness'],'UNKNOWN')


if __name__=='__main__':
    unittest.main()
