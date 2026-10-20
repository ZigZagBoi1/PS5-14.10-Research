#!/usr/bin/env python3
"""Tests for tools/syscall_isolation_sweep.py.

The integration test runs the real driver against a mock loader over a real
socket, so the 8-byte framing, the generated Lua and the classification are all
exercised. The mock executes the probe with Lua 5.1 via ``lupa``; for a
"lethal" number it returns the response truncated at the sentinel line and
closes the connection, which is what the real loader looks like when the
process dies inside the call.
"""

import re
import socket
import socketserver
import struct
import threading
import unittest

import lupa

from tools import syscall_isolation_sweep as sweep

SETUP_LUA = """
syscall = { pipe = { syscall_no = 0 } }
setmetatable(syscall.pipe, {
    __call = function(self, a, b, c, d, e, f)
        if __behavior == 'raise' then error('mock failure') end
        return 42
    end,
})
uint64 = function(x) return x end
"""


def _run_lua(source, behavior):
    """Execute a probe chunk and return the captured print output."""
    captured = []
    runtime = lupa.LuaRuntime(unpack_returned_tuples=True)
    globals_ = runtime.globals()
    globals_["__behavior"] = behavior
    globals_["capture"] = lambda text: captured.append(text)
    runtime.execute(
        "print = function(...) "
        "local parts = {} "
        "for i = 1, select('#', ...) do parts[i] = tostring(select(i, ...)) end "
        "capture(table.concat(parts, '\\t')) "
        "end"
    )
    runtime.execute(SETUP_LUA)
    try:
        runtime.execute(source)
    except lupa.LuaError:
        # The driver wraps the call in pcall, so this only fires if the mock
        # itself is wrong.
        raise
    return "\n".join(captured) + ("\n" if captured else "")


class MockLoader(socketserver.ThreadingTCPServer):
    """Accepts the loader's framing and answers from a behaviour table."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, behaviours):
        self.behaviours = behaviours
        super().__init__(("127.0.0.1", 0), MockHandler)

    @property
    def port(self):
        return self.server_address[1]


class MockHandler(socketserver.BaseRequestHandler):
    def handle(self):
        behaviours = self.server.behaviours
        header = self._recv_exact(8)
        if header is None:
            return
        (length,) = struct.unpack("<Q", header)
        body = self._recv_exact(length)
        if body is None:
            return
        source = body.decode("utf-8")
        match = re.search(r"make_syscall\((\d+)\)", source)
        num = int(match.group(1)) if match else -1
        behaviour = behaviours.get(num, "return")

        if behaviour == "refuse":
            return

        output = _run_lua(source, "raise" if behaviour == "raise" else "return")
        if behaviour == "lethal":
            # The process died inside the call: only the sentinel reached us.
            sentinel = sweep.SENTINEL.format(num=num)
            kept = []
            for line in output.splitlines():
                kept.append(line)
                if line.strip() == sentinel:
                    break
            output = "\n".join(kept) + "\n"
        self.request.sendall(output.encode("utf-8"))

    def _recv_exact(self, count):
        chunks = []
        remaining = count
        while remaining:
            chunk = self.request.recv(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


class ParseRangeTests(unittest.TestCase):
    def test_single_number(self):
        self.assertEqual(sweep.parse_range("661"), [661])

    def test_inclusive_range(self):
        self.assertEqual(sweep.parse_range("661-664"), [661, 662, 663, 664])

    def test_mixed_list_and_range(self):
        self.assertEqual(sweep.parse_range("661,663-664"), [661, 663, 664])

    def test_descending_range_is_rejected(self):
        with self.assertRaises(ValueError):
            sweep.parse_range("670-661")

    def test_empty_spec_is_rejected(self):
        with self.assertRaises(ValueError):
            sweep.parse_range(" , ")


class BuildProbeTests(unittest.TestCase):
    def test_probe_carries_its_own_number(self):
        source = sweep.build_probe(662)
        self.assertIn("SWEEP SENTINEL 662", source)
        self.assertIn("SWEEP RESULT 662", source)
        self.assertIn("=== SWEEP DONE 662 ===", source)
        self.assertIn("make_syscall(662)", source)

    def test_probe_passes_six_zero_arguments(self):
        source = sweep.build_probe(661)
        self.assertIn("uint64(0), uint64(0), uint64(0), uint64(0), "
                      "uint64(0), uint64(0)", source)

    def test_probe_wraps_the_call_in_pcall(self):
        self.assertIn("pcall(function()", sweep.build_probe(661))

    def test_probe_reports_returns_without_numeric_coercion(self):
        source = sweep.build_probe(661)
        self.assertIn("local function describe(v)", source)
        self.assertIn("describe(probe_ret)", source)
        # %d on userdata throws inside string.format, so the template must not
        # use it on the raw return value. tostring(describe()) is safe.
        self.assertNotIn("ret=%d", source)


class ClassifyTests(unittest.TestCase):
    def test_returned_value(self):
        out = "=== SWEEP SENTINEL 661 ===\nSWEEP RESULT 661 ok=1 ret=42\n"
        self.assertEqual(sweep.classify(out, 661), (sweep.RETURNED, "ret=42"))

    def test_lua_error(self):
        out = "=== SWEEP SENTINEL 661 ===\nSWEEP RESULT 661 ok=0 err=mock failure\n"
        self.assertEqual(sweep.classify(out, 661), (sweep.RAISED, "err=mock failure"))

    def test_sentinel_without_result_is_a_kill(self):
        out = "=== SWEEP SENTINEL 661 ===\n"
        self.assertEqual(sweep.classify(out, 661), (sweep.KILLED_IN_CALL, None))

    def test_empty_response_is_no_output(self):
        self.assertEqual(sweep.classify("", 661), (sweep.NO_OUTPUT, None))

    def test_missing_connection(self):
        self.assertEqual(sweep.classify(None, 661), (sweep.CONNECT_FAILED, None))

    def test_another_numbers_result_is_not_credited(self):
        # If the loader echoes a neighbouring result, 661 must not borrow it.
        out = ("=== SWEEP SENTINEL 661 ===\n"
               "SWEEP RESULT 662 ok=1 ret=42\n")
        self.assertEqual(sweep.classify(out, 661), (sweep.KILLED_IN_CALL, None))


class ReportTests(unittest.TestCase):
    def test_report_names_survivors_and_lethal_numbers(self):
        records = [
            {"num": 661, "status": sweep.KILLED_IN_CALL, "aborted": False,
             "attempts": [{"status": sweep.KILLED_IN_CALL, "detail": None}]},
            {"num": 662, "status": sweep.RETURNED, "aborted": False,
             "attempts": [{"status": sweep.RETURNED, "detail": "ret=42"}]},
        ]
        report = sweep.format_report(records)
        self.assertIn("Process terminated inside: 661", report)
        self.assertIn("Returned values from: 662", report)
        self.assertIn("KILLED_IN_CALL=1", report)


class SweepIntegrationTests(unittest.TestCase):
    """End to end over a real socket, against a Lua-backed mock loader."""

    def _start(self, behaviours):
        server = MockLoader(behaviours)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            # Windows raises WinError 10038 if the socket closes while the
            # serve_forever loop is still selecting, so join before closing.
            server.shutdown()
            thread.join(2.0)
            server.server_close()

        self.addCleanup(stop)
        return server

    def _transport(self, server):
        def transport(source):
            return sweep.tcp_transport("127.0.0.1", server.port, source,
                                       timeout=5.0)
        return transport

    def test_lethal_number_does_not_hide_the_rest_of_the_range(self):
        # This is the regression the driver exists for: 54c stopped at 661 and
        # 662-670 were never executed.
        server = self._start({661: "lethal", 662: "return", 663: "raise"})
        records = sweep.sweep([661, 662, 663], self._transport(server),
                              delay=0.0, sleep=lambda _s: None)
        self.assertEqual([r["status"] for r in records],
                         [sweep.KILLED_IN_CALL, sweep.RETURNED, sweep.RAISED])
        self.assertFalse(any(r["aborted"] for r in records))

    def test_every_number_uses_its_own_connection(self):
        server = self._start({661: "lethal", 662: "lethal", 663: "return"})
        seen = []

        def transport(source):
            seen.append(source)
            return sweep.tcp_transport("127.0.0.1", server.port, source,
                                       timeout=5.0)

        records = sweep.sweep([661, 662, 663], transport,
                              delay=0.0, sleep=lambda _s: None)
        self.assertEqual(len(seen), 3)
        self.assertEqual([r["status"] for r in records],
                         [sweep.KILLED_IN_CALL, sweep.KILLED_IN_CALL,
                          sweep.RETURNED])

    def test_refused_connection_aborts_instead_of_misreporting(self):
        # Bind and close to get a port nothing is listening on.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()

        def transport(source):
            return sweep.tcp_transport("127.0.0.1", dead_port, source,
                                       timeout=2.0)

        records = sweep.sweep([661, 662, 663], transport,
                              delay=0.0, sleep=lambda _s: None)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["aborted"])
        self.assertEqual(records[0]["status"], sweep.CONNECT_FAILED)

    def test_silent_number_aborts_instead_of_burning_the_range(self):
        # A call that parks the Lua thread leaves the port open but never
        # answers; without the guard every later number costs a full timeout.
        seen = []

        def transport(source):
            seen.append(source)
            return ""

        records = sweep.sweep([1, 2, 3], transport, delay=0.0,
                              sleep=lambda _s: None)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["aborted"])
        self.assertEqual(records[0]["status"], sweep.NO_OUTPUT)
        self.assertEqual(len(records[0]["attempts"]), 2)
        self.assertEqual(len(seen), 2)

    def test_wedge_guard_can_be_disabled(self):
        def transport(source):
            return ""

        records = sweep.sweep([1, 2], transport, delay=0.0,
                              sleep=lambda _s: None, wedge_guard=False)
        self.assertEqual([r["status"] for r in records],
                         [sweep.NO_OUTPUT, sweep.NO_OUTPUT])
        self.assertFalse(any(r["aborted"] for r in records))

    def test_repeat_records_every_attempt(self):
        server = self._start({662: "return"})
        records = sweep.sweep([662], self._transport(server), delay=0.0,
                              sleep=lambda _s: None, repeat=2)
        self.assertEqual(len(records[0]["attempts"]), 2)
        self.assertEqual(records[0]["status"], sweep.RETURNED)


if __name__ == "__main__":
    unittest.main()
