#!/usr/bin/env python3
"""Loopback regression tests for the loader lifecycle helpers.

``tools/send_probe.py`` is both a CLI and the transport module imported by the
sweep and restart drivers.  Commit 9936faa deleted four public helpers from it -
``loader_is_up``, ``loader_answers``, ``wait_for_loader`` and ``run_source`` -
while the drivers kept importing them, so the tools failed before they could
open a socket.  These tests pin the helper behavior itself:

* an accepting listener is not the same as a live Lua thread,
* a wait only succeeds when the requested readiness condition is met,
* generated Lua source goes through the normal framing and its transcript is
  returned instead of being saved, with its temporary file removed even when
  the connection fails.

Everything runs against a loopback listener on ``127.0.0.1`` with an
OS-assigned port.  No probe is executed, no result tree is written, and no
console is contacted.
"""

import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from tools import send_probe


def _unused_port():
    """Return a loopback port that is closed again before use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _recv_exact(sock, count):
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("closed after %d of %d bytes" % (count - remaining, count))
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame(conn):
    """Read one loader frame: 8-byte little-endian length, then Lua bytes."""
    length = struct.unpack("<Q", _recv_exact(conn, 8))[0]
    if length > 1 << 20:
        raise ValueError("implausible frame length %d" % length)
    return _recv_exact(conn, length)


class _LoopbackLoader(threading.Thread):
    """Accept a fixed number of loopback connections and run ``handler`` on each."""

    def __init__(self, handler, limit=1):
        super().__init__(daemon=True)
        self._handler = handler
        self._limit = limit
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(10)
        self.port = self._listener.getsockname()[1]
        self.handled = 0
        self.error = None

    def run(self):
        try:
            while self.handled < self._limit:
                try:
                    conn, _ = self._listener.accept()
                except OSError:
                    return
                self.handled += 1
                try:
                    self._handler(conn, self)
                except Exception as exc:  # surface fixture failures in the test
                    self.error = exc
                    return
                finally:
                    try:
                        conn.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    conn.close()
        finally:
            try:
                self._listener.close()
            except OSError:
                pass

    def stop(self):
        """Reap the thread without leaving it blocked in accept()."""
        self.join(timeout=2)
        if self.is_alive():
            try:
                self._listener.close()
            except OSError:
                pass
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
            except OSError:
                pass
            self.join(timeout=2)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.stop()
        return False


class LoaderIsUpTests(unittest.TestCase):
    def test_accepting_listener_is_up_and_receives_no_bytes(self):
        received = []

        def handler(conn, _server):
            conn.settimeout(1)
            received.append(conn.recv(64))

        with _LoopbackLoader(handler) as server:
            self.assertTrue(send_probe.loader_is_up("127.0.0.1", server.port,
                                                    connect_timeout=1))
        self.assertIsNone(server.error)
        self.assertEqual(received, [b""], "loader_is_up must send nothing")

    def test_closed_port_is_down(self):
        self.assertFalse(send_probe.loader_is_up("127.0.0.1", _unused_port(),
                                                 connect_timeout=0.5))


class LoaderAnswersTests(unittest.TestCase):
    def test_marker_reply_means_the_lua_thread_is_alive(self):
        requests = []

        def handler(conn, _server):
            requests.append(_read_frame(conn))
            conn.sendall(b"LOADER-READY\n")

        with _LoopbackLoader(handler) as server:
            self.assertTrue(send_probe.loader_answers("127.0.0.1", server.port,
                                                      timeout=1))
        self.assertIsNone(server.error)
        self.assertEqual(requests, [b'print("LOADER-READY")\n'])

    def test_marker_split_across_reads_is_reassembled(self):
        def handler(conn, _server):
            _read_frame(conn)
            conn.sendall(b"LOADER-")
            time.sleep(0.02)
            conn.sendall(b"READY\n")

        with _LoopbackLoader(handler) as server:
            self.assertTrue(send_probe.loader_answers("127.0.0.1", server.port,
                                                      timeout=1))
        self.assertIsNone(server.error)

    def test_listener_that_accepts_but_never_answers_is_not_alive(self):
        requests = []

        def handler(conn, _server):
            requests.append(_read_frame(conn))

        with _LoopbackLoader(handler) as server:
            self.assertFalse(send_probe.loader_answers("127.0.0.1", server.port,
                                                       timeout=0.2))
        self.assertIsNone(server.error)
        self.assertEqual(len(requests), 1)

    def test_unrelated_reply_is_not_the_marker(self):
        def handler(conn, _server):
            _read_frame(conn)
            conn.sendall(b"loader-ready\n")

        with _LoopbackLoader(handler) as server:
            self.assertFalse(send_probe.loader_answers("127.0.0.1", server.port,
                                                       timeout=1))
        self.assertIsNone(server.error)

    def test_refused_connection_is_not_alive(self):
        self.assertFalse(send_probe.loader_answers("127.0.0.1", _unused_port(),
                                                   timeout=0.5))


class WaitForLoaderTests(unittest.TestCase):
    def test_returns_immediately_when_the_port_accepts(self):
        logs = []
        with _LoopbackLoader(lambda _conn, _server: None) as server:
            self.assertTrue(send_probe.wait_for_loader(
                "127.0.0.1", server.port, timeout=1, poll=0.01,
                log=logs.append))
        self.assertIsNone(server.error)
        self.assertEqual(logs, [])

    def test_times_out_with_the_documented_messages(self):
        logs = []
        started = time.monotonic()
        result = send_probe.wait_for_loader(
            "127.0.0.1", _unused_port(), timeout=0.2, poll=0.02,
            log=logs.append)
        elapsed = time.monotonic() - started
        self.assertFalse(result)
        self.assertGreaterEqual(elapsed, 0.2)
        self.assertLess(elapsed, 5)
        self.assertTrue(any("Loader is down" in line for line in logs))
        self.assertTrue(any("Gave up waiting for the loader" in line
                            for line in logs))

    def test_answers_mode_ignores_a_socket_without_a_thread(self):
        """The first answering probe is silent; the second one must decide it."""
        connections = []

        def handler(conn, server):
            connections.append(server.handled)
            if server.handled == 4:
                _read_frame(conn)
                conn.sendall(b"LOADER-READY\n")

        logs = []
        with _LoopbackLoader(handler, limit=4) as server:
            self.assertTrue(send_probe.wait_for_loader(
                "127.0.0.1", server.port, timeout=2, poll=0.01,
                log=logs.append, answers=True))
        self.assertIsNone(server.error)
        self.assertEqual(connections, [1, 2, 3, 4])
        self.assertTrue(any("Loader is down" in line for line in logs))
        self.assertTrue(any("Loader is answering again" in line
                            for line in logs))

    def test_answers_mode_stops_on_a_silent_listener_budget(self):
        logs = []
        result = send_probe.wait_for_loader(
            "127.0.0.1", _unused_port(), timeout=0.2, poll=0.02,
            log=logs.append, answers=True)
        self.assertFalse(result)
        self.assertTrue(any("Gave up waiting for the loader" in line
                            for line in logs))


class RunSourceTests(unittest.TestCase):
    def test_sends_generated_source_and_returns_the_transcript(self):
        source = "print('generated probe')\nreturn 0\n"
        requests = []

        def handler(conn, _server):
            requests.append(_read_frame(conn))
            conn.sendall(b"generated probe\nDONE\n")

        with tempfile.TemporaryDirectory(prefix="run-source-") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                with _LoopbackLoader(handler) as server:
                    status, text = send_probe.run_source(
                        "127.0.0.1", server.port, source, timeout=1)
                self.assertFalse(Path("results").exists(),
                                 "generated source must not be saved")
            finally:
                os.chdir(previous)

        self.assertIsNone(server.error)
        self.assertEqual(status, send_probe.STATUS_COMPLETE)
        self.assertIn("generated probe\nDONE\n", text)
        self.assertEqual(requests, [source.encode("utf-8")])

    def test_refused_connection_is_reported_and_temporary_file_is_removed(self):
        created = []
        real_mkstemp = tempfile.mkstemp

        def recording_mkstemp(*args, **kwargs):
            handle, path = real_mkstemp(*args, **kwargs)
            created.append(path)
            return handle, path

        with mock.patch.object(tempfile, "mkstemp",
                               side_effect=recording_mkstemp):
            status, text = send_probe.run_source(
                "127.0.0.1", _unused_port(), "print('never sent')\n",
                timeout=0.5)

        # A closed loopback port normally refuses, but some Windows stacks
        # report the failed connect as a timeout instead.  Either way the
        # payload must not be saved and the temporary file must be gone.
        self.assertIn(status, (send_probe.STATUS_CONNECTION_REFUSED,
                               send_probe.STATUS_CONNECT_TIMEOUT))
        self.assertTrue("Connection refused" in text or
                        "Connection timed out" in text)
        self.assertEqual(len(created), 1)
        self.assertFalse(os.path.exists(created[0]))


class PublicSurfaceTests(unittest.TestCase):
    def test_helpers_remain_importable_from_the_transport_module(self):
        for name in ("loader_is_up", "loader_answers", "wait_for_loader",
                     "run_source"):
            self.assertTrue(callable(getattr(send_probe, name, None)),
                            "tools.send_probe must export %s" % name)
