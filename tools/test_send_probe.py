#!/usr/bin/env python3
"""Integration regression tests for phase-mirrored probe result saving.

Every case runs the *real* CLI (``tools/send_probe.py`` or
``tools/send_probe.ps1``, copied verbatim into a throwaway checkout) as a
subprocess against a loopback TCP loader that speaks the loaders' wire
protocol: an 8-byte little-endian uint64 frame length followed by the raw
UTF-8 Lua bytes.  The loader records exactly what it received, replies with
controlled output bytes and closes, so the test can assert both the transport
framing and the result file the sender leaves on disk.

Saving must mirror the probe's path below the checkout's ``probes/`` directory
under ``results/`` (creating missing directories); probes outside ``probes/``
stay at the ``results/`` root.  ``results`` itself stays relative to the
caller's working directory.

Run with::

    python -m unittest discover -s tools -p "test_send_probe.py" -v

All writes stay inside a per-case temporary directory; the repository's own
``probes/`` and ``results/`` trees are never touched.
"""

import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent

PS_EXE = shutil.which("pwsh") or shutil.which("powershell")

# The Python sender prints the response it received, which includes invalid
# UTF-8.  Force UTF-8 stdio so its own console encoding can never turn a
# non-ASCII response into an unrelated stdout encoding failure on Windows.
SUBPROCESS_ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}

# Phase-scoped probe, nested probe two levels deep, root-level probe, and a
# probe in a sibling directory outside the checkout's probes/ tree.
PHASE_PROBE = "probes/phase10_untested_theories/43a_kldstat_kaslr.lua"
NESTED_PROBE = "probes/phase13_53batch/03_subdir/deep_probe.lua"
ROOT_PROBE = "probes/root_probe.lua"
EXTERNAL_PROBE = "probes-other/phase10_untested_theories/external_probe.lua"

FIXTURE_PROBES = (PHASE_PROBE, NESTED_PROBE, ROOT_PROBE, EXTERNAL_PROBE)

# Response bytes exercise binary-safety: multibyte UTF-8, NUL, high bytes,
# and mixed CRLF/LF/CR line endings that a text-mode write would corrupt.
OUTPUT_BYTES = (
    b"[*] probe output\n"
    b"phase=phase10\r\n"
    b"status=ok \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\x00\xff\xfe\n"
    b"tail\r"
)

SAVED_NAME_RE = r"^%s_\d{8}_\d{6}\.txt$"


def _lua_source(relative_path):
    """Unique Lua fixture bytes per probe: multibyte UTF-8, LF-only newlines.

    LF-only keeps the on-disk bytes identical to what both senders transmit;
    the Python sender reads its probe in universal-newline text mode, so CRLF
    would legitimately change the framed payload.
    """
    return (
        "-- fixture probe\n"
        "-- location: %s\n"
        "print('hello \u65e5\u672c\u8a9e')\n"
        "return 0\n" % relative_path
    ).encode("utf-8")


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


class _LuaLoader(threading.Thread):
    """Single-shot loopback Lua loader implementing the framing protocol."""

    def __init__(self, response):
        super().__init__(daemon=True)
        self._response = response
        self.declared_length = None
        self.payload = None
        self.error = None
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(15)
        self.port = self._listener.getsockname()[1]

    def run(self):
        conn = None
        try:
            conn, _ = self._listener.accept()
            conn.settimeout(15)
            header = _recv_exact(conn, 8)
            self.declared_length = struct.unpack("<Q", header)[0]
            if self.declared_length > 1 << 20:
                raise ValueError("implausible frame length %d" % self.declared_length)
            self.payload = _recv_exact(conn, self.declared_length)
            if self._response:
                conn.sendall(self._response)
        except Exception as exc:
            self.error = exc
        finally:
            if conn is not None:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()
            try:
                self._listener.close()
            except OSError:
                pass

    def stop(self):
        """Reap the loader thread without leaving it blocked in accept()."""
        self.join(timeout=5)
        if self.is_alive():
            # A real connection wakes a blocked accept() on every platform.
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=2).close()
            except OSError:
                pass
            self.join(timeout=5)


def _build_checkout(fixture):
    """Copy the real sender CLIs plus Lua fixtures into a throwaway checkout."""
    tools = fixture / "tools"
    tools.mkdir(parents=True)
    shutil.copy2(TOOLS_DIR / "send_probe.py", tools / "send_probe.py")
    shutil.copy2(TOOLS_DIR / "send_probe.ps1", tools / "send_probe.ps1")
    for relative_path in FIXTURE_PROBES:
        probe = fixture / relative_path
        probe.parent.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(_lua_source(relative_path))


def _cases():
    """Table of probe/cwd/save combinations shared by both CLI suites."""
    return [
        {
            "label": "phase directory probe mirrors its phase directory",
            "arg": "relative",
            "probe": PHASE_PROBE,
            "expect_dir": "phase10_untested_theories",
        },
        {
            "label": "nested phase directories are all mirrored",
            "arg": "relative",
            "probe": NESTED_PROBE,
            "expect_dir": "phase13_53batch/03_subdir",
        },
        {
            "label": "existing phase destination is reused",
            "arg": "relative",
            "probe": PHASE_PROBE,
            "expect_dir": "phase10_untested_theories",
            "precreate": ("phase10_untested_theories",),
        },
        {
            "label": "absolute probe argument invoked outside the checkout",
            "arg": "absolute",
            "probe": PHASE_PROBE,
            "cwd": None,
            "expect_dir": "phase10_untested_theories",
        },
        {
            "label": "root probe stays at the results root",
            "arg": "relative",
            "probe": ROOT_PROBE,
            "expect_dir": "",
        },
        {
            "label": "external sibling probe-other stays at the results root",
            "arg": "relative",
            "probe": EXTERNAL_PROBE,
            "expect_dir": "",
            "precreate": ("phase10_untested_theories",),
        },
        {
            "label": "no save flag writes nothing",
            "arg": "relative",
            "probe": PHASE_PROBE,
            "save": False,
            "expect_dir": None,
        },
        {
            "label": "empty response writes nothing",
            "arg": "relative",
            "probe": PHASE_PROBE,
            "response": b"",
            "expect_dir": None,
        },
    ]


class PhaseResultCaptureTests(unittest.TestCase):
    def _run_case(self, cli, case):
        save = case.get("save", True)
        cwd_rel = case.get("cwd", ".")
        precreate = case.get("precreate", ())
        response = case.get("response", OUTPUT_BYTES)
        expect_dir = case["expect_dir"]

        with tempfile.TemporaryDirectory(prefix="probe-fixture-") as tmp:
            base = Path(tmp)
            fixture = base / "checkout"
            _build_checkout(fixture)

            if cwd_rel is None:
                run_cwd = base / "outside"  # outside the copied checkout
                run_cwd.mkdir()
            else:
                run_cwd = fixture / cwd_rel

            results_root = run_cwd / "results"
            for relative_dir in precreate:
                (results_root / relative_dir).mkdir(parents=True, exist_ok=True)

            probe_path = fixture / case["probe"]
            lua_bytes = probe_path.read_bytes()
            probe_arg = str(probe_path) if case["arg"] == "absolute" else case["probe"]

            loader = _LuaLoader(response)
            loader.start()
            if cli == "py":
                cmd = [
                    sys.executable,
                    str(fixture / "tools" / "send_probe.py"),
                    probe_arg,
                    "--ip", "127.0.0.1",
                    "--port", str(loader.port),
                ]
                if save:
                    cmd.append("--save")
            else:
                cmd = [
                    PS_EXE,
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-File", str(fixture / "tools" / "send_probe.ps1"),
                    probe_arg,
                    "-Ip", "127.0.0.1",
                    "-Port", str(loader.port),
                ]
                if save:
                    cmd.append("-Save")
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=str(run_cwd),
                    capture_output=True,
                    timeout=90,
                    env=SUBPROCESS_ENV,
                )
            finally:
                loader.stop()

            detail = "stdout=%r stderr=%r" % (
                proc.stdout[-2000:], proc.stderr[-2000:]
            )
            self.assertEqual(proc.returncode, 0, "sender failed: %s" % detail)
            self.assertIsNone(loader.error, "loader error %r: %s" % (loader.error, detail))
            self.assertEqual(loader.declared_length, len(lua_bytes),
                             "frame length mismatch: %s" % detail)
            self.assertEqual(loader.payload, lua_bytes,
                             "transport payload mismatch: %s" % detail)

            saved = []
            if results_root.is_dir():
                saved = sorted(
                    path.relative_to(results_root)
                    for path in results_root.rglob("*")
                    if path.is_file()
                )
            stem = Path(case["probe"]).stem

            if expect_dir is None:
                self.assertEqual(saved, [],
                                 "unexpected saved results %s: %s" % (saved, detail))
                return

            wanted_dir = Path(expect_dir) if expect_dir else Path(".")
            names = [path.name for path in saved if path.parent == wanted_dir]
            self.assertEqual(len(names), 1,
                             "expected one result in %s, saw %s: %s"
                             % (wanted_dir, saved, detail))
            name = names[0]
            self.assertRegex(name, SAVED_NAME_RE % re.escape(stem))
            self.assertEqual(saved, [wanted_dir / name],
                             "unexpected results tree %s: %s" % (saved, detail))
            self.assertEqual((results_root / wanted_dir / name).read_bytes(),
                             response, "saved bytes differ: %s" % detail)

    def test_python_sender(self):
        for case in _cases():
            with self.subTest(case=case["label"]):
                self._run_case("py", case)

    @unittest.skipIf(PS_EXE is None, "PowerShell (pwsh or powershell) not available")
    def test_powershell_sender_mirrors_phase_path_through_posix_temp_alias(self):
        """A pwsh-on-POSIX invocation keeps a phase path through /tmp aliases."""
        case = _cases()[0]
        self._run_case("ps", case)

    @unittest.skipIf(PS_EXE is None, "PowerShell (pwsh or powershell) not available")
    def test_powershell_sender(self):
        for case in _cases():
            with self.subTest(case=case["label"]):
                self._run_case("ps", case)


if __name__ == "__main__":
    unittest.main()
