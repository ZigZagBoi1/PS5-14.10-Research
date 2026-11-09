#!/usr/bin/env python3
"""Containment tests for the browser runner's static file helper."""

import tempfile
import unittest
from pathlib import Path

from tools.browser_runner import serve


class SafeFileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="browser-runner-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.base = self.root / "public"
        self.base.mkdir()
        (self.base / "index.html").write_text("ok", encoding="utf-8")
        (self.root / "secret.key").write_text("secret", encoding="utf-8")

    def test_serves_file_inside_base(self):
        self.assertEqual(
            serve._safe_file(self.base, "index.html"),
            (self.base / "index.html").resolve(),
        )

    def test_rejects_parent_traversal(self):
        self.assertIsNone(serve._safe_file(self.base, "../secret.key"))

    def test_rejects_absolute_path(self):
        self.assertIsNone(serve._safe_file(self.base, str(self.root / "secret.key")))

    def test_rejects_directory(self):
        (self.base / "sub").mkdir()
        self.assertIsNone(serve._safe_file(self.base, "sub"))

    def test_rejects_symlink_outside_base(self):
        link = self.base / "link.key"
        try:
            link.symlink_to(self.root / "secret.key")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")
        self.assertIsNone(serve._safe_file(self.base, link.name))


class BeaconLogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="browser-runner-log-")
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "beacons.log"
        self.stream = self.path.open("w", encoding="utf-8")
        self.addCleanup(self.stream.close)
        self.handler = serve.ProbeHandler.__new__(serve.ProbeHandler)
        self.handler.client_address = ("192.0.2.10", 54321)
        old_log = serve.ProbeHandler.log_file
        serve.ProbeHandler.log_file = self.stream
        self.addCleanup(setattr, serve.ProbeHandler, "log_file", old_log)

    def test_beacon_newlines_do_not_create_extra_records(self):
        self.handler._log_beacon("first\r\nsecond\n[FORGED] third")
        self.stream.flush()
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("first\\r\\nsecond\\n[FORGED] third", lines[0])

    def test_beacon_escapes_every_splitlines_separator(self):
        separators = "\v\f\x1c\x1d\x1e\x85\u2028\u2029"
        self.handler._log_beacon("before" + separators + "after")
        self.stream.flush()
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn(
            "before\\v\\f\\x1c\\x1d\\x1e\\x85\\u2028\\u2029after",
            lines[0],
        )

    def test_beacon_keeps_utf8(self):
        self.handler._log_beacon("caf\u00e9")
        self.stream.flush()
        self.assertIn("caf\u00e9", self.path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
