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


if __name__ == "__main__":
    unittest.main()
