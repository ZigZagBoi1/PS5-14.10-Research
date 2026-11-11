#!/usr/bin/env python3
"""Tests for tools/regen_archives.py."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import regen_archives


class RegenArchivesCheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "probes").mkdir()
        (self.root / "results").mkdir()
        (self.root / "docs").mkdir()
        (self.root / "probes" / "probe.lua").write_text("print('hi')\n",
                                                        encoding="utf-8")
        (self.root / "results" / "run.txt").write_text("result\n",
                                                       encoding="utf-8")
        self._patches = [
            mock.patch.object(regen_archives, "ROOT", self.root),
            mock.patch.object(regen_archives, "DOCS", self.root / "docs"),
        ]
        for patch in self._patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self._patches):
            patch.stop()
        self._tmp.cleanup()

    def _check(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = regen_archives.main(["--check"])
        return code, out.getvalue()

    def test_check_fails_when_an_archive_is_missing_or_stale(self):
        code, out = self._check()
        self.assertEqual(code, 1)
        self.assertIn("STALE", out)

    def test_archive_output_does_not_depend_on_the_calendar_day(self):
        source = self.root / "probes" / "probe.lua"
        first = regen_archives.render_archive(
            "Title", "Intro", self.root / "probes", [source], "probes")
        second = regen_archives.render_archive(
            "Title", "Intro", self.root / "probes", [source], "probes")
        self.assertEqual(first, second)
        self.assertNotIn("Regenerated 20", first)

    def test_write_then_check_is_current(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(regen_archives.main([]), 0)
        code, out = self._check()
        self.assertEqual(code, 0)
        self.assertIn("current", out)


if __name__ == "__main__":
    unittest.main()
