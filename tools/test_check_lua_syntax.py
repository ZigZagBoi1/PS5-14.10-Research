#!/usr/bin/env python3
"""Tests for tools/check_lua_syntax.py."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

try:
    from tools import check_lua_syntax
except ImportError:  # lupa is optional
    check_lua_syntax = None


@unittest.skipUnless(check_lua_syntax, "lupa not installed")
class CheckLuaSyntaxTests(unittest.TestCase):
    def test_one_unreadable_probe_is_reported_without_aborting_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probes = root / "probes"
            probes.mkdir()
            (probes / "good.lua").write_text("print('ok')\n", encoding="utf-8")
            (probes / "bad.lua").write_bytes(b"print('bad')\xff\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = check_lua_syntax.main(root)
            self.assertTrue(code)
            text = out.getvalue()
            self.assertIn("Compiled 2 Lua 5.1 probe sources; failures=1", text)
            self.assertIn("bad.lua: probe source was not valid UTF-8", text)

    def test_the_committed_probe_corpus_compiles(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = check_lua_syntax.main(ROOT)
        self.assertFalse(code, out.getvalue())


if __name__ == "__main__":
    unittest.main()
