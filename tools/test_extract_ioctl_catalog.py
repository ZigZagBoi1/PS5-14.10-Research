#!/usr/bin/env python3
"""Tests for tools/extract_ioctl_catalog.py."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools import extract_ioctl_catalog


class EmptyScanTests(unittest.TestCase):
    def test_text_without_candidates_reports_zero_and_writes_empty_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = Path(tmp) / "kernel.bin"
            out = Path(tmp) / "catalog.json"
            text.write_bytes(b"\x90" * 64)
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = extract_ioctl_catalog.main([
                    "--text", str(text), "--out", str(out),
                ])
            self.assertEqual(code, 0)
            self.assertIn("0 ioctl-like constants", captured.getvalue())
            self.assertEqual(json.loads(out.read_text(encoding="utf-8")), [])


if __name__ == "__main__":
    unittest.main()
