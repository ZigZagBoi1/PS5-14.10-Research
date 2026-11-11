"""Regression: a FREE before any RDI load must not reference an unbound slot."""

import contextlib
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import capstone  # optional offline dependency
except ImportError:  # pragma: no cover - exercised only without optional deps
    capstone = None

from tools import handler_ptrfree


@unittest.skipUnless(capstone is not None, "capstone not installed")
class HandlerPtrfreeTests(unittest.TestCase):
    def test_free_before_any_rdi_load_does_not_crash(self):
        base = handler_ptrfree.BASE
        free = handler_ptrfree.FREE
        relative = free - (base + 5)
        kernel = b"\xe8" + struct.pack("<i", relative) + b"\xc3"
        sysent = struct.pack("<IIQ", 2, 0, base) + b"\x00" * 48
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "kernel_text.bin").write_bytes(kernel)
            (root / "sysent_raw.bin").write_bytes(sysent)
            out = io.StringIO()
            with mock.patch.object(sys, "argv", ["handler_ptrfree.py", "--dump", str(root)]), \
                    contextlib.redirect_stdout(out):
                self.assertEqual(handler_ptrfree.main(), 0)
        self.assertIn("0 sites", out.getvalue())


if __name__ == "__main__":
    unittest.main()
