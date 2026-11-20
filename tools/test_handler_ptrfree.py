"""Regression: a FREE before any RDI load must not reference an unbound slot."""

import contextlib
import io
import subprocess
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

@unittest.skipUnless(capstone is not None, "capstone not installed")
class HandlerPtrfreeTests(unittest.TestCase):
    def test_free_before_any_rdi_load_does_not_crash(self):
        from tools import handler_ptrfree

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


class OptionalDependencyTests(unittest.TestCase):
    def test_missing_capstone_skips_analysis_without_import_error(self):
        code = '''
import importlib.abc
import sys
import unittest

class BlockCapstone(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "capstone" or fullname.startswith("capstone."):
            raise ModuleNotFoundError("capstone deliberately unavailable", name="capstone")

sys.meta_path.insert(0, BlockCapstone())
from tools import test_handler_ptrfree
suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_handler_ptrfree.HandlerPtrfreeTests)
result = unittest.TextTestRunner().run(suite)
assert result.wasSuccessful() and len(result.skipped) == 1
assert "tools.handler_ptrfree" not in sys.modules
'''
        result = subprocess.run([sys.executable, "-c", code],
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
