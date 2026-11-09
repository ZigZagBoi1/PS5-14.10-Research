#!/usr/bin/env python3
"""Tests for the V88 forge geometry settlement and probe integrity (Issue #179).

Validates the structure, offsets, and safety properties of the reconciliation
probes: p578 (vtable slot discrimination), p579 (wrapper slot sweep), and
p582 (table geometry discrimination).
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent


class V88ForgeGeometryTests(unittest.TestCase):
    P578 = ROOT / "probes" / "phase13_webkit" / "p578-vtable-slot-discrimination.html"
    P579 = ROOT / "probes" / "phase13_webkit" / "p579-wrapper-slot-sweep.html"
    P582 = ROOT / "probes" / "phase13_webkit" / "p582-table-geometry-discrim.html"
    DOC = ROOT / "docs" / "V88_FORGE_GEOMETRY_RECONCILIATION.md"

    def test_probes_exist(self):
        self.assertTrue(self.P578.is_file(), "p578 probe file missing")
        self.assertTrue(self.P579.is_file(), "p579 probe file missing")
        self.assertTrue(self.P582.is_file(), "p582 probe file missing")

    def test_reconciliation_document_covers_all_contradictions(self):
        self.assertTrue(self.DOC.is_file(), "Reconciliation document missing")
        text = self.DOC.read_text(encoding="utf-8")
        self.assertIn("C1:", text)
        self.assertIn("C2:", text)
        self.assertIn("C3:", text)
        self.assertIn("C4:", text)
        self.assertIn("192", text)

    def test_script_tags_are_well_formed(self):
        for path in (self.P578, self.P579, self.P582):
            content = path.read_text(encoding="utf-8")
            open_scripts = len(re.findall(r"<script\b", content))
            close_scripts = len(re.findall(r"</script\s*>", content))
            self.assertEqual(open_scripts, close_scripts, f"Mismatched script tags in {path.name}")
            self.assertGreaterEqual(open_scripts, 1, f"No script tags in {path.name}")

    def test_size_class_is_192_bytes(self):
        for path in (self.P578, self.P579, self.P582):
            content = path.read_text(encoding="utf-8")
            self.assertIn("SIZE=192", content.replace(" ", ""), f"SIZE must be 192 in {path.name}")

    def test_p578_arms_all_vtable_slots(self):
        content = self.P578.read_text(encoding="utf-8")
        self.assertIn("0x41414141", content)
        self.assertIn("P578-S2-SENTINELS-ARMED", content)
        self.assertIn("fontStateChgA", content)
        self.assertIn("fontStateChgB", content)

    def test_p579_sweeps_wrapper_slot(self):
        content = self.P579.read_text(encoding="utf-8")
        self.assertIn("P579-SETUP-mode=", content)
        self.assertIn("MODE === '0'", content)
        self.assertIn("MODE === '1'", content)
        self.assertIn("MODE === 'ffff'", content)
        self.assertIn("MODE === 'leaked'", content)

    def test_p582_tests_impl_and_entry_geometry(self):
        content = self.P582.read_text(encoding="utf-8")
        self.assertIn("GEOM === 'impl'", content)
        self.assertIn("P582-SETUP-geom=", content)


if __name__ == "__main__":
    unittest.main()
