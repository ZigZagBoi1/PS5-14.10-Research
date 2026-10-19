#!/usr/bin/env python3
"""Pins for the 81400 false-positive retraction.

pastawithpesto's V480 (analysis/false-positive-81400.md in their repo) showed
that the `.length = 81400` "corruption" was the real string length: the
p146/p156 worker chunk literal is 814 characters, so the constructed strings
are 814 x 100 = 81,400 chars from birth. These tests pin the cause (the
literal lengths in the probe sources), the retraction text in the findings doc,
and the audit banner — so the false positive cannot be re-introduced as a
"confirmed corruption" claim without breaking a test.

Offline and read-only.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FINDINGS = ROOT / "docs" / "WEBKIT_FINDINGS.md"
AUDIT = ROOT / "docs" / "WEBKIT_LENGTH_WINDOW_AUDIT.md"
PROBES = [
    ROOT / "probes" / "phase13_webkit" / "p146-string-primary.js",
    ROOT / "probes" / "phase13_webkit" / "p156-bait-switch.js",
    ROOT / "probes" / "phase14_final_push" / "54g_webkit_kaslr.js",
]


class LiteralCauseTests(unittest.TestCase):
    def test_the_literals_are_814_and_798(self):
        for probe in PROBES:
            src = probe.read_text(encoding="utf-8")
            a = re.findall(r"'(A{100,})'", src)
            b = re.findall(r"'(B{100,})'", src)
            self.assertTrue(a and b, f"{probe.name}: long A/B literals not found")
            self.assertEqual(len(a[0]), 814, f"{probe.name}: A literal != 814")
            self.assertEqual(len(b[0]), 798, f"{probe.name}: B literal != 798")

    def test_p161_uses_loop_built_chunks(self):
        src = (ROOT / "probes" / "phase13_webkit" / "p161-length-window.js").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"'A{100,}'", src),
                          "p161 must not use a short A literal for its strings")
        self.assertIn("for (var j = 0; j < 1000; j++) block += ch;", src)


class RetractionTests(unittest.TestCase):
    def test_findings_doc_records_the_false_positive(self):
        text = FINDINGS.read_text(encoding="utf-8")
        self.assertIn("RETRACTED as false positive", text)
        self.assertIn("814-char literal", text)
        self.assertIn("0 of 14", text)

    def test_no_uncorrected_corruption_claims_remain(self):
        text = FINDINGS.read_text(encoding="utf-8")
        self.assertNotIn("**All 14 JSStrings corrupted, `.length` = 81400**", text)

    def test_crosslink_block_corrected(self):
        text = FINDINGS.read_text(encoding="utf-8")
        self.assertIn("same false positive (corrected 2026-10-20)", text)

    def test_audit_carries_the_status_revision(self):
        text = AUDIT.read_text(encoding="utf-8")
        self.assertIn("Status revision (2026-10-20): the audited value was a FALSE POSITIVE", text)


if __name__ == "__main__":
    unittest.main()
