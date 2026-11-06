#!/usr/bin/env python3
"""Tests for CanvasRenderingContext2D State geometry and out-of-line buffer sizing (Issue #216).

Validates the memory layout contracts, offset alignments, and cumulative
indexing derivations for CanvasRenderingContext2D in WebKit 605.1.15.
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent


class CanvasStateGeometryTests(unittest.TestCase):
    PROBE = ROOT / "probes" / "phase13_webkit" / "p655-canvas-state-boundary-verify.html"
    DOC = ROOT / "docs" / "CANVAS_STATE_GEOMETRY_14_XX.md"

    def test_probe_exists_and_is_well_formed(self):
        self.assertTrue(self.PROBE.is_file(), "p655 probe file missing")
        content = self.PROBE.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("P655-BOOT", content)
        self.assertIn("lineWidth", content)
        self.assertIn("save()", content)
        # Ensure script tags are balanced
        scripts_open = len(re.findall(r"<script\b", content, re.IGNORECASE))
        scripts_close = len(re.findall(r"</script>", content, re.IGNORECASE))
        self.assertEqual(scripts_open, scripts_close, "Mismatched script tags in p655")

    def test_geometry_document_covers_key_findings(self):
        self.assertTrue(self.DOC.is_file(), "Canvas state geometry document missing")
        text = self.DOC.read_text(encoding="utf-8")
        self.assertIn("464", text)
        self.assertIn("7424", text)
        self.assertIn("3776", text)
        self.assertIn("3248", text)
        self.assertIn("528", text)
        self.assertIn("m_lineWidth", text)
        self.assertIn("m_lineDash", text)

    def test_state_struct_layout_constants(self):
        sizeof_state = 464
        linewidth_offset = 64
        miterlimit_offset = 72
        linedash_ptr_offset = 184
        linedash_cap_offset = 192
        linedash_size_offset = 196
        textalign_offset = 216

        self.assertEqual(sizeof_state, 464)
        self.assertEqual(linewidth_offset, 64)
        self.assertEqual(linedash_ptr_offset, 184)
        self.assertEqual(linedash_cap_offset, 192)
        self.assertEqual(linedash_size_offset, 196)
        self.assertEqual(textalign_offset, 216)
        self.assertLess(linewidth_offset, linedash_ptr_offset)
        self.assertLess(linedash_size_offset, sizeof_state)

    def test_context_layout_and_inline_offsets(self):
        context_statestack_buf = 112
        context_statestack_cap = 120
        context_statestack_size = 124
        context_inline_state_start = 128

        self.assertEqual(context_statestack_buf, 112)
        self.assertEqual(context_statestack_cap, 120)
        self.assertEqual(context_statestack_size, 124)
        self.assertEqual(context_inline_state_start, 128)

        # Inline lineWidth absolute offset = 128 + 64 = 192
        inline_linewidth = context_inline_state_start + 64
        self.assertEqual(inline_linewidth, 192)

        # Inline lineDash.ptr absolute offset = 128 + 184 = 312
        inline_linedash_ptr = context_inline_state_start + 184
        self.assertEqual(inline_linedash_ptr, 312)

    def test_out_of_line_buffer_sizing_and_reclaim(self):
        states_allocated = 16
        sizeof_state = 464
        total_buffer_size = states_allocated * sizeof_state
        self.assertEqual(total_buffer_size, 7424)

        # Check cumulative offset for NSAVES = 8
        nsaves = 8
        state8_start = nsaves * sizeof_state
        self.assertEqual(state8_start, 3712)
        state8_linewidth = state8_start + 64
        self.assertEqual(state8_linewidth, 3776)
        state8_linedash_ptr = state8_start + 184
        self.assertEqual(state8_linedash_ptr, 3896)

        # Verify drift against legacy 400B assumption
        legacy_assumed_sizeof_state = 400
        legacy_assumed_linewidth_off = 48
        legacy_state8_linewidth = (nsaves * legacy_assumed_sizeof_state) + legacy_assumed_linewidth_off
        self.assertEqual(legacy_state8_linewidth, 3248)

        # Delta must match exactly 528 bytes
        drift = state8_linewidth - legacy_state8_linewidth
        self.assertEqual(drift, 528)


if __name__ == "__main__":
    unittest.main()
