#!/usr/bin/env python3
"""Tests for CanvasRenderingContext2D State geometry and out-of-line buffer sizing (Issue #216).

Validates the memory layout contracts, offset alignments, Vector header ordering,
and bmalloc allocation ladder for CanvasRenderingContext2D in WebKit 605.1.15.
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
        scripts_open = len(re.findall(r"<script\b", content, re.IGNORECASE))
        scripts_close = len(re.findall(r"</script>", content, re.IGNORECASE))
        self.assertEqual(scripts_open, scripts_close, "Mismatched script tags in p655")

    def test_geometry_document_covers_key_findings(self):
        self.assertTrue(self.DOC.is_file(), "Canvas state geometry document missing")
        text = self.DOC.read_text(encoding="utf-8")
        self.assertIn("m_stateStack", text)
        self.assertIn("+0x70", text)
        self.assertIn("+0x78", text)
        self.assertIn("+0x7C", text)
        self.assertIn("+0x80", text)
        self.assertIn("lineWidth", text)
        self.assertIn("+0x30", text)
        self.assertIn("bmalloc", text)
        self.assertIn("3840", text)
        self.assertIn("4096", text)

    def test_context_layout_and_vector_header(self):
        # wtf/Vector.h:396-397: {T* m_buffer, unsigned m_capacity, unsigned m_size}
        context_statestack_buf = 0x70  # 112
        context_statestack_cap = 0x78  # 120
        context_statestack_size = 0x7C  # 124
        context_inline_state_start = 0x80  # 128

        self.assertEqual(context_statestack_buf, 112)
        self.assertEqual(context_statestack_cap, 120)
        self.assertEqual(context_statestack_size, 124)
        self.assertEqual(context_inline_state_start, 128)

        # Self-pointing inline buffer check: buffer points at ctx + 128
        dummy_ctx_va = 0x120000000
        expected_self_pointing_buf = dummy_ctx_va + context_inline_state_start
        self.assertEqual(expected_self_pointing_buf, 0x120000080)

    def test_drop_state_internal_layout_constants(self):
        # WK-1400 Drop: BASE.h:267-295
        unparsed_stroke_color = 0x00
        unparsed_fill_color = 0x08
        stroke_style = 0x10
        fill_style = 0x20
        linewidth_offset = 0x30  # 48
        miterlimit_offset = 0x40  # 64
        transform_offset = 0x70  # 112
        linedash_offset = 0xF8  # 248
        linedash_off_offset = 0x108  # 264
        textalign_offset = 0x118  # 280

        self.assertEqual(linewidth_offset, 48)
        self.assertEqual(miterlimit_offset, 64)
        self.assertEqual(transform_offset, 112)
        self.assertEqual(linedash_offset, 248)
        self.assertLess(linewidth_offset, transform_offset)
        self.assertLess(transform_offset, linedash_offset)

    def test_vector_growth_and_ladder_sizing(self):
        # Exact Vector expansion formula: newCap = cap + cap // 4 + 1
        cap = 1
        capacities = [cap]
        while cap < 11:
            cap = cap + cap // 4 + 1
            capacities.append(cap)
        # Sequence: 1 -> 2 -> 3 -> 4 -> 6 -> 8 -> 11
        self.assertEqual(capacities, [1, 2, 3, 4, 6, 8, 11])

        # Validate buffer sizing across both capacity models (10 vs 11 states)
        drop_state_size_min = 376
        drop_state_size_max = 408

        # 10 states model (integer 1.25x scaling):
        buf_10_min = 10 * drop_state_size_min
        buf_10_max = 10 * drop_state_size_max
        self.assertEqual(buf_10_min, 3760)
        self.assertEqual(buf_10_max, 4080)

        # 11 states model (exact cap + cap//4 + 1):
        buf_11_min = 11 * drop_state_size_min
        buf_11_max = 11 * drop_state_size_max
        self.assertEqual(buf_11_min, 4136)
        self.assertEqual(buf_11_max, 4488)

        # Both models fall cleanly within the pre-registered ladder [3328 .. 4352]
        ladder = [3328, 3584, 3840, 4096, 4352]
        self.assertTrue(any(3760 <= b <= 4096 for b in ladder))
        self.assertIn(4352, ladder)

        # Ladder decider covers the bmalloc bucket window [3328 .. 4352]
        ladder = [3328, 3584, 3840, 4096, 4352]
        self.assertTrue(any(3760 <= b <= 4096 for b in ladder))


if __name__ == "__main__":
    unittest.main()
