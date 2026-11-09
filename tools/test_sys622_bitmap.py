#!/usr/bin/env python3
"""Pin the sys 622 bitmap gate corrected in sys_622_deep.md section 4.4.

The committed analysis named commands 0x12D and 0x130 as the pair selected by
the second bitmap 0x600000000000. The bitmap says bits 45 and 46, which are
0x12D and 0x12E; 0x130 is bit 48 and lives in the first bitmap. These tests
hold the bytes and both mappings so the correction cannot drift back.

Offline and read-only.
"""

import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KERNEL_TEXT = ROOT / "docs" / "dumps_13.60" / "kernel_text.bin"
NOTE = ROOT / "results" / "kernel_handlers" / "analysis" / "sys_622_deep.md"

BITMAP1_RVA = 0x7DCE0E
BITMAP1 = 0xF8FFF000000D5
BITMAP2_RVA = 0x7DD00B
BITMAP2 = 0x600000000000
BASE = 0x100


def kernel():
    return KERNEL_TEXT.read_bytes()


def commands(bitmap: int) -> list[int]:
    """Commands selected by a bitmap whose bit i is command BASE + i."""
    return [BASE + bit for bit in range(64) if bitmap >> bit & 1]


class BitmapByteTests(unittest.TestCase):
    def test_first_bitmap_bytes(self):
        blob = kernel()
        self.assertEqual(blob[BITMAP1_RVA:BITMAP1_RVA + 10],
                         bytes.fromhex("48b9d5000000ff8f0f00"))

    def test_second_bitmap_bytes(self):
        blob = kernel()
        self.assertEqual(blob[BITMAP2_RVA:BITMAP2_RVA + 10],
                         bytes.fromhex("48b90000000000600000"))

    def test_index_is_command_minus_0x100(self):
        blob = kernel()
        self.assertEqual(blob[0x7DCE02:0x7DCE09],
                         bytes.fromhex("418d8600ffffff"))  # lea eax,[r14-0x100]
        self.assertEqual(blob[0x7DCE09:0x7DCE0C], bytes.fromhex("83f833"))
        self.assertEqual(blob[0x7DCE0C:0x7DCE0E], bytes.fromhex("7741"))

    def test_bit_tests_and_their_targets(self):
        blob = kernel()
        self.assertEqual(blob[0x7DCE18:0x7DCE1C], bytes.fromhex("480fa3c1"))
        self.assertEqual(blob[0x7DCE1C:0x7DCE22], bytes.fromhex("0f83e9010000"))
        self.assertEqual(blob[0x7DD015:0x7DD019], bytes.fromhex("480fa3c1"))
        self.assertEqual(blob[0x7DD019:0x7DD01F], bytes.fromhex("0f8330feffff"))

    def test_second_bitmap_is_reached_only_when_the_first_bit_is_clear(self):
        blob = kernel()
        rel = struct.unpack_from("<i", blob, 0x7DCE1C + 2)[0]
        self.assertEqual(0x7DCE1C + 6 + rel, BITMAP2_RVA)
        rel = struct.unpack_from("<i", blob, 0x7DD019 + 2)[0]
        self.assertEqual(0x7DD019 + 6 + rel, 0x7DCE4F)


class BitMappingTests(unittest.TestCase):
    def test_first_bitmap_commands(self):
        self.assertEqual(commands(BITMAP1), [
            0x100, 0x102, 0x104, 0x106, 0x107,
            0x120, 0x121, 0x122, 0x123, 0x124, 0x125, 0x126, 0x127,
            0x128, 0x129, 0x12A, 0x12B, 0x12F,
            0x130, 0x131, 0x132, 0x133,
        ])

    def test_second_bitmap_commands_are_0x12d_and_0x12e(self):
        self.assertEqual(commands(BITMAP2), [0x12D, 0x12E])

    def test_0x130_is_in_the_first_bitmap_not_the_second(self):
        self.assertTrue(BITMAP1 >> (0x130 - BASE) & 1)
        self.assertFalse(BITMAP2 >> (0x130 - BASE) & 1)

    def test_0x12f_is_gated_by_the_first_bitmap(self):
        self.assertTrue(BITMAP1 >> (0x12F - BASE) & 1)

    def test_every_gated_command_is_within_the_dispatch_window(self):
        # cmp eax,0x33; ja reject -> only cmd-0x100 <= 0x33 reach a bitmap.
        for cmd in commands(BITMAP1) + commands(BITMAP2):
            self.assertLessEqual(cmd - BASE, 0x33, hex(cmd))


class NoteTests(unittest.TestCase):
    def test_note_names_the_corrected_pair(self):
        text = NOTE.read_text(encoding="utf-8")
        self.assertIn("### 4.4 Bitmap-Gated Auth (commands 0x12D, 0x12E)", text)
        self.assertIn("bit 45 is `0x12D` and bit 46 is `0x12E`", text)
        self.assertIn("`0x130` is bit 48", text)
        self.assertIn("0x7dce0e", text)
        self.assertIn("0x7dd00b", text)
        self.assertIn("0x609110", text)

    def test_note_no_longer_claims_0x130_in_the_second_bitmap(self):
        text = NOTE.read_text(encoding="utf-8")
        self.assertNotIn("select 0x12D and 0x130 only", text)


if __name__ == "__main__":
    unittest.main()
