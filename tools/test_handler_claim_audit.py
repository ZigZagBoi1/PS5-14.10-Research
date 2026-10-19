#!/usr/bin/env python3
"""Tests for tools/handler_claim_audit.py.

Two layers:

* the parsers are exercised on synthetic fixtures, so a formatting change in
  the committed assembly shows up as a parser failure rather than a silently
  wrong verdict;
* one integration test runs the audit against the repository artifacts and
  requires every check to hold. That test is the regression guard for the
  correction note: if an artifact is replaced and a corrected claim stops
  matching, the suite fails.

Nothing here contacts a console, a network endpoint, or a running process.
"""

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import handler_claim_audit as audit


def _entry(target: int, at: int, base: int = 0) -> bytes:
    """An E9 rel32 window entry, relative to the window's own base RVA."""
    return b"\xe9" + struct.pack("<i", target - (base + at + 5)) + b"\xcc\xcc\xcc"


class TrampolineTests(unittest.TestCase):
    def test_entries_resolve_against_window_base(self):
        blob = _entry(0x1000, 0, 0x400) + _entry(0x2000, 8, 0x400) + b"\xcc" * 8
        got = audit.trampoline_entries(blob, base=0x400)
        self.assertEqual(got, [(0, 0x1000), (8, 0x2000)])

    def test_non_entry_words_are_skipped(self):
        blob = b"\x90" * 8 + _entry(0x1000, 8, 0x400)
        self.assertEqual(audit.trampoline_entries(blob, base=0x400), [(8, 0x1000)])

    def test_jmp_target_honours_base(self):
        blob = _entry(0x3AF8F0, 0, 0x265710)
        self.assertEqual(audit.jmp_target(blob, 0, 0x265710), 0x3AF8F0)

    def test_jmp_target_rejects_non_e9(self):
        self.assertIsNone(audit.jmp_target(b"\x90" * 8, 0, 0))


class ParseAsmTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._orig = audit.ASM
        audit.ASM = Path(self.tmp.name)

    def tearDown(self):
        audit.ASM = self._orig

    def _write(self, num, text):
        (Path(self.tmp.name) / f"sys_{num}.asm").write_text(text, encoding="utf-8")

    def test_target_header_with_rva_label(self):
        self._write(1, "\n".join([
            "; ===== TARGET: body_one RVA 0x1000 | Evidence ev_x =====",
            "body_one: ; RVA 0x1000",
            "0x1000: PUSH RBP",
            "0x1001: POP RBP",
            "0x1002: RET",
        ]))
        insns, ranges = audit.parse_asm(1)
        self.assertEqual(insns[0x1001], "POP RBP")
        self.assertEqual(audit.containing(ranges, 0x1002), "body_one")

    def test_target_header_with_bare_label(self):
        self._write(2, "\n".join([
            "; ===== TARGET: body_two RVA 0x2000 | Evidence ev_y =====",
            "body_two:",
            "0x2000: PUSH RBP",
            "0x2001: RET",
        ]))
        insns, ranges = audit.parse_asm(2)
        self.assertEqual(insns[0x2000], "PUSH RBP")
        self.assertEqual(audit.containing(ranges, 0x2000), "body_two")

    def test_context_header_without_name(self):
        self._write(3, "\n".join([
            "; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): RVA 0x3000 | ev",
            "0x3000: PUSH RBP",
            "0x3001: RET",
        ]))
        _, ranges = audit.parse_asm(3)
        self.assertEqual(audit.containing(ranges, 0x3001), "sub_3000")

    def test_body_declaration_beats_inferred_extent(self):
        self._write(4, "\n".join([
            "; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): RVA 0x4000 | ev",
            '; helper; body [{"start": "0x4000", "end": "0x4004"}]',
            "0x4000: PUSH RBP",
            "0x4001: RET",
            "0x5000: INT3",
        ]))
        _, ranges = audit.parse_asm(4)
        # The declared range stops at 0x4004 even though 0x5000 followed it.
        self.assertEqual(audit.containing(ranges, 0x4004), "sub_4000")
        self.assertIsNone(audit.containing(ranges, 0x4005))

    def test_function_declaration(self):
        self._write(5, "\n".join([
            "; FUNCTION thunk_6000 [0x6000, 0x6004] | ev",
            "thunk_6000:",
            "0x6000: JMP 0x007000",
        ]))
        _, ranges = audit.parse_asm(5)
        self.assertEqual(audit.containing(ranges, 0x6002), "thunk_6000")

    def test_missing_file_is_empty(self):
        self.assertEqual(audit.parse_asm(99), ({}, []))


class CountGuardTests(unittest.TestCase):
    """The guard direction is easy to invert; pin it explicitly."""

    def test_small_counts_are_rejected(self):
        # 0 is the exception: 0 - 0x81 wraps to exactly 0xffffff7f, and `ja`
        # is strictly-above, so it passes here and is caught later by the
        # `cmp r15d, 2` branch into the fixed-buffer path.
        for count in (0x1, 0x10, 0x80):
            self.assertFalse(audit.count_accepted(count), hex(count))

    def test_zero_passes_this_guard(self):
        self.assertTrue(audit.count_accepted(0))

    def test_boundary_is_inclusive(self):
        self.assertTrue(audit.count_accepted(0x81))

    def test_large_counts_are_admitted(self):
        for count in (0x100, 0x40000001, 0xFFFFFF00, 0xFFFFFFFF):
            self.assertTrue(audit.count_accepted(count), hex(count))

    def test_wide_value_wraps_through_the_32_bit_compare(self):
        # count - 0x81 is computed at 32 bits, so a 64-bit count whose low
        # word lands above 0x80 is admitted.
        self.assertTrue(audit.count_accepted(0x1_0000_0081))
        self.assertFalse(audit.count_accepted(0x1_0000_0080))


class BranchSourceTests(unittest.TestCase):
    def test_separates_calls_from_jumps(self):
        call_at, jump_at = 1, 6
        call = b"\xe8" + struct.pack("<i", 0x1000 - (call_at + 5))
        jump = b"\xe9" + struct.pack("<i", 0x1000 - (jump_at + 5))
        blob = b"\x90" + call + jump
        got = audit.branch_sources(blob, {0x1000})
        self.assertEqual(got[0x1000], [(call_at, "call"), (jump_at, "jmp")])

    def test_ignores_unrelated_targets(self):
        blob = b"\xe8" + struct.pack("<i", 0x9999 - 5)
        self.assertEqual(audit.branch_sources(blob, {0x1000}), {0x1000: []})


class RepositoryAuditTests(unittest.TestCase):
    """Integration: the corrected claims must still match the artifacts."""

    def test_every_check_holds(self):
        required = [
            audit.DUMPS / "sysent_index.json",
            audit.DUMPS / "kernel_text.bin",
            audit.ASM / "sys_661.asm",
            audit.ASM / "sys_666.asm",
        ]
        if not all(p.exists() for p in required):
            self.skipTest("13.60 handler artifacts not present")

        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = audit.main(["handler_claim_audit.py"])
        report = buf.getvalue()
        self.assertEqual(code, 0, report)
        self.assertIn("11/11 checks hold", report)


if __name__ == "__main__":
    unittest.main()
