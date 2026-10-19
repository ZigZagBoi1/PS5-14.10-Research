#!/usr/bin/env python3
"""Pins for tools/tier3_claim_audit.py and docs/TIER3_CLAIMS_AUDIT.md.

Each assertion re-derives a cited byte from the committed 13.60 artifact, so a
drift in the dump or in the note fails a named test. Offline and read-only.
"""

import json
import struct
import unittest
from pathlib import Path

from tools import tier3_claim_audit as audit

ROOT = Path(__file__).resolve().parent.parent
DUMPS = ROOT / "docs" / "dumps_13.60"
NOTE = ROOT / "docs" / "TIER3_CLAIMS_AUDIT.md"


class SysentTableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = audit.sysent_entries()

    def test_table_shape(self):
        self.assertEqual(len(self.rows), 679)
        self.assertEqual(len(self.rows[0]), 48)

    def test_entry_zero_matches_the_index_json(self):
        entry = json.loads((DUMPS / "sysent_index.json").read_text())["entries"][0]
        self.assertEqual(audit.qword(self.rows[0], audit.OFF_SYCALL),
                         int(entry["sy_call"], 16))

    def test_sony_range_au_event_exception_is_658(self):
        nonzero = {i: audit.dword(self.rows[i], audit.OFF_AUEVENT)
                   for i in range(532, 677)
                   if audit.dword(self.rows[i], audit.OFF_AUEVENT)}
        self.assertEqual(nonzero, {658: 43069})

    def test_658_is_a_real_wrapper_not_the_nosys_stub(self):
        text = (DUMPS / "kernel_text.bin").read_bytes()
        idx = {e["num"]: int(e["sy_call_off"], 16)
               for e in json.loads((DUMPS / "sysent_index.json").read_text())["entries"]}
        rel = struct.unpack_from("<i", text, idx[658] + 1)[0]
        body = (idx[658] + 5 + rel) & 0xFFFFFFFFFFFFFFFF
        self.assertEqual(body, 0x8FB440)
        self.assertEqual(text[body:body + 12],
                         bytes.fromhex("554889e58b365de9c4fdffff"))
        self.assertNotEqual(body, 0x265760)

    def test_flags_take_only_two_values_before_the_malformed_rows(self):
        values = {audit.dword(self.rows[i], audit.OFF_FLAGS) for i in range(677)}
        self.assertEqual(values, {1, 4})

    def test_rows_677_and_678_are_malformed(self):
        for num in (677, 678):
            self.assertEqual(audit.dword(self.rows[num], 0x04), 0xFFFFFFFF)
            self.assertGreater(audit.dword(self.rows[num], audit.OFF_NARG), 1 << 31)


class UcredTests(unittest.TestCase):
    def test_the_three_values_are_at_the_cited_offsets(self):
        blob = (DUMPS / "ucred.bin").read_bytes()
        self.assertEqual(len(blob), 256)
        self.assertEqual(audit.qword(blob, 0x58), 0x4800000000000007)
        self.assertEqual(audit.qword(blob, 0x60), 0x40FF1CFFFFFFFFFF)
        self.assertEqual(audit.qword(blob, 0x68), 0xFFFFFFFFFFFFFFFF)

    def test_no_stray_copies(self):
        blob = (DUMPS / "ucred.bin").read_bytes()
        targets = set(audit.UCRED_OFFSETS.values())
        stray = [off for off in range(len(blob) - 7)
                 if audit.qword(blob, off) in targets and off not in audit.UCRED_OFFSETS]
        self.assertEqual(stray, [])


class ModuleMapTests(unittest.TestCase):
    def test_every_cited_offset_is_read_in_the_dylib_handler(self):
        result = audit.claim19()
        self.assertTrue(result["ok"], result["detail"])
        self.assertEqual(result["verdict"], "CONFIRMED")

    def test_handler_extent_is_the_608_body(self):
        text = (DUMPS / "kernel_text.bin").read_bytes()
        self.assertEqual(text[audit.DYLIB_HANDLER:audit.DYLIB_HANDLER + 4],
                         bytes.fromhex("554889e5"))


class KernelStringTests(unittest.TestCase):
    def test_cited_strings_exist_in_the_data_range(self):
        data = (DUMPS / "kernel_data.bin").read_bytes()
        for needle in audit.DATA_STRINGS.values():
            self.assertIn(needle.encode(), data, needle)

    def test_ktls_strings_are_absent_from_the_data_range(self):
        # Recorded as a scope limit for the KTLS assessment, not as proof that
        # the kernel lacks KTLS: the dump is a fixed range, not a full image.
        data = (DUMPS / "kernel_data.bin").read_bytes()
        for needle in (b"ktls", b"KTLS", b"SO_TXTLS"):
            self.assertEqual(data.count(needle), 0, needle)


class Sys640Tests(unittest.TestCase):
    def test_stub_bytes(self):
        text = (DUMPS / "kernel_text.bin").read_bytes()
        self.assertEqual(text[0xA90E10:0xA90E18],
                         bytes.fromhex("554889e531c05dc3"))
        self.assertEqual(text[0xA90E18:0xA90E20], b"\x90" * 8)

    def test_narg_is_eight(self):
        rows = audit.sysent_entries()
        self.assertEqual(audit.dword(rows[640], audit.OFF_NARG), 8)

    def test_neighbour_starts_a_one_shot_initialiser(self):
        text = (DUMPS / "kernel_text.bin").read_bytes()
        head = text[0xA90E20:0xA90E38]
        self.assertEqual(head[0], 0x55)
        self.assertEqual(head[6:11], bytes.fromhex("b901000000"))
        self.assertEqual(head[13:16], bytes.fromhex("f00fb1"))

    def test_claim_transcription_is_corrected(self):
        # The claim writes 'mov rsp,rbp'; the encoding is mov rbp,rsp.
        self.assertEqual(audit.SYS_640_STUB[1:4], bytes.fromhex("4889e5"))
        text = NOTE.read_text(encoding="utf-8")
        self.assertIn("mov rbp,rsp", text)
        self.assertIn("mov rsp,rbp", text)  # quoted as the wrong transcription


class VerdictTests(unittest.TestCase):
    def test_no_drift_and_check_mode_is_green(self):
        for result in (audit.claim16(), audit.claim18(), audit.claim19(),
                       audit.claim21(), audit.claim22()):
            self.assertTrue(result["ok"], f"claim {result['id']}: {result['detail']}")
        self.assertEqual(audit.main(["tier3_claim_audit.py", "--check"]), 0)

    def test_verdicts(self):
        self.assertEqual(audit.claim16()["verdict"], "PARTIAL")
        self.assertEqual(audit.claim18()["verdict"], "CONFIRMED")
        self.assertEqual(audit.claim19()["verdict"], "CONFIRMED")
        self.assertEqual(audit.claim21()["verdict"], "CONFIRMED")
        self.assertEqual(audit.claim22()["verdict"], "CONFIRMED")

    def test_unresolved_claims_are_named(self):
        ids = [cid for cid, _, _ in audit.UNRESOLVED]
        self.assertEqual(ids, ["17", "20"])


class NoteTests(unittest.TestCase):
    def test_note_covers_every_claim(self):
        text = NOTE.read_text(encoding="utf-8")
        for cid in ("16", "17", "18", "19", "20", "21", "22"):
            self.assertIn(f"| {cid} |", text)

    def test_note_states_limits(self):
        text = NOTE.read_text(encoding="utf-8").lower()
        self.assertIn("13.60", text)
        self.assertIn("no 14.10", text)
        self.assertIn("inferred", text)


if __name__ == "__main__":
    unittest.main()
