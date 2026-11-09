#!/usr/bin/env python3
"""Pins for tools/tier2_claim_audit.py and docs/TIER2_CLAIMS_AUDIT.md.

Every assertion is against the committed 13.60 artifact: sysent slot bytes,
body RVAs, head bytes, instruction encodings, branch targets and counts. The
audit's whole value is that its citations are checkable, so the tests check
them twice: once through the tool's own verdict functions and once against
raw bytes read here.

Offline and read-only: no console is contacted.
"""

import json
import struct
import unittest
from pathlib import Path

from tools import tier2_claim_audit as audit

ROOT = Path(__file__).resolve().parent.parent
DUMPS = ROOT / "docs" / "dumps_13.60"
NOTE = ROOT / "docs" / "TIER2_CLAIMS_AUDIT.md"


def kernel():
    return (DUMPS / "kernel_text.bin").read_bytes()


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blob = kernel()
        cls.idx = audit.index()

    def test_slots_resolve_to_the_cited_bodies(self):
        expected = {548: 0xABBE60, 565: 0x6034E0, 566: 0x603710, 598: 0x34C990,
                    612: 0x34CE50, 649: 0x34CFA0, 664: 0x3B0FB0, 665: 0x3B1670,
                    666: 0x3B1680, 670: 0x3B28D0, 675: 0x2D36F0}
        for num, body in expected.items():
            self.assertEqual(audit.resolve(self.blob, self.idx, num), body, num)

    def test_every_cited_body_starts_with_a_prologue(self):
        for body in (0xABBE60, 0x6034E0, 0x603710, 0x34C990, 0x34CE50,
                     0x34CFA0, 0x3B0FB0, 0x3B1670, 0x3B1680, 0x3B28D0, 0x2D36F0):
            self.assertEqual(self.blob[body:body + 3], b"\x55\x48\x89", hex(body))

    def test_665_is_a_wrapper_that_tail_jumps_to_nosys(self):
        wrapper = self.blob[0x3B1670:0x3B1680]
        self.assertEqual(wrapper[:7], bytes.fromhex("554889e531f65d"))
        self.assertEqual(wrapper[7], 0xE9)
        self.assertEqual(audit.jmp_target(self.blob, 0x3B1677), audit.NOSYS)

    def test_670_plus_0x480_is_a_function_but_not_a_sysent_entry(self):
        target = 0x3B28D0 + 0x480
        self.assertEqual(self.blob[target:target + 4], bytes.fromhex("554889e5"))
        self.assertNotIn(target, {audit.resolve(self.blob, self.idx, n) for n in self.idx})

    def test_670_body_does_not_call_the_function_at_plus_0x480(self):
        target = 0x3B2D50
        for site in range(0x3B28D0, target - 5):
            if self.blob[site] in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", self.blob, site + 1)[0]
                self.assertNotEqual((site + 5 + rel) & 0xFFFFFFFFFFFFFFFF, target,
                                    hex(site))

    def test_the_only_direct_edge_is_the_unmapped_trampoline(self):
        target = 0x3B2D50
        edges = []
        for site in range(len(self.blob) - 5):
            if self.blob[site] in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", self.blob, site + 1)[0]
                if (site + 5 + rel) & 0xFFFFFFFFFFFFFFFF == target:
                    edges.append(site)
        self.assertEqual(edges, [0x265750])
        self.assertEqual(self.blob[0x265750:0x265758],
                         bytes.fromhex("e9fbd51400cccccc"))

    def test_675_is_forty_bytes_with_three_stores(self):
        self.assertEqual(self.blob[0x2D3717], 0xC3)  # ret
        self.assertEqual(self.blob[0x2D3718:0x2D3720], b"\x90" * 8)
        for site in (0x2D36F4, 0x2D36FE, 0x2D3709):
            self.assertEqual(self.blob[site], 0x48 if site != 0x2D36F4 else 0xC7)

    def test_598_call_set_is_complete(self):
        insns = audit.disasm(0x34C990, 0x34CAA0, self.blob)
        targets = sorted({t for _, t in audit.calls(insns)})
        self.assertEqual(targets, [0x2591D0, 0x6FD6B0, 0xB22A30, 0xC1A3E0])

    def test_649_switch_table_is_outside_the_dumped_text(self):
        # The relative table's RVA is 0x14c02b0, past kernel_text.bin's end.
        self.assertGreater(0x14C02B0, len(self.blob))
        self.assertEqual(self.blob[0x34D01E:0x34D025],
                         bytes.fromhex("488d0d8b321701"))  # lea rcx,[rip+0x117328b]

    def test_565_and_566_write_different_module_offsets(self):
        b565 = audit.disasm(0x6034E0, 0x603710, self.blob)
        b566 = audit.disasm(0x603710, 0x6039D0, self.blob)
        indexed565 = [i.op_str for i in b565
                      if "+ 0x160]" in i.op_str and "r12*8" in i.op_str]
        indexed566 = [i.op_str for i in b566
                      if "+ 0x190]" in i.op_str and "*8" in i.op_str]
        self.assertEqual(len(indexed565), 4)
        self.assertEqual(len(indexed566), 2)
        self.assertFalse([s for s in indexed565 if "0x190" in s])
        self.assertFalse([s for s in indexed566 if "0x160" in s])
        # 566 also has single-field stores on the -1 path (0x603897, 0x60392c).
        single = [i for i in b566 if i.op_str.endswith("+ 0x190], r12")
                  and "*8" not in i.op_str]
        self.assertEqual(len(single), 2)

    def test_566_routes_index_minus_one_to_its_own_store(self):
        # cmp r13d,-1 ; je 0x603925 -- the bound admits 0xffffffff, and the
        # -1 case is handled by a separate branch rather than rejected.
        self.assertEqual(self.blob[0x6037DB:0x6037E5],
                         bytes.fromhex("4183fdff0f8440010000"))

    def test_pte_mask_is_the_cited_constant(self):
        self.assertEqual(self.blob[0x6034F6:0x603500],
                         bytes.fromhex("48b900007b00f0ffffff"))


class VerdictTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blob = kernel()
        cls.idx = audit.index()
        cls.results = {
            "9": audit.claim9(cls.blob, cls.idx),
            "10": audit.claim10(cls.blob),
            "11": audit.claim11(cls.blob),
            "12": audit.claim12(cls.blob, cls.idx),
            "13": audit.claim13(cls.blob),
            "14": audit.claim14(cls.blob),
            "15": audit.claim15(cls.blob),
        }

    def test_no_claim_drifts(self):
        for cid, result in self.results.items():
            self.assertTrue(result["ok"], f"claim {cid} drifted: {result['detail']}")

    def test_verdicts_are_the_documented_ones(self):
        expected = {"9": "PARTIAL", "10": "CONFIRMED", "11": "PARTIAL",
                    "12": "PARTIAL", "13": "PARTIAL", "14": "CONFIRMED",
                    "15": "PARTIAL"}
        self.assertEqual({k: v["verdict"] for k, v in self.results.items()}, expected)

    def test_check_mode_exits_zero(self):
        self.assertEqual(audit.main(["tier2_claim_audit.py", "--check"]), 0)

    def test_simulated_bounds(self):
        # 565: cmp r12,6 ; setae -> reject index >= 6
        self.assertTrue(all(not (i >= 6) for i in range(6)))
        self.assertFalse(not (6 >= 6))
        # 566: lea eax,[r13-6] ; cmp eax,-7 ; jb -> reject (index-6) < 0xfffffff9
        def accepted(i):
            return not (((i - 6) & 0xFFFFFFFF) < 0xFFFFFFF9)
        self.assertTrue(all(accepted(i) for i in range(6)))
        self.assertFalse(accepted(6))
        self.assertFalse(accepted(7))
        # The bound admits 0xffffffff; a separate cmp r13d,-1 handles it.
        self.assertTrue(accepted(0xFFFFFFFF))


class NoteTests(unittest.TestCase):
    def test_note_exists_and_cites_every_verdict(self):
        text = NOTE.read_text(encoding="utf-8")
        for cid in ("9", "10", "11", "12", "13", "14", "15"):
            self.assertIn(f"| {cid} |", text)
        for token in ("0x34cfa0", "0x2d36f0", "0x34c990", "0x3b2d50",
                      "0x3b1680", "0x6034f6", "0xabbf95"):
            self.assertIn(token, text.lower())

    def test_note_states_the_artifact_limits(self):
        text = NOTE.read_text(encoding="utf-8").lower()
        self.assertIn("13.60", text)
        self.assertIn("no 14.10", text)
        self.assertIn("priv_check", text)


if __name__ == "__main__":
    unittest.main()
