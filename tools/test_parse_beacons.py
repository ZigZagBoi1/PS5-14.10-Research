#!/usr/bin/env python3
"""Tests for tools/parse_beacons.py — synthetic nginx beacon logs."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "parse_beacons.py")

# Reference fingerprint (p691-run3): VP=0x80C6A1B28, slots as in REF.
# Issue #295 has the same deltas at a different absolute VP RVA.
REF_VP = 0x80C6A1B28
REF_SLOTS = [0x80AF90FB0, 0x80AF90FE0, 0x809455750, 0x80AF916B0,
             0x809455750, 0x809455750, 0x80ABE7400, 0x80AF91810, 0x0]


class BeaconAnalyzerTests(unittest.TestCase):
    def make_log(self, lines):
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.addCleanup(os.unlink, path)
        return path

    @staticmethod
    def beacon(uid, msg):
        return (f'1.2.3.4 - - [17/Nov/2026:00:00:00 +0000] '
                f'"GET /beacon/MOD-{msg}?t=1&u={uid} HTTP/1.1" 200 2')

    @staticmethod
    def full_run(uid, vp, slots, base):
        lines = [BeaconAnalyzerTests.beacon(uid, "VER-DATA-1"),
                 BeaconAnalyzerTests.beacon(uid, "WALK-ok%3Dtrue"),
                 BeaconAnalyzerTests.beacon(uid, f"VP-{hex(vp)}"),
                 BeaconAnalyzerTests.beacon(uid, f"BASE-{hex(base)}")]
        for i, slot in enumerate(slots):
            lines.append(BeaconAnalyzerTests.beacon(uid, f"S{i}-{hex(slot)}"))
        lines.append(BeaconAnalyzerTests.beacon(uid, "COMPLETE"))
        return lines

    def run_tool(self, path, *extra):
        return subprocess.run([sys.executable, TOOL, path, *extra],
                              capture_output=True, text=True)

    def test_match_reference_layout(self):
        """Identical deltas at a different slide match the fingerprint only."""
        slide = 0x120000  # different ASLR slide from the reference family
        vp = REF_VP + slide
        slots = [s + slide if s else 0 for s in REF_SLOTS]
        path = self.make_log(self.full_run("AAAAAA", vp, slots, vp - 0xC6A1B28))
        r = self.run_tool(path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("MATCH_REFERENCE_DELTAS", r.stdout)
        self.assertIn("absolute VP_RVA=unresolved", r.stdout)

    def test_uniform_shift_stays_relative(self):
        """A uniform VP-relative shift cannot prove an absolute RVA."""
        # Text slots keep their reference RVAs (same slide as VP), but the
        # vtable itself sits 0x8000 higher against .text, so each VP-si delta
        # grows by exactly 0x8000 while inter-slot gaps are unchanged.
        shift = 0x8000
        vp = REF_VP + 0x120000
        slots = [s + 0x120000 if s else 0 for s in REF_SLOTS]
        vp += shift
        path = self.make_log(self.full_run("BBBBBB", vp, slots, vp - 0xC6A1B28))
        r = self.run_tool(path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("UNIFORM_SHIFT_REFERENCE_DELTAS", r.stdout)
        self.assertIn("relative shift=0x8000 absolute VP_RVA=unresolved", r.stdout)

    def test_mismatch_is_consistent_but_requires_manual_review(self):
        """A complete unknown fingerprint is consistent data, not a success."""
        vp = 0x812345678
        slots = [0x811111110, 0x822222220, 0x833333330, 0x844444440,
                 0x855555550, 0x866666660, 0x877777770, 0x888888880, 0x0]
        path = self.make_log(self.full_run("CCCCCC", vp, slots, vp - 0xC6A1B28))
        r = self.run_tool(path, "--json")
        self.assertEqual(r.returncode, 1, r.stderr)
        data = json.loads(r.stdout)[0]
        self.assertEqual(data["verdict"], "MISMATCH_MANUAL_REVIEW")
        self.assertTrue(data["run_valid"])
        self.assertEqual(data["absolute_rva"], "unresolved")

    def test_incomplete_run(self):
        """Only a UA beacon, no VP -> INCOMPLETE, exit 1."""
        path = self.make_log([self.beacon("DDDDDD", "UA-Mozilla%2F5.0")])
        r = self.run_tool(path)
        self.assertEqual(r.returncode, 1)
        self.assertIn("INVALID_RUN", r.stdout)

    def test_base_claim_disagreement_flagged(self):
        """Probe BASE claim inconsistent with its own VP -> agree=False."""
        slide = 0x120000
        vp = REF_VP + slide
        slots = [s + slide if s else 0 for s in REF_SLOTS]
        wrong_base = vp - 0xC6A1B28 - 0x4000  # corrupted beacon
        path = self.make_log(self.full_run("EEEEEE", vp, slots, wrong_base))
        r = self.run_tool(path)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("INVALID_RUN", r.stdout)
        self.assertIn("agree=False", r.stdout)
        self.assertIn("MATCH_REFERENCE_DELTAS", r.stdout)  # slots still decide

    def test_zero_required_slot_invalidates_run(self):
        vp = REF_VP + 0x120000
        slots = [s + 0x120000 if s else 0 for s in REF_SLOTS]
        slots[2] = 0
        path = self.make_log(self.full_run("ZEROSLOT", vp, slots,
                                           vp - 0xC6A1B28))
        r = self.run_tool(path, "--json")
        self.assertEqual(r.returncode, 1, r.stderr)
        data = json.loads(r.stdout)[0]
        self.assertEqual(data["verdict"], "INVALID_RUN")
        self.assertFalse(data["run_valid"])
        self.assertIn("required slots S0-S7 missing or zero",
                      data["validation_errors"])

    def test_reference_deltas_do_not_confirm_absolute_rva(self):
        """Issue #295 family: same deltas, different absolute VP RVA.

        A matching slot fingerprint validates the walk shape, not the probe's
        hardcoded 0xC6A1B28 base assumption.
        """
        vp = 0x8158EDB28
        deltas = [0x1710B78, 0x1710B48, 0x324C3D8, 0x1710478,
                  0x324C3D8, 0x324C3D8, 0x1ABA728, 0x1710318]
        slots = [vp - delta for delta in deltas] + [0]
        path = self.make_log(self.full_run("FAMILY2", vp, slots,
                                           vp - 0xC6A1B28))
        r = self.run_tool(path, "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)[0]
        self.assertEqual(data["verdict"], "MATCH_REFERENCE_DELTAS")
        self.assertTrue(data["run_valid"])
        self.assertEqual(
            data["address_inference"],
            "unresolved: relative slot deltas cannot determine absolute module base")
        self.assertNotIn("base_candidate", data)
        self.assertNotIn("vp_rva_assumed", data)

    def test_uid_filter_and_json(self):
        slide = 0x120000
        vp = REF_VP + slide
        slots = [s + slide if s else 0 for s in REF_SLOTS]
        lines = self.full_run("AAAAAA", vp, slots, vp - 0xC6A1B28)
        lines += self.full_run("BBBBBB", 0x0, [0] * 9, 0x0)
        path = self.make_log(lines)
        r = self.run_tool(path, "--uid", "AAAAAA", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["uid"], "AAAAAA")
        self.assertEqual(data[0]["verdict"], "MATCH_REFERENCE_DELTAS")


if __name__ == "__main__":
    unittest.main()
