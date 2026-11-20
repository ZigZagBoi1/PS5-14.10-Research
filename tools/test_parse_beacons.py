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

# 13.60 reference (p691-run3): VP=0x80C6A1B28, slots as in REF.
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

    def test_match_1360_layout(self):
        """14.10 run with identical deltas at a different slide -> MATCH."""
        slide = 0x120000  # different ASLR slide from 13.60
        vp = REF_VP + slide
        slots = [s + slide if s else 0 for s in REF_SLOTS]
        path = self.make_log(self.full_run("AAAAAA", vp, slots, vp - 0xC6A1B28))
        r = self.run_tool(path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("MATCH_1360_LAYOUT", r.stdout)
        self.assertIn("VP_RVA ASSUMED = 0xc6a1b28", r.stdout)

    def test_uniform_shift_recompute(self):
        """Vtable moved vs .text: every VP-slot delta shifts by one constant."""
        # Text slots keep their 13.60 RVAs (same slide as VP), but the vtable
        # itself sits 0x8000 higher against .text (different link), so each
        # VP-si delta grows by exactly 0x8000 while inter-slot gaps are unchanged.
        shift = 0x8000
        vp = REF_VP + 0x120000
        slots = [s + 0x120000 if s else 0 for s in REF_SLOTS]  # pure slide
        vp += shift  # vtable sits higher against .text
        path = self.make_log(self.full_run("BBBBBB", vp, slots, vp - 0xC6A1B28))
        r = self.run_tool(path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("UNIFORM_SHIFT_RVA_RECOMPUTED", r.stdout)
        self.assertIn("VP_RVA CANDIDATE = 0xc6a9b28", r.stdout)  # 0xC6A1B28 + 0x8000
        self.assertIn(f"base_candidate={hex(vp - (0xC6A1B28 + shift))}", r.stdout)

    def test_mismatch_garbage_slots(self):
        """Random slot values -> MISMATCH, not a false RVA."""
        vp = 0x812345678
        slots = [0x811111110, 0x822222220, 0x833333330, 0x844444440,
                 0x855555550, 0x866666660, 0x877777770, 0x888888880, 0x0]
        path = self.make_log(self.full_run("CCCCCC", vp, slots, vp - 0xC6A1B28))
        r = self.run_tool(path)
        self.assertEqual(r.returncode, 1)
        self.assertIn("MISMATCH_MANUAL_REVIEW", r.stdout)

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
        self.assertIn("MATCH_1360_LAYOUT", r.stdout)  # slots still decide

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
        self.assertEqual(data[0]["verdict"], "MATCH_1360_LAYOUT")


if __name__ == "__main__":
    unittest.main()
