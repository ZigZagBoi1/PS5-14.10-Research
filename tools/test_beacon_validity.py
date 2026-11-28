"""Offline validity contract; all inputs are synthetic."""
import json
import unittest

from tools import test_parse_beacons as helpers

REF_SLOTS = helpers.REF_SLOTS
REF_VP = helpers.REF_VP


class BeaconValidityTests(unittest.TestCase):
    make_log = helpers.BeaconAnalyzerTests.make_log
    beacon = staticmethod(helpers.BeaconAnalyzerTests.beacon)
    full_run = staticmethod(helpers.BeaconAnalyzerTests.full_run)
    run_tool = helpers.BeaconAnalyzerTests.run_tool

    def lines(self):
        return self.full_run("AAAAAA", REF_VP, REF_SLOTS, REF_VP - 0xC6A1B28)

    def check_invalid(self, lines):
        result = self.run_tool(self.make_log(lines), "--json")
        self.assertEqual(result.returncode, 1, result.stdout)
        record = json.loads(result.stdout)[0]
        self.assertFalse(record["run_valid"])
        self.assertEqual(record["verdict"], "INVALID_RUN")
        self.assertTrue(record["validation_errors"])
        for key in ("vp_rva_confirmed", "vp_rva_recomputed", "base_true",
                    "vp_rva_assumed", "vp_rva_candidate", "base_candidate"):
            self.assertNotIn(key, record)
        return record

    def test_failed_walk(self):
        self.check_invalid([line.replace("ok%3Dtrue", "ok%3Dfalse") for line in self.lines()])

    def test_missing_completion(self):
        self.check_invalid(self.lines()[:-1])

    def test_missing_required_slot(self):
        self.check_invalid([line for line in self.lines() if "MOD-S7-" not in line])

    def test_zero_required_slot(self):
        self.check_invalid([line.replace(hex(REF_SLOTS[0]), "0x0") for line in self.lines()])

    def test_contradictory_walk(self):
        self.check_invalid([self.beacon("AAAAAA", "WALK-ok%3Dfalse")] + self.lines())

    def test_contradictory_pointer(self):
        self.check_invalid([self.beacon("AAAAAA", "VP-0x1")] + self.lines())

    def test_malformed_pointer_not_hidden_by_later_value(self):
        self.check_invalid([self.beacon("AAAAAA", "S0-bad")] + self.lines())

    def test_malformed_optional_slot(self):
        lines = [line for line in self.lines() if "MOD-S8-" not in line]
        self.check_invalid(lines + [self.beacon("AAAAAA", "S8-bad")])

    def test_disagreeing_base(self):
        lines = [line.replace(hex(REF_VP - 0xC6A1B28), "0x1") for line in self.lines()]
        self.check_invalid(lines)

    def test_identical_duplicates_remain_valid(self):
        lines = self.lines()
        result = self.run_tool(self.make_log(lines + lines), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)[0]
        self.assertTrue(record["run_valid"])
        self.assertEqual(record["layout_verdict"], "MATCH_REFERENCE_DELTAS")
        self.assertNotIn("vp_rva_assumed", record)
        self.assertNotIn("vp_rva_confirmed", record)
        self.assertEqual(record["absolute_rva"], "unresolved")

    def test_invalid_run_keeps_diagnostics(self):
        record = self.check_invalid(self.lines()[:-1])
        self.assertEqual(record["layout_verdict"], "MATCH_REFERENCE_DELTAS")
        self.assertIn("slot_deltas", record)

    def test_mixed_runs_and_uid_filter(self):
        lines = self.lines() + [line.replace("AAAAAA", "BBBBBB").replace(
            "ok%3Dtrue", "ok%3Dfalse") for line in self.lines()]
        path = self.make_log(lines)
        result = self.run_tool(path, "--json")
        self.assertEqual(result.returncode, 0)
        records = json.loads(result.stdout)
        self.assertEqual([r["run_valid"] for r in records], [True, False])
        result = self.run_tool(path, "--uid", "BBBBBB", "--json")
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
