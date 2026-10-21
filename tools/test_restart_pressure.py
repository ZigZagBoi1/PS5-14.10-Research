#!/usr/bin/env python3
"""Tests for the restart-pressure driver: parsing, sequencing, verdicts."""

import unittest

from tools import restart_pressure


TRANSCRIPT = """=== PROBE 217a: RESTART PRESSURE SAMPLE ===

SAMPLE pid=94 ops624=1337 mods593=39 vm674=317 c1=6144/3948 c2=2560/2014
DONE
"""


class ParseSampleTest(unittest.TestCase):
    def test_reads_every_field(self):
        sample = restart_pressure.parse_sample(TRANSCRIPT)
        self.assertEqual(sample["pid"], 94)
        self.assertEqual(sample["ops624"], 1337)
        self.assertEqual(sample["vm674"], 317)
        self.assertEqual(sample["c1"], (6144, 3948))
        self.assertEqual(sample["c2"], (2560, 2014))

    def test_missing_line_is_none(self):
        self.assertIsNone(restart_pressure.parse_sample("=== PROBE 217a ===\n"))


class MeasureTest(unittest.TestCase):
    def test_samples_before_each_kill_and_times_the_gap(self):
        calls = []
        clock = {"value": 0.0}

        def take_sample():
            calls.append("sample")
            return {"pid": len(calls)}

        def kill():
            calls.append("kill")

        def wait_ready():
            calls.append("wait")
            clock["value"] += 9.0
            return True

        rows = restart_pressure.measure(2, take_sample, kill, wait_ready,
                                        clock=lambda: clock["value"])

        self.assertEqual(calls, ["sample", "kill", "wait", "sample",
                                 "kill", "wait", "sample"])
        self.assertEqual([row["round"] for row in rows], [0, 1, 2])
        self.assertEqual([row["recovery"] for row in rows], [None, 9.0, 9.0])

    def test_a_lost_loader_ends_the_run_without_a_sample(self):
        state = {"ready": True}

        def wait_ready():
            state["ready"] = False
            return False

        rows = restart_pressure.measure(3, lambda: {"pid": 1}, lambda: None,
                                        wait_ready, clock=lambda: 0.0)

        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[-1]["failed"])
        self.assertIsNone(rows[-1]["sample"])

    def test_a_silent_first_sample_skips_the_kills(self):
        killed = []
        rows = restart_pressure.measure(3, lambda: None,
                                        lambda: killed.append(True),
                                        lambda: True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(killed, [])


class VerdictTest(unittest.TestCase):
    def test_reports_a_counter_that_held_and_one_that_moved(self):
        rows = [
            {"round": 0, "sample": {"pid": 90, "ops624": 100, "vm674": 317},
             "recovery": None},
            {"round": 1, "sample": {"pid": 94, "ops624": 105, "vm674": 317},
             "recovery": 9.0},
            {"round": 2, "sample": {"pid": 99, "ops624": 110, "vm674": 317},
             "recovery": 37.0},
        ]
        text = restart_pressure.verdict(rows)
        self.assertIn("ops624 moved: 100 -> 105 -> 110", text)
        self.assertIn("vm674 held at 317", text)
        self.assertIn("recovery 9.0s to 37.0s", text)

    def test_reports_a_loader_that_never_restarted(self):
        rows = [{"round": 0, "sample": {"pid": 90}, "recovery": None},
                {"round": 1, "sample": {"pid": 90}, "recovery": 0.0}]
        self.assertIn("pid never changed", restart_pressure.verdict(rows))

    def test_needs_two_samples(self):
        rows = [{"round": 0, "sample": {"pid": 90}, "recovery": None}]
        self.assertIn("not enough samples", restart_pressure.verdict(rows))


if __name__ == "__main__":
    unittest.main()
