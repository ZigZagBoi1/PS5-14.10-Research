"""Tests for tools/gen_presence_map.py."""

import json
import os
import tempfile
import unittest

import gen_presence_map


def record(num, status, detail=None):
    rec = {"num": num, "status": status, "attempts": []}
    if detail is not None:
        rec["attempts"] = [{"detail": detail}]
    return rec


class LoadMeasurementsTest(unittest.TestCase):
    def write_sweep(self, directory, name, started_at, records):
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"started_at": started_at, "records": records}, f)
        return path

    def test_connect_failed_is_not_a_measurement(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write_sweep(tmp, "a.json", "2026-10-21T13:00:00",
                             [record(523, "KILLED_IN_CALL"),
                              record(524, "CONNECT_FAILED")])
            got = gen_presence_map.load_measurements(os.path.join(tmp, "*.json"))
            self.assertEqual(sorted(got), [523])
            self.assertEqual(got[523][1], "KILLED_IN_CALL")

    def test_connect_failed_does_not_shadow_an_older_measurement(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write_sweep(tmp, "old.json", "2026-10-21T10:00:00",
                             [record(523, "RETURNED", "ret=0xFFFFFFFFFFFFFFFF")])
            self.write_sweep(tmp, "new.json", "2026-10-21T13:00:00",
                             [record(523, "CONNECT_FAILED")])
            got = gen_presence_map.load_measurements(os.path.join(tmp, "*.json"))
            self.assertEqual(got[523][2], "0xFFFFFFFFFFFFFFFF")

    def test_newest_record_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write_sweep(tmp, "old.json", "2026-10-21T10:00:00",
                             [record(99, "KILLED_IN_CALL")])
            self.write_sweep(tmp, "new.json", "2026-10-21T13:00:00",
                             [record(99, "RETURNED", "ret=0x0")])
            got = gen_presence_map.load_measurements(os.path.join(tmp, "*.json"))
            self.assertEqual(got[99][1], "RETURNED")

    def test_no_output_keeps_its_own_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write_sweep(tmp, "a.json", "2026-10-21T13:00:00",
                             [record(572, "NO_OUTPUT")])
            got = gen_presence_map.load_measurements(os.path.join(tmp, "*.json"))
            self.assertEqual(got[572][1], "NO_OUTPUT")


class RenderTest(unittest.TestCase):
    def test_states_render_as_before(self):
        lines = gen_presence_map.render(
            {99: "netcontrol"},
            {99: ("2026-10-21T13:00:00", "RETURNED", "0xFFFFFFFFFFFFFFFF"),
             100: ("2026-10-21T13:00:00", "KILLED_IN_CALL", None)})
        self.assertIn("| 99 | `netcontrol` | `-1` | present |", lines)
        self.assertIn("| 100 | `?` | - | kills |", lines)


if __name__ == "__main__":
    unittest.main()
