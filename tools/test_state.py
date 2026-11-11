#!/usr/bin/env python3
"""Regression tests for ``tools/state.py``.

The tool exists so that research state survives a context compaction, which
only works if two properties hold: the ledger is append-only and idempotent
(re-running ``seed`` must never duplicate the thousands of existing captures),
and the state block round-trips values that contain spaces, colons and
parentheses unchanged. A silent failure in either property would corrupt the
only record a later session reads.

Run with::

    python -m unittest discover -s tools -p "test_state.py" -v

Read-only outside its own temp directory: no console contact, no writes to the
repository's real ``results/``.
"""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from tools import state


class StateToolTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "results" / "phase1").mkdir(parents=True)
        state._set_root(str(self.root))

    def tearDown(self):
        self._tmp.cleanup()

    def _capture(self, rel, body="x"):
        path = self.root / "results" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def _run(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = state.main(argv)
        return code, out.getvalue()

    def _ledger(self):
        return Path(state.INDEX).read_text(encoding="utf-8").splitlines()

    def test_seed_is_idempotent(self):
        self._capture("phase1/1335a_claim_20261106_145651.txt")
        self._capture("1331a_base_20261106_143746.txt")

        self._run(["seed"])
        first = self._ledger()

        code, out = self._run(["seed"])
        self.assertEqual(code, 0)
        self.assertIn("seeded 0 row(s)", out)
        self.assertEqual(self._ledger(), first, "a second seed duplicated rows")

    def test_seed_orders_by_capture_timestamp_and_derives_probe(self):
        self._capture("1335a_late_20261106_145651.txt")
        self._capture("1331a_early_20261106_143746.txt")

        self._run(["seed"])
        rows = [line for line in self._ledger() if line.startswith("| 2026-")]
        self.assertEqual(len(rows), 2)
        self.assertIn("| 1331a |", rows[0])
        self.assertIn("| 1335a |", rows[1])

    def test_row_binds_the_newest_matching_capture(self):
        old = self._capture("1340f_first_20261106_231621.txt")
        new = self._capture("1340f_second_20261106_232418.txt")
        os.utime(old, (1_700_000_000, 1_700_000_000))

        code, _ = self._run([
            "row", "1340f", "--claim", "multi-round race", "--result", "reclaim=0",
            "--grade", "V",
        ])

        self.assertEqual(code, 0)
        last = self._ledger()[-1]
        self.assertIn("| 1340f |", last)
        self.assertIn("| V |", last)
        self.assertTrue(last.rstrip().endswith("results/1340f_second_20261106_232418.txt |"))

    def test_row_without_a_capture_records_a_dash(self):
        code, _ = self._run(["row", "9999z", "--claim", "no capture", "--grade", "I"])
        self.assertEqual(code, 0)
        self.assertTrue(self._ledger()[-1].rstrip().endswith("| - |"))

    def test_state_round_trips_values_with_colons_and_spaces(self):
        value = "192.168.1.121:9026 (a probe death kills the game; only the user can relaunch)"
        self._run(["set", "console=" + value, "last_probe=1340f"])

        code, out = self._run(["show"])
        self.assertEqual(code, 0)
        self.assertIn("console", out)
        self.assertIn(value, out)
        self.assertIn("last_probe", out)

        pairs = dict(state._read_state())
        self.assertEqual(pairs["console"], value)
        self.assertEqual(pairs["last_probe"], "1340f")

    def test_set_preserves_existing_keys_and_appends_new_ones(self):
        self._run(["set", "kernel_base=0xFFFFFFFFCD000000"])
        self._run(["set", "brand_new=1"])

        keys = [key for key, _ in state._read_state()]
        self.assertIn("kernel_base", keys)
        self.assertEqual(keys[-1], "brand_new")
        self.assertEqual(keys.count("kernel_base"), 1)

    def test_check_reports_an_unreachable_console_without_raising(self):
        code, out = self._run(["check", "--ip", "127.0.0.1"])
        self.assertEqual(code, 0)
        self.assertIn("127.0.0.1:9026", out)
        self.assertIn("UNREACHABLE", out)

    def test_date_only_capture_is_seeded(self):
        """Older captures carry no clock time; dropping them hides real evidence."""
        self._capture("phase13_webkit/p560_sort_oob_write_20261027.txt")
        _code, out = self._run(["seed"])
        self.assertIn("seeded 1 row", out)
        text = (self.root / "results" / "INDEX.md").read_text(encoding="utf-8")
        self.assertIn("p560_sort_oob_write_20261027.txt", text)
        self.assertIn("| 2026-10-27 |", text)

    def test_pipe_in_a_claim_cannot_add_a_column(self):
        self._run(["row", "9999z", "--claim", "left | forged-column",
                   "--result", "r", "--grade", "M"])
        line = [l for l in self._ledger() if "9999z" in l][0]
        self.assertEqual(line.count("|") - line.count("\\|"), 7)

    def test_newline_in_a_claim_cannot_add_a_row(self):
        self._run(["row", "9999z", "--claim", "first\n| 2026-01-01 | injected |",
                   "--result", "r", "--grade", "M"])
        self.assertEqual(len([l for l in self._ledger() if l.startswith("| 20")]), 1)

    def test_newline_in_a_state_value_is_refused(self):
        self._run(["set", "notes=calm"])
        before = (self.root / "results" / "STATE.md").read_text(encoding="utf-8")
        with self.assertRaises(SystemExit):
            self._run(["set", "notes=first\n- injected: yes"])
        self.assertEqual(
            before, (self.root / "results" / "STATE.md").read_text(encoding="utf-8"))

    def test_state_marker_in_a_value_round_trips(self):
        value = "<!-- STATE:END -->"
        self._run(["set", "notes=" + value])
        self.assertEqual(dict(state._read_state())["notes"], value)

    def test_every_splitlines_separator_is_refused_in_state(self):
        self._run(["set", "notes=calm"])
        before = (self.root / "results" / "STATE.md").read_text(encoding="utf-8")
        for separator in "\v\f\x1c\x1d\x1e\x85\u2028\u2029":
            with self.assertRaises(SystemExit):
                self._run(["set", "notes=first" + separator + "second"])
        self.assertEqual(
            before, (self.root / "results" / "STATE.md").read_text(encoding="utf-8"))

    def test_regrading_a_capture_replaces_its_row(self):
        """A seed row and a graded row for one capture must not both survive."""
        self._capture("phase14_final_push/55c_probe_20261018_095816.txt")
        self._run(["seed"])
        self.assertEqual(len([l for l in self._ledger() if l.startswith("| 20")]), 1)

        _code, out = self._run([
            "row", "55c_probe", "--claim", "void: rejected at the entry check",
            "--result", "0x800E0001 on every read", "--grade", "V",
            "--capture", "results/phase14_final_push/55c_probe_20261018_095816.txt"])
        self.assertIn("replaced 1 row", out)
        rows = [l for l in self._ledger() if l.startswith("| 20")]
        self.assertEqual(len(rows), 1)
        self.assertIn("| V |", rows[0])
        self.assertIn("void: rejected at the entry check", rows[0])

    def test_underscore_files_are_logs_and_are_skipped(self):
        self._capture("_selftest_watchdog_log.txt")
        self._capture("phase1/1335a_claim_20261106_145651.txt")
        _code, out = self._run(["seed"])
        self.assertIn("seeded 1 row", out)


if __name__ == "__main__":
    unittest.main()
