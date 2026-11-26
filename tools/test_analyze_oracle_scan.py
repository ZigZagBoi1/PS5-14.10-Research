"""Offline tests for the +2 oracle-scan grader; all inputs are synthetic."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "analyze_oracle_scan.py"


class OracleScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "scan.log"

    def run_tool(self, lines, *args):
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(TOOL), str(self.log), "--json", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def records(self, lines, *args):
        result = self.run_tool(lines, *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_plus2_read_classes(self):
        record = self.records([
            "L1+0=0",
            "L1+8=0x10002",
            "L1+16=0x100000",
            "L1+24=0x110000",
            "L1+32=1",
        ])[0]
        self.assertEqual(
            [r["class"] for r in record["reads"]],
            ["SMALL", "TEXT", "HEAP", "CEILING", "SMALL"],
        )
        self.assertEqual(record["verdict"], "TEXT_FAMILY_ONLY")
        self.assertTrue(record["budget_ok"])

    def test_text_pointer_requires_read_confirm_and_vtab(self):
        lines = [
            "P3+0=0x1A201",
            "P3+2=0x10002",
            "P3+8=0x110000",
            "P3+16=0",
            "SELF=0x1000384480",
            "VTAB=0x10001A201",
            "CALLS=87",
        ]
        record = self.records(lines)[0]
        self.assertEqual(record["verdict"], "TEXT_PTR_CONFIRMED")
        self.assertEqual(record["calls_recomputed"], 87)
        self.assertTrue(record["self_found"])
        self.assertEqual(
            [r["class"] for r in record["reads"][:3]], ["TEXT", "TEXT", "CEILING"]
        )

    def test_family_confirmation_without_vtab_is_downgraded(self):
        record = self.records(["P3+0=0x1A201", "P3+2=0x10002", "CALLS=42"])[0]
        self.assertEqual(record["verdict"], "TEXT_FAMILY_CONFIRMED")
        self.assertIsNone(record["vtab_claim"])

    def test_budget_overrun_fails_closed(self):
        lines = [f"P3+{i * 8}=0x1A201" for i in range(6)] + ["SELF=1"]
        result = self.run_tool(lines)
        self.assertEqual(result.returncode, 1)
        record = json.loads(result.stdout)[0]
        self.assertEqual(record["verdict"], "INVALID_RUN")
        self.assertFalse(record["budget_ok"])
        self.assertEqual(record["calls_recomputed"], 129)
        self.assertTrue(any("PAGE_CALL_BUDGET_EXCEEDED" in e for e in record["validation_errors"]))

    def test_call_count_mismatch_fails_closed(self):
        result = self.run_tool([
            "P3+0=0x1A201", "P3+2=0x10002", "VTAB=0x10001A201", "CALLS=21"
        ])
        self.assertEqual(result.returncode, 1)
        record = json.loads(result.stdout)[0]
        self.assertEqual(record["verdict"], "INVALID_RUN")
        self.assertTrue(any("CALL_COUNT_MISMATCH" in e for e in record["validation_errors"]))

    def test_vtab_out_of_text_band_fails_closed(self):
        result = self.run_tool([
            "P3+0=0x1A201", "P3+2=0x10002", "VTAB=0x1000384480"
        ])
        self.assertEqual(result.returncode, 1)
        record = json.loads(result.stdout)[0]
        self.assertTrue(any("VTAB_OUT_OF_TEXT_BAND" in e for e in record["validation_errors"]))

    def test_encoded_beacons_group_by_uid_and_filter(self):
        lines = [
            "[00:00:01] BEACON 10.0.0.1: P3+0%3D0x1A201?t%3D1&u%3DABC123",
            "[00:00:02] BEACON 10.0.0.1: P3+2%3D0x10002?t%3D2&u%3DABC123",
            "[00:00:03] BEACON 10.0.0.1: P3+0%3D0?t%3D3&u%3DDEF456",
        ]
        records = self.records(lines)
        self.assertEqual([r["uid"] for r in records], ["ABC123", "DEF456"])
        self.assertEqual(records[0]["verdict"], "TEXT_FAMILY_CONFIRMED")
        self.assertEqual(records[1]["verdict"], "NO_TEXT_POINTER")
        filtered = self.records(lines, "--uid", "DEF456")
        self.assertEqual([r["uid"] for r in filtered], ["DEF456"])

    def test_malformed_read_value_fails_closed(self):
        result = self.run_tool(["P3+0=0xZZ", "P3+2=0x10002"])
        self.assertEqual(result.returncode, 1)
        record = json.loads(result.stdout)[0]
        self.assertEqual(record["verdict"], "INVALID_RUN")
        self.assertIn("malformed value", " ".join(record["validation_errors"]))

    def test_no_reads_is_a_clean_negative(self):
        record = self.records(["SELF=1"])[0]
        self.assertEqual(record["verdict"], "NO_TEXT_POINTER")
        self.assertEqual(record["calls_recomputed"], 3)

    def test_fullwidth_echo_promotes_to_fullwidth_confirmed(self):
        record = self.records([
            "P3+0=0x1A201", "P3+2=0x10002", "VTAB=0x10001A201", "CALLS=42",
            "MARK_P3+0=0x0000010001A201",
            "GEN=1", "FW_P3+0=0x0000010001A201",
            "GEN=2", "FW_P3+0=0x0000010001A201",
        ])[0]
        self.assertEqual(record["verdict"], "FULLWIDTH_CONFIRMED")
        self.assertEqual(record["calls_recomputed"], 42)
        self.assertEqual(len(record["fullwidth_reads"]), 2)
        self.assertTrue(any("MARKER_ECHO_OK" in n for n in record["notes"]))

    def test_echo_mismatch_downgrades_and_keeps_text_ptr_confirmed(self):
        record = self.records([
            "P3+0=0x1A201", "P3+2=0x10002", "VTAB=0x10001A201",
            "MARK_P3+0=0x0000010001A201",
            "GEN=1", "FW_P3+0=0x0000010001A201",
            "GEN=2", "FW_P3+0=0x0000010001A202",
        ])[0]
        self.assertEqual(record["verdict"], "TEXT_PTR_CONFIRMED")
        self.assertTrue(any("MARKER_MISMATCH" in n for n in record["notes"]))

    def test_full_width_comparison_never_truncates_to_low_32_bits(self):
        record = self.records([
            "P3+0=0x1A201", "P3+2=0x10002", "VTAB=0x10001A201",
            "MARK_P3+0=0x0000010001A201",
            "GEN=1", "FW_P3+0=0x0000010001A201",
            "GEN=2", "FW_P3+0=0x0000020001A201",
        ])[0]
        self.assertEqual(record["verdict"], "TEXT_PTR_CONFIRMED")
        self.assertEqual(record["echo_mask"], "0xffffffffffff")
        self.assertTrue(any("MARKER_MISMATCH" in n for n in record["notes"]))

    def test_explicit_narrow_echo_mask_is_honored(self):
        record = self.records([
            "P3+0=0x1A201", "P3+2=0x10002", "VTAB=0x10001A201",
            "ECHO_MASK=0xFFFFFFFF",
            "GEN=1", "FW_P3+0=0x0000010001A201",
            "GEN=2", "FW_P3+0=0x0000020001A201",
        ])[0]
        self.assertEqual(record["verdict"], "FULLWIDTH_CONFIRMED")
        self.assertEqual(record["echo_mask"], "0xffffffff")

    def test_flip_class_value_downgrades_even_with_text_confirmation(self):
        record = self.records([
            "P3+0=0x1A201", "P3+2=0x10002", "VTAB=0x10001A201",
            "GEN=1", "FW_P3+0=0x80000004",
            "GEN=2", "FW_P3+0=0x7FFFFFF4",
        ])[0]
        self.assertEqual(record["verdict"], "FLIP_CLASS_SUSPECT")
        self.assertTrue(record["flip_class_suspect"])

    def test_single_generation_cannot_promote(self):
        record = self.records([
            "P3+0=0x1A201", "P3+2=0x10002", "VTAB=0x10001A201",
            "FW_P3+0=0x0000010001A201",
        ])[0]
        self.assertEqual(record["verdict"], "TEXT_PTR_CONFIRMED")
        self.assertTrue(any("NEED_TWO_GENERATIONS" in n for n in record["notes"]))

    def test_malformed_fullwidth_token_fails_closed(self):
        result = self.run_tool([
            "P3+0=0x1A201", "P3+2=0x10002", "VTAB=0x10001A201",
            "FW_P3+0=0xZZ", "GEN=2", "FW_P3+0=0x0000010001A201",
        ])
        self.assertEqual(result.returncode, 1)
        record = json.loads(result.stdout)[0]
        self.assertEqual(record["verdict"], "INVALID_RUN")
        self.assertTrue(any("malformed full-width" in e for e in record["validation_errors"]))

    def test_missing_uid_filter_fails_closed(self):
        result = self.run_tool(["P3+0=0x1A201"], "--uid", "NOPE00")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), [])


if __name__ == "__main__":
    unittest.main()
