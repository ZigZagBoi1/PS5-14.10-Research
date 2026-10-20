"""Tests for the bounded no-console offline verifier."""

from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools" / "verify_offline.py"


class OfflineVerificationCliTests(unittest.TestCase):
    def test_run_suite_propagates_a_selected_test_failure(self):
        from tools import verify_offline

        self.assertTrue(callable(getattr(verify_offline, "run_suite", None)))

        class FailingTest(unittest.TestCase):
            def runTest(self):
                self.fail("intentional failure")

        stream = __import__("io").StringIO()
        self.assertEqual(verify_offline.run_suite(unittest.TestSuite([FailingTest()]), stream), 1)

    def test_default_run_executes_the_bounded_suite(self):
        proc = subprocess.run(
            [sys.executable, str(RUNNER)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Ran ", proc.stderr)
        self.assertIn("OK", proc.stderr)

    def test_list_is_sorted_and_uses_only_the_bounded_suite(self):
        proc = subprocess.run(
            [sys.executable, str(RUNNER), "--list"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        modules = tuple(line for line in proc.stdout.splitlines() if line)
        self.assertEqual(modules, tuple(sorted(modules)))
        self.assertEqual(modules, (
            "tests.test_audit_research",
            "tools.test_analyze_result",
            "tools.test_deep_result_scanner",
            "tools.test_evidence_pins",
            "tools.test_handler_claim_audit",
            "tools.test_remaining_cve_triage",
            "tools.test_sys622_bitmap",
            "tools.test_syscall_labels",
            "tools.test_umtx454_correction",
            "tools.test_webkit_false_positive",
        ))


if __name__ == "__main__":
    unittest.main()
