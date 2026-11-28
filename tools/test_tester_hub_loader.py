#!/usr/bin/env python3
"""Behavioural checks for the tester-hub stage loader.

The loader must deliver synchronous results, settle each run exactly once, and
reject callbacks carried over from an earlier run. These tests execute the
committed runProbeStage body under Node with DOM and timer stubs; no console or
network transport is contacted.
"""

import json
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probes" / "phase14_rop" / "tester-hub.html"
HARNESS = ROOT / "tools" / "tester_hub_loader_harness.js"
NODE = shutil.which("node")


def run_loader():
    if NODE is None:
        raise RuntimeError("node is not installed")
    proc = subprocess.run(
        [NODE, str(HARNESS), str(PROBE)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError("loader harness failed: %s" % proc.stderr.strip()[-400:])
    return json.loads(proc.stdout.strip().splitlines()[-1])


@unittest.skipIf(NODE is None, "node is not installed")
class TesterHubLoaderTests(unittest.TestCase):
    def test_synchronous_and_duplicate_completion(self):
        result = run_loader()
        self.assertEqual(result["sync_duplicate"], [True])
        self.assertTrue(result["sync_timer_cleared"])

    def test_timeout_and_load_error_are_one_shot(self):
        result = run_loader()
        self.assertEqual(result["timeout_late"], [False])
        self.assertEqual(result["error_late"], [False])

    def test_stale_callback_cannot_complete_next_run(self):
        result = run_loader()
        self.assertEqual(result["cross_timeout"], [False])
        self.assertEqual(result["cross_sync"], [True])
        self.assertEqual(result["cross_error"], [False])

    def test_same_stage_rerun_is_isolated(self):
        result = run_loader()
        self.assertEqual(result["same_stage_timeout"], [False])

    def test_callback_requires_matching_run_token(self):
        result = run_loader()
        self.assertTrue(result["has_run_token"])
        self.assertEqual(result["missing_token_before_valid"], [])
        self.assertEqual(result["wrong_token_before_valid"], [])
        self.assertEqual(result["valid_token"], [True])


if __name__ == "__main__":
    unittest.main()
