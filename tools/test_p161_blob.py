#!/usr/bin/env python3
"""Behavioural checks for probes/phase13_webkit/p161-length-window.js.

The committed probe once built each blob chunk from units.join('') once, so the
generated function held ~2.35M op_calls instead of 38,348,816 and the metadata
table never wrapped. A third-console run caught it live: BLOB-9MB-calls=
38348816, SURVIVED, and the worker busy-loop never detected corruption.

The probe itself carries the guard: it beacons BLOB-MISMATCH-<actual>-
<expected> when the generated source is not exactly calls * 4 + 53 bytes. These
tests run the probe under node with the browser pieces it needs and check what
it reports, so the chunk construction is measured and not pinned as source
text.

Offline and read-only: no console is contacted.
"""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probes" / "phase13_webkit" / "p161-length-window.js"
HARNESS = ROOT / "tools" / "p161_blob_harness.js"

N_OVERFLOW = 38348816
CHUNK = 4000000
HARNESS_CALLS = 4000000
NODE = shutil.which("node")


def run_probe(mode="pair", calls=HARNESS_CALLS, probe=PROBE):
    """Run the probe under node and return the beacons it reported."""
    out = subprocess.run(
        [NODE, str(HARNESS), str(probe), mode, str(calls)],
        capture_output=True, text=True, timeout=120)
    if out.returncode not in (0, 1):
        raise AssertionError("harness failed: %s" % out.stderr.strip()[-400:])
    return json.loads(out.stdout.strip().splitlines()[-1])


@unittest.skipIf(NODE is None, "node is not installed")
class BlobChunkTests(unittest.TestCase):
    def test_blob_holds_every_call(self):
        result = run_probe()
        beacons = result["beacons"]
        self.assertTrue(
            any(b.startswith("V161-pair-BLOB-") for b in beacons),
            "the probe never reported a blob: %s" % beacons)
        self.assertFalse(
            [b for b in beacons if "MISMATCH" in b],
            "the generated source was not the expected size: %s" % beacons)
        expected_bytes = HARNESS_CALLS * 4 + 53
        self.assertEqual(
            result["blobMB"], "%dMB" % int(expected_bytes / 1048576))

    def test_probe_reports_the_mode_in_its_beacons(self):
        result = run_probe(mode="pair")
        self.assertIn("V161-pair-BOOT", result["beacons"])
        result = run_probe(mode="single")
        self.assertIn("V161-single-BOOT", result["beacons"])

    def test_single_mode_envelope_matches_p156(self):
        units = ["a();"]
        per_chunk = CHUNK // len(units)
        chunk_text = "".join(units) * per_chunk
        chunks = N_OVERFLOW // (per_chunk * len(units))
        calls_done = 0
        total_bytes = 0
        total_calls = 0
        for _ in range(chunks):
            total_bytes += len(chunk_text)
            calls_done += per_chunk * len(units)
        for r in range(N_OVERFLOW - calls_done):
            total_bytes += len(units[r % len(units)])
            total_calls += 1
        total_calls += chunks * per_chunk * len(units)
        self.assertEqual(total_calls, N_OVERFLOW)
        # ~146MB source, the p156 envelope (9 x 16MB chunks + remainder)
        self.assertGreater(total_bytes, 140 * 1024 * 1024)
        self.assertLess(total_bytes, 160 * 1024 * 1024)

    def test_pair_mode_envelope_matches_p156(self):
        units = ["a();", "b();"]
        per_chunk = CHUNK // len(units)
        chunk_text = "".join(units) * per_chunk
        chunks = N_OVERFLOW // (per_chunk * len(units))
        calls_done = chunks * per_chunk * len(units)
        rest = N_OVERFLOW - calls_done
        total_calls = calls_done + rest
        total_bytes = chunks * len(chunk_text) + rest * len("a();")
        self.assertEqual(total_calls, N_OVERFLOW)
        self.assertGreater(total_bytes, 140 * 1024 * 1024)
        self.assertLess(total_bytes, 160 * 1024 * 1024)
        # wrap arithmetic unchanged: N * 112 = 2^32 + 100096
        self.assertEqual(N_OVERFLOW * 112, 2**32 + 100096)


if __name__ == "__main__":
    unittest.main()
