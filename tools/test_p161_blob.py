#!/usr/bin/env python3
"""Pins for probes/phase13_webkit/p161-length-window.js blob construction.

The committed probe built each blob chunk from units.join('') once (8 bytes in
pair mode), so the generated function held ~2.35M op_calls instead of
38,348,816 and the metadata table never wrapped. A third-console run caught it
live: BLOB-9MB-calls=38348816, SURVIVED, and the worker busy-loop never
detected corruption. These tests hold the fix and the arithmetic.

Offline and read-only: no console is contacted.
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probes" / "phase13_webkit" / "p161-length-window.js"

N_OVERFLOW = 38348816
CHUNK = 4000000


class BlobChunkTests(unittest.TestCase):
    def setUp(self):
        self.source = PROBE.read_text(encoding="utf-8")

    def test_chunk_is_expanded_not_pushed_once(self):
        self.assertIn(
            "var chunkText = '';\n"
            "    for (var u = 0; u < perChunkCalls; u++) chunkText += units.join('');",
            self.source)
        self.assertNotIn("var chunkText = units.join('');", self.source)

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

    def test_pair_beacon_prefix_records_the_mode(self):
        self.assertIn("V161-' + MODE + '-'", self.source)


if __name__ == "__main__":
    unittest.main()
