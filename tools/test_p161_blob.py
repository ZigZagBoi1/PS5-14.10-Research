#!/usr/bin/env python3
"""Pins for probes/phase13_webkit/p161-length-window.js blob construction.

The chunk must append one call per CHUNK_UNITS iteration, cycling through the
selected mode's units.  A one-copy ``units.join('')`` chunk makes the blob far
shorter than the claimed call count, so it cannot reach the intended wrap.

Offline and read-only: no console is contacted and no full blob is built.
"""

import unittest
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probes" / "phase13_webkit" / "p161-length-window.js"

N_OVERFLOW = 38348816
CHUNK = 4000000


CHUNK_LOOP = re.compile(
    r"""
    var\s+chunkText\s*=\s*''\s*;
    \s*for\s*\(\s*var\s+c\s*=\s*0\s*;\s*c\s*<\s*CHUNK_UNITS\s*;\s*c\+\+\s*\)
    \s*chunkText\s*\+=\s*units\s*\[\s*c\s*%\s*units\.length\s*\]\s*;
    """,
    re.VERBOSE,
)


def build_overflow_fragment(source):
    """Return only the source-owned overflow builder, not the whole probe."""
    start = source.index("  function buildOverflow() {")
    end = source.index("\n  }\n})();", start)
    return source[start:end]


def has_full_chunk_constructor(source):
    """Recognize the bounded source contract for a reusable full-size chunk."""
    fragment = build_overflow_fragment(source)
    loop = CHUNK_LOOP.search(fragment)
    if not loop:
        return False

    after_loop = fragment[loop.end():]
    return (
        "var CHUNK_UNITS = 4000000;" in fragment[:loop.start()]
        and "var fullChunks = Math.floor(N_OVERFLOW / CHUNK_UNITS);" in after_loop
        and "for (var k = 0; k < fullChunks; k++) parts.push(chunkText);" in after_loop
    )


def bounded_chunk_prefix(source, units, calls):
    """Model the source-recognized modulo loop without allocating a full chunk."""
    if not has_full_chunk_constructor(source):
        raise ValueError("source does not construct a full chunk")
    return "".join(units[index % len(units)] for index in range(calls))


class BlobChunkTests(unittest.TestCase):
    def setUp(self):
        self.source = PROBE.read_text(encoding="utf-8")

    def test_chunk_constructor_builds_one_call_per_chunk_unit(self):
        self.assertTrue(has_full_chunk_constructor(self.source))

    def test_chunk_constructor_cycles_pair_units_in_bounded_prefix(self):
        self.assertEqual(
            bounded_chunk_prefix(self.source, ["a();", "b();"], 5),
            "a();b();a();b();a();",
        )

    def test_one_copy_chunk_mutation_is_rejected(self):
        fragment = build_overflow_fragment(self.source)
        loop = CHUNK_LOOP.search(fragment)
        self.assertIsNotNone(loop, "current source must provide a mutation target")
        assert loop is not None
        mutated = self.source.replace(loop.group(), "var chunkText = units.join('');", 1)
        self.assertFalse(has_full_chunk_constructor(mutated))

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
