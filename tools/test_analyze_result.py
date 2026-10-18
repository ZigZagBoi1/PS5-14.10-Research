#!/usr/bin/env python3
"""Regression tests for kernel-pointer reporting in tools/analyze_result.py.

A 64-bit value on a marked probe line (">>> KPTR ...") and on an unmarked
data line must be classified by the same scan: a marker's own hex offset is
never a pointer, a marked pointer is reported exactly once, and only
kernel-band values may produce pointer rows.

Marked lines are the shapes the 14.10 probes actually print:
probes/phase14_final_push/54f_kaslr_deep.lua:79
    "  >>> KPTR [<label>+0xNNN]: 0xHHHHHHHH_LLLLLLLL"
probes/phase14_final_push/55a_post_kaslr_kread.lua:139
    "  >>> KPTR at kinfo+0xNNN: 0xHHHHHHHH_LLLLLLLL"

Each case runs the real analyze_file over a temporary result text file and
reads the standalone pointer-analysis rows back as integers, so an assertion
can never be satisfied by the source line echoed back in the report.
"""

import contextlib
import io
import os
import re
import tempfile
import unittest

import analyze_result

# ANSI SGR sequences surround parts of the report; strip them before matching.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# A standalone pointer row of the kernel pointer analysis section, e.g.
# "    Line 4: 0xFFFF8000_12345678".  Matched whole, so echoed finding lines
# ("[!!!] Line 1: ...") and crash lines cannot be mistaken for output evidence.
POINTER_ROW_RE = re.compile(r"^Line \d+: (0x[0-9A-Fa-f]{8}_[0-9A-Fa-f]{8})$")

# Synthetic leak value; not captured PS5 data.
KERNEL_PTR = 0xFFFF800012345678

# Marked lines that must report KERNEL_PTR exactly once.
MARKER_CASES = (
    ("bracketed marker with hex offset",
     "  >>> KPTR [kinfo+0x060]: 0xFFFF8000_12345678", [KERNEL_PTR]),
    ("inline-at marker with hex offset",
     "  >>> KPTR at kinfo+0x060: 0xFFFF8000_12345678", [KERNEL_PTR]),
    ("direct marker",
     "  >>> KPTR: 0xFFFF8000_12345678", [KERNEL_PTR]),
    ("kernel pointer marker",
     "  >>> KERNEL POINTER: 0xFFFF8000_12345678", [KERNEL_PTR]),
)

# Marked lines whose payload is not a kernel pointer: no row, no count.
INVALID_MARKER_CASES = (
    ("offset-only marker line without a value",
     "  >>> KPTR at kinfo+0x060:", []),
    ("marker with zeroed value",
     "  >>> KPTR: 0x00000000_00000000", []),
    ("marker with userland value",
     "  >>> KPTR: 0x0000007F_ABCDEF00", []),
    ("marker with all-ones sentinel",
     "  >>> KPTR: 0xFFFFFFFF_FFFFFFFF", []),
)

# Unmarked lines: real data output is scanned, a printed input is not.
UNMARKED_CASES = (
    ("kernel pointer in buffer data",
     "  612(h=0,m=0) ret=0 buf[0]=0xFFFF8000_12345678", [KERNEL_PTR]),
    ("test input address is not output evidence",
     "[*] GPU mmap page: 0xFFFF8000_12345678", []),
)


def _pointer_rows(output):
    """Values of standalone pointer-analysis rows only, as integers."""
    values = []
    for line in ANSI_RE.sub("", output).splitlines():
        match = POINTER_ROW_RE.match(line.strip())
        if match is not None:
            values.append(int(match.group(1), 16))
    return values


class KernelPointerAnalysisTests(unittest.TestCase):
    def _analyze(self, text):
        """Run analyze_file on one temporary result file, capture the report."""
        with tempfile.TemporaryDirectory(prefix="analyze-result-") as tmp:
            path = os.path.join(tmp, "result.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                result = analyze_result.analyze_file(path)
        return result, _pointer_rows(captured.getvalue())

    def _assert_pointer_rows(self, line, expected):
        result, rows = self._analyze(line + "\n")
        reds, yellows, kptrs = result
        detail = "line=%r reds=%d yellows=%d kptrs=%d rows=%s" % (
            line, reds, yellows, kptrs,
            ["0x%016X" % value for value in rows])
        self.assertEqual(kptrs, len(expected), detail)
        self.assertEqual(rows, expected, detail)
        self.assertEqual(reds, len(expected), detail)

    def test_marked_lines_report_each_pointer_once(self):
        for label, line, expected in MARKER_CASES:
            with self.subTest(case=label):
                self._assert_pointer_rows(line, expected)

    def test_invalid_marker_payloads_report_no_pointer(self):
        for label, line, expected in INVALID_MARKER_CASES:
            with self.subTest(case=label):
                self._assert_pointer_rows(line, expected)

    def test_unmarked_lines_follow_data_output_gating(self):
        for label, line, expected in UNMARKED_CASES:
            with self.subTest(case=label):
                self._assert_pointer_rows(line, expected)


if __name__ == "__main__":
    unittest.main()
