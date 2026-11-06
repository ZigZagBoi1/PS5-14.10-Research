"""Bounded offline regressions for the documented fault-scan wire format.

Format: decode_fault_scan.py:4-12,24-27; producer
probes/phase17_new_vectors/1199a_fault_oracle_kaslr.lua:88-96,159-160.
Semantics: docs/FAULT_ORACLE_KASLR_14_10.md:15-20 (only 4/5 defined).
Other nibbles are *unclassified*, not invented firmware fault meanings;
the CLI documents these as unknown in its module docstring.
No probe, transport, or console code is imported or executed.
"""

from collections import Counter
import hashlib
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

from tools import decode_fault_scan

ROOT = Path(__file__).resolve().parents[1]
DECODER = ROOT / "tools/decode_fault_scan.py"


def record(address, raw, index=0, fill=b"\0"):
    # Independent constants from the wire specification, not decoder globals.
    body = bytearray((fill * 256)[:256])
    struct.pack_into("<I", body, 24, raw)
    return f"[T{index:03d}] 0x{address:016X}\n".encode("ascii") + body


class FaultScanDecoderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "synthetic.bin"

    def decode_file(self, data):
        self.path.write_bytes(data)
        return list(decode_fault_scan.decode(self.path.read_bytes()))

    def cli_file(self, data):
        self.path.write_bytes(data)
        return self.cli_path(self.path)

    def cli_path(self, path):
        proc = subprocess.run([sys.executable, "-B", str(DECODER), str(path)],
                              capture_output=True, text=True, timeout=10,
                              cwd=ROOT, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    def assert_summary(self, output, total, mapped, unmapped, unknown=0):
        # Literal expected counts supplied by each test, never production logic.
        got = {}
        for key in ("Total probes", "Mapped (present)", "Unmapped", "Unknown"):
            match = re.search(r"^" + re.escape(key) + r": (\d+)$", output, re.M)
            self.assertIsNotNone(match, output)
            got[key] = int(match.group(1))
        self.assertEqual(got, {"Total probes": total,
                              "Mapped (present)": mapped, "Unmapped": unmapped,
                              "Unknown": unknown})
        self.assertEqual(got["Total probes"], got["Mapped (present)"]
                         + got["Unmapped"] + got["Unknown"])
        return got["Unknown"]

    def test_all_sixteen_nibbles_preserve_addresses_and_raw_values(self):
        data = b"\n".join(record(0x1000 + i, 0x12345000 + i, i)
                          for i in range(16))
        self.assertEqual(self.decode_file(data),
                         [(0x1000 + i, i, 0x12345000 + i) for i in range(16)])

    def test_all_sixteen_cli_classes_keep_fourteen_unknown(self):
        data = b"\n".join(record(0x1000 + i, i, i) for i in range(16))
        unknown = self.assert_summary(self.cli_file(data), 16, 1, 1, 14)
        self.assertEqual(unknown, 14)

    def test_minimal_unknown_is_not_unmapped(self):
        # Shortest header accepted by the actual CLI grammar; one full zero body.
        data = b"[T0] 0x0\n" + bytes(256)
        self.assertEqual(self.decode_file(data), [(0, 0, 0)])
        self.assertEqual(self.assert_summary(self.cli_file(data), 1, 0, 0, 1), 1)

    def test_documented_main_and_child_codes(self):
        raw = [4, 5, 0x14, 0x15]
        data = b"\n".join(record(0x1000 + i, v, i) for i, v in enumerate(raw))
        self.assertEqual(self.decode_file(data),
                         [(0x1000, 4, 4), (0x1001, 5, 5),
                          (0x1002, 4, 0x14), (0x1003, 5, 0x15)])
        self.assertEqual(self.assert_summary(self.cli_file(data), 4, 2, 2), 0)

    def test_duplicates_are_records_not_deduplicated_addresses(self):
        data = record(0x1000, 0x14) + b"\n" + record(0x1000, 0x14)
        self.assertEqual(self.decode_file(data), [(0x1000, 4, 0x14)] * 2)
        self.assert_summary(self.cli_file(data), 2, 0, 2)

    def test_binary_newlines_and_embedded_header_do_not_split_record(self):
        # Arbitrary bytes are permitted inside the fixed-size context body.
        first = record(0x1000, 0x15, fill=b"\n[T999] 0xDEAD\n")
        second = record(0x2000, 0x14)
        data = b"preamble\n" + first + b"\nstatus\n" + second + b"\nend\n"
        self.assertEqual(self.decode_file(data),
                         [(0x1000, 5, 0x15), (0x2000, 4, 0x14)])
        self.assert_summary(self.cli_file(data), 2, 1, 1)

    def test_every_incomplete_prefix_yields_no_record(self):
        data = record(0x1000, 0x15)
        for cut in range(len(data)):
            with self.subTest(cut=cut):
                self.assertEqual(self.decode_file(data[:cut]), [])
        self.assertEqual(self.decode_file(data), [(0x1000, 5, 0x15)])

    def test_truncated_tail_preserves_previous_complete_record(self):
        first = record(0x1000, 0x14)
        tail = record(0x2000, 0x15)
        for cut in range(len(tail)):
            with self.subTest(cut=cut):
                self.assertEqual(self.decode_file(first + b"\n" + tail[:cut]),
                                 [(0x1000, 4, 0x14)])
        self.assertEqual(self.decode_file(first + b"\n" + tail),
                         [(0x1000, 4, 0x14), (0x2000, 5, 0x15)])

    def check_capture(self, filename, expected, summary):
        path = ROOT / "results/phase17_new_vectors" / filename
        self.assertTrue(path.is_file(), f"Required public artifact missing: {path}")
        before = hashlib.sha256(path.read_bytes()).digest()
        self.assertEqual(list(decode_fault_scan.decode(path.read_bytes())), expected)
        self.assertEqual(Counter(v[1] for v in expected),
                         Counter({4: summary[2], 5: summary[1]}))
        self.assert_summary(self.cli_path(path), *summary)
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)

    def test_public_lower_capture_exact_records_and_summary(self):
        expected = [(0xFFFFFFFF80000000 + i * 0x200000, 4, 0x14)
                    for i in range(512)]
        self.check_capture("1199a_fault_oracle_kaslr_20261104_234210.txt",
                           expected, (512, 0, 512))

    def test_public_upper_capture_exact_records_and_summary(self):
        # Documented stub + 102 MB image; expected addresses are source literals.
        mapped = {0xFFFFFFFFC0000000} | set(
            range(0xFFFFFFFFD4000000, 0xFFFFFFFFDA600000, 0x200000))
        expected = []
        for i in range(512):
            address = 0xFFFFFFFFC0000000 + i * 0x200000
            if address in mapped:
                expected.append((address, 5, 0x15))
            else:
                expected.append((address, 4, 0x14))
        self.check_capture("1199b_fault_oracle_upper_20261104_234410.txt",
                           expected, (512, 52, 460))

    def test_public_edges_capture_exact_records_and_summary(self):
        expected = [(0xFFFFFFFFD3FF8000 + i * 0x1000, 4, 0x14)
                    for i in range(8)]
        expected += [(0xFFFFFFFFDA400000 + i * 0x1000, 5, 0x15)
                     for i in range(512)]
        expected += [(0xFFFFFFFFDA600000 + i * 0x1000, 4, 0x14)
                     for i in range(8)]
        self.check_capture("1199c_fault_oracle_edges_20261104_235448.txt",
                           expected, (528, 512, 16))


if __name__ == "__main__":
    unittest.main()
