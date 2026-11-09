"""Bounded synthetic fixtures independent of production evidence constants."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from tools.check_fault_oracle_boundary import verify_capture, verify_gap


class BoundaryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        directory = self.root / "results/phase17_new_vectors"
        directory.mkdir(parents=True)
        self.path = directory / "fixture.txt"
        first, second = bytearray(256), bytearray(256)
        struct.pack_into("<I", first, 24, 0x14)
        struct.pack_into("<I", second, 24, 0x15)
        # Each literal header is 26 bytes; second starts after 26+256+1 bytes.
        self.data = (b"[T000] 0x0000000000001000\n" + first + b"\n"
                     + b"[T001] 0x0000000000002000\n" + second)
        self.expected = ((0, 0, 4096, 20), (1, 283, 8192, 21))
        self.path.write_bytes(self.data)

    def check(self, data=None, expected=None):
        if data is None:
            data = self.data
        return verify_capture(self.root, "fixture.txt", hashlib.sha256(data).hexdigest(),
                              2, self.expected if expected is None else expected)

    def test_correct_observations(self):
        self.assertEqual(self.check(), {0: (0, 4096, 20), 1: (283, 8192, 21)})

    def test_modified_discriminator_rejected_even_with_matching_fixture_hash(self):
        data = bytearray(self.data)
        data[26+24] = 0x15
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "discriminator mismatch"):
            self.check(data)

    def test_modified_evidence_hash_rejected(self):
        self.path.write_bytes(self.data + b"changed")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.check()

    def test_invalid_record_offset(self):
        with self.assertRaisesRegex(ValueError, "offset/address"):
            self.check(expected=((0, 1, 4096, 20), (1, 283, 8192, 21)))

    def test_missing_capture(self):
        with self.assertRaisesRegex(ValueError, "missing capture"):
            verify_capture(self.root, "absent.txt", "0"*64, 2, self.expected)

    def test_correct_gap_literal_expectation(self):
        self.assertEqual(verify_gap(0xFFFFFFFFD3FFF000, 0xFFFFFFFFDA400000), 25600)

    def test_incorrect_gap_arithmetic(self):
        with self.assertRaisesRegex(ValueError, "gap arithmetic mismatch"):
            verify_gap(0xFFFFFFFFD3FFF000, 0xFFFFFFFFDA3FF000)
        with self.assertRaisesRegex(ValueError, "gap arithmetic mismatch"):
            verify_gap(0xFFFFFFFFD3FFF001, 0xFFFFFFFFDA400000)


if __name__ == "__main__":
    unittest.main()
