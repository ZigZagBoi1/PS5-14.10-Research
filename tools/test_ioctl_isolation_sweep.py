"""Offline tests for tools/ioctl_isolation_sweep.py."""

import unittest

from tools.ioctl_isolation_sweep import classify, build_probe, parse_numbers
from tools.send_probe import STATUS_COMPLETE, STATUS_IDLE_TIMEOUT


class ParseNumbersTest(unittest.TestCase):
    def test_decimal_range(self):
        self.assertEqual(parse_numbers("0-3"), [0, 1, 2, 3])

    def test_hex_range(self):
        self.assertEqual(parse_numbers("0x00-0x03"), [0, 1, 2, 3])

    def test_explicit_hex_list(self):
        self.assertEqual(parse_numbers("0x10,0x17"), [0x10, 0x17])

    def test_mixed(self):
        self.assertEqual(parse_numbers("0x0a, 12"), [10, 12])

    def test_descending_range_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_numbers("5-1")


class BuildProbeTest(unittest.TestCase):
    def test_command_is_encoded_as_eight_hex_digits(self):
        probe = build_probe("/dev/dmem1", 0x80108017)
        self.assertIn("uint64(0x80108017)", probe)

    def test_device_path_is_quoted_into_the_open_call(self):
        probe = build_probe("/dev/gic", 0xC0104701)
        self.assertIn('put_str("/dev/gic")', probe)

    def test_argument_size_reaches_alloc_and_the_fill_loop(self):
        probe = build_probe("/dev/dmem1", 0x80108017, arg_size=0x40)
        self.assertIn("memory.alloc(0x40)", probe)
        self.assertIn("0x40 - 4", probe)

    def test_open_flags_are_carried(self):
        probe = build_probe("/dev/dmem1", 0x80108017, flags=0)
        self.assertIn("uint64(0), uint64(0))", probe)

    def test_probe_disables_stdout_buffering(self):
        probe = build_probe("/dev/dmem1", 1)
        self.assertIn('io.stdout:setvbuf("no")', probe)
        self.assertLess(probe.index('setvbuf'), probe.index('=== IOCTL SWEEP'))

    def test_probe_ends_with_a_marker(self):
        self.assertTrue(build_probe("/dev/dmem1", 1).rstrip().endswith('print("DONE")'))


class ClassifyTest(unittest.TestCase):
    def test_complete_survived(self):
        self.assertEqual(classify(STATUS_COMPLETE), "survived")

    def test_idle_timeout_stopped(self):
        self.assertEqual(classify(STATUS_IDLE_TIMEOUT), "stopped")


if __name__ == "__main__":
    unittest.main()
