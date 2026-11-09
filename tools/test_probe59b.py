#!/usr/bin/env python3
"""Structural tests for probe 59b (thr_* family survey).

Verifies:
- Correct syscall numbers for every thr_* call
- Every call has [BEFORE] and [AFTER]/[RETURNED] markers
- thr_exit (431) is NEVER called — it terminates the process
- thr_create (430) is NEVER called — deferred to probe 58e
- thr_new (455) is NEVER called — already confirmed blocked
- thr_kill uses signal 0 (null signal), never a real signal
- thr_suspend uses a zero timeout, never NULL (which would block)
- Buffer allocations are large enough for their purpose
- The sysent CSV agrees with the syscall numbers used

Offline and read-only: no console is contacted.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probes" / "phase15_native_sysent" / "59b_thr_family_survey.lua"
SYSENT_CSV = ROOT / "docs" / "sysent-names-13.60.csv"
PROBE_INDEX = ROOT / "docs" / "PROBE_INDEX.md"


def probe_text():
    return PROBE.read_text()


class SyscallNumberTests(unittest.TestCase):
    """Every make_syscall(N) in the probe matches the sysent CSV."""

    @classmethod
    def setUpClass(cls):
        cls.src = probe_text()
        cls.sysent = {}
        if SYSENT_CSV.exists():
            for line in SYSENT_CSV.read_text().splitlines():
                parts = line.strip().split(",")
                if len(parts) >= 2 and parts[0].isdigit():
                    cls.sysent[int(parts[0])] = parts[1]

    def _assert_syscall_named(self, num, expected_name_fragment):
        """Assert make_syscall(num) appears and the sysent name matches."""
        self.assertIn(f"make_syscall({num})", self.src,
                      f"make_syscall({num}) not found in probe")
        if num in self.sysent:
            self.assertIn(expected_name_fragment, self.sysent[num],
                          f"sysent[{num}]={self.sysent[num]} doesn't match {expected_name_fragment}")

    def test_thr_self_is_432(self):
        self._assert_syscall_named(432, "thr_self")

    def test_thr_kill_is_433(self):
        self._assert_syscall_named(433, "thr_kill")

    def test_thr_suspend_is_442(self):
        self._assert_syscall_named(442, "thr_suspend")

    def test_thr_wake_is_443(self):
        self._assert_syscall_named(443, "thr_wake")

    def test_thr_set_name_is_464(self):
        self._assert_syscall_named(464, "thr_set_name")

    def test_thr_kill2_is_481(self):
        self._assert_syscall_named(481, "thr_kill2")

    def test_thr_get_name_is_616(self):
        self._assert_syscall_named(616, "thr_get_name")

    def test_thr_suspend_ucontext_is_632(self):
        self._assert_syscall_named(632, "thr_suspend_ucontext")

    def test_thr_resume_ucontext_is_633(self):
        self._assert_syscall_named(633, "thr_resume_ucontext")

    def test_thr_get_ucontext_is_634(self):
        self._assert_syscall_named(634, "thr_get_ucontext")

    def test_thr_set_ucontext_is_635(self):
        self._assert_syscall_named(635, "thr_set_ucontext")

    def test_getpid_canary_is_20(self):
        self.assertIn("make_syscall(20)", self.src)


class SafetyTests(unittest.TestCase):
    """The probe must never call dangerous syscalls."""

    @classmethod
    def setUpClass(cls):
        cls.src = probe_text()

    def test_thr_exit_431_never_called(self):
        """thr_exit terminates the thread — must never be invoked."""
        self.assertNotIn("make_syscall(431)", self.src,
                         "DANGER: probe creates a handle for thr_exit(431)")

    def test_thr_create_430_never_called(self):
        """thr_create is deferred to probe 58e with its decoded context."""
        self.assertNotIn("make_syscall(430)", self.src,
                         "DANGER: probe creates a handle for thr_create(430) — use 58e")

    def test_thr_new_455_never_called(self):
        """thr_new is already confirmed blocked; no need to retest."""
        self.assertNotIn("make_syscall(455)", self.src,
                         "probe creates a handle for thr_new(455) — already blocked")

    def test_thr_kill_uses_signal_zero_only(self):
        """thr_kill must only send signal 0 (null signal = permission check)."""
        for m in re.finditer(r'sc_thr_kill\(([^)]+)\)', self.src):
            args = m.group(1)
            # The last uint64() argument is the signal number
            sigs = re.findall(r'uint64\((\d+)\)', args)
            if sigs:
                last_sig = int(sigs[-1])
                self.assertEqual(last_sig, 0,
                                 f"thr_kill called with signal {last_sig} != 0")

    def test_thr_kill2_uses_signal_zero_only(self):
        """thr_kill2 must only send signal 0."""
        for m in re.finditer(r'sc_thr_kill2\(([^)]+)\)', self.src):
            args = m.group(1)
            sigs = re.findall(r'uint64\((\d+)\)', args)
            if len(sigs) >= 3:
                sig = int(sigs[2])
                self.assertEqual(sig, 0,
                                 f"thr_kill2 called with signal {sig} != 0")

    def test_thr_suspend_never_uses_null_timeout(self):
        """thr_suspend(NULL) would block forever. Must always pass a buffer."""
        for m in re.finditer(r'sc_thr_suspend\(([^)]+)\)', self.src):
            args = m.group(1)
            self.assertNotIn("uint64(0)", args,
                             "thr_suspend called with NULL/0 timeout — would block forever")


class MarkerTests(unittest.TestCase):
    """Every section has [BEFORE] and [RETURNED] markers."""

    @classmethod
    def setUpClass(cls):
        cls.src = probe_text()

    def test_every_section_has_before_marker(self):
        sections = re.findall(r'SECTION ([A-K])', self.src)
        unique = sorted(set(sections))
        for s in unique:
            self.assertIn(f"[BEFORE] {s}", self.src,
                          f"Section {s} missing [BEFORE] marker")

    def test_every_section_has_returned_marker(self):
        sections = re.findall(r'SECTION ([A-K])', self.src)
        unique = sorted(set(sections))
        for s in unique:
            self.assertIn(f"[RETURNED] {s}", self.src,
                          f"Section {s} missing [RETURNED] marker")

    def test_sections_a_through_k_exist(self):
        for s in "ABCDEFGHIJK":
            self.assertIn(f"SECTION {s}:", self.src,
                          f"Section {s} not found in probe")


class BufferTests(unittest.TestCase):
    """Buffer allocations are adequate."""

    @classmethod
    def setUpClass(cls):
        cls.src = probe_text()

    def test_tid_buffer_at_least_8_bytes(self):
        m = re.search(r'tid_buf\s*=\s*memory\.alloc\((\d+)\)', self.src)
        self.assertIsNotNone(m, "tid_buf allocation not found")
        self.assertGreaterEqual(int(m.group(1)), 8)

    def test_name_buffer_at_least_20_bytes(self):
        """MAXCOMLEN is 19 + NUL = 20 minimum."""
        m = re.search(r'name_buf\s*=\s*memory\.alloc\((\d+)\)', self.src)
        self.assertIsNotNone(m, "name_buf allocation not found")
        self.assertGreaterEqual(int(m.group(1)), 20)

    def test_ctx_buffer_at_least_0x500_bytes(self):
        """thr_create copies 0x500 bytes; ucontext should be at least that."""
        m = re.search(r'ctx_buf\s*=\s*memory\.alloc\((0x[0-9a-fA-F]+|\d+)\)', self.src)
        self.assertIsNotNone(m, "ctx_buf allocation not found")
        size = int(m.group(1), 0)
        self.assertGreaterEqual(size, 0x500)


class ProbeIndexTests(unittest.TestCase):
    """PROBE_INDEX.md has an entry for 59b."""

    def test_probe_index_contains_59b(self):
        if not PROBE_INDEX.exists():
            self.skipTest("PROBE_INDEX.md not found")
        text = PROBE_INDEX.read_text()
        self.assertIn("59b", text)
        self.assertIn("thr_family_survey", text)


class CrashClassTests(unittest.TestCase):
    """Probe header conventions."""

    @classmethod
    def setUpClass(cls):
        cls.src = probe_text()

    def test_crash_class_is_moderate(self):
        self.assertIn("CRASH_CLASS: MODERATE", self.src)

    def test_probe_number_in_header(self):
        self.assertIn("PROBE 59b", self.src)

    def test_not_run_disclaimer(self):
        self.assertIn("PREPARED", self.src)
        self.assertIn("NOT RUN", self.src)


if __name__ == "__main__":
    unittest.main()
