#!/usr/bin/env python3
"""Regression tests for the evidence-context gate in tools/deep_result_scanner.py.

Kernel-band values printed as probe inputs must never become pointer
candidates; only console readback may. Each case runs the real scan_file
over a temporary result text file, and candidates are compared as integers
so an assertion cannot be satisfied by an echoed source line.

Input shapes come from committed captures and their probe sources:
results/phase2_kernel_objects/13_nwake_oracle_20261015_190841.txt:39
    ("0xfffff80000000000: 68318 ns") — DMAP list in
    probes/phase2_kernel_objects/13_nwake_oracle.lua:190-195.
results/phase3_signals_codexec/25b_sigalt_ign_20261015_194744.txt:15
    ("verify: sp=0xfffff80010000000 flags=0x0") — read-back of the dword
    pair the probe wrote at probes/phase3_signals_codexec/25b_sigalt_ign.lua:102-103.
results/phase3_signals_codexec/26d_find_ret_20261015_195332.txt:9
    ("offset to code: 0xfffffffd42945a14 (-11767883244)") — one offset
    formatted two ways at probes/phase3_signals_codexec/26d_find_ret.lua:58.
results/phase14_final_push/56i9_kaslr_bruteforce_20261018_121926.txt:16
    ("0xFFFF800000000000 avg=0.0: 0,0,0,0,0") — literal list in
    probes/phase14_final_push/56i9_kaslr_bruteforce.lua:150-157.

Readback shapes come from committed read sites:
results/phase14_final_push/56i8_eboot_data_kptr_20261018_121608.txt:12-16
    ("[0] 0xFFFF8270_00014E08") — one live safe_rq value per index at
    probes/phase14_final_push/56i8_eboot_data_kptr.lua:143-144.
"""

import os
import tempfile
import unittest

import deep_result_scanner


# Synthetic kernel-band value; not captured PS5 data.
KERNEL_CANDIDATE = 0xFFFF800012345678

# Probe-input echoes: zero kernel_ptrs expected.
INPUT_CASES = (
    ("timing row echoes the probe's own DMAP list",
     "  0xfffff80000000000: 68318 ns"),
    ("verify line reads back the probe's own altstack constant",
     "  verify: sp=0xfffff80010000000 flags=0x0"),
    ("arithmetic label prints an unsigned negative offset",
     "  offset to code: 0xfffffffd42945a14 (-11767883244)"),
    ("timing row echoes a literal kernel-base list",
     "  0xFFFF800000000000 avg=0.0: 0,0,0,0,0"),
)

# Console-readback shapes: the payload must remain a candidate.
READBACK_CASES = (
    ("hexdump row",
     "  +0x03E38: 0xFFFF8000_12345678 KPTR!"),
    ("buffer view",
     "  buf[0]=0xFFFF800012345678"),
    ("indexed read row prints one live qword per index",
     "  [0] 0xFFFF8000_12345678"),
)


class EvidenceGateTest(unittest.TestCase):
    def _scan(self, text):
        handle, path = tempfile.mkstemp(
            prefix="deep-scan-gate-", suffix=".txt")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as handle_file:
                handle_file.write(text + "\n")
            findings, err = deep_result_scanner.scan_file(path)
        finally:
            os.unlink(path)
        self.assertIsNone(err)
        return findings

    def test_probe_inputs_are_not_candidates(self):
        for name, text in INPUT_CASES:
            with self.subTest(name):
                findings = self._scan(text)
                self.assertEqual(findings["kernel_ptrs"], [])

    def test_console_readback_stays_a_candidate(self):
        for name, text in READBACK_CASES:
            with self.subTest(name):
                findings = self._scan(text)
                values = [val for _, val, _ in findings["kernel_ptrs"]]
                self.assertEqual(values, [KERNEL_CANDIDATE])


if __name__ == "__main__":
    unittest.main()
