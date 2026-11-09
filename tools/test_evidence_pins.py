#!/usr/bin/env python3
"""Regression tests for the kevent and 430 evidence corrections.

Each case pins a committed artifact to the claim made about it in
``docs/KEVENT_TIMEOUT_VARIABLE.md`` and ``docs/SYSCALL_430_MISLABEL.md``:
the exact probe source lines that build each kevent call, the exact capture
lines that record each return, and the exact handler bytes that name 430.
If a probe, capture, or dump is edited, the affected case names the stale
citation instead of silently passing.

Run with::

    python -m unittest discover -s tools -p "test_evidence_pins.py" -v

Read-only: no console contact, no writes outside test tempdirs.
"""

import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def lines(path):
    """File lines (1-based access via index-1), tolerant of encodings."""
    raw = (ROOT / path).read_bytes()
    for codec in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(codec).splitlines()
        except UnicodeDecodeError:
            continue
    raise AssertionError(f"undecodable file: {path}")


class KevenCallShapeTests(unittest.TestCase):
    P20 = "probes/phase2_kernel_objects/20_kqueue_stress.lua"
    P21 = "probes/phase2_kernel_objects/21_kqueue_deep.lua"
    P30C = "probes/phase4_ipc_network/30c_fcntl_bypass.lua"

    def test_probe20_splits_register_and_poll(self):
        src = lines(self.P20)
        self.assertIn("syscall.sc_kevent(kq, changelist, #pipes, eventlist, 0, timeout)",
                      src[137])
        self.assertIn("syscall.sc_kevent(kq, changelist, 0, eventlist, 10, timeout)",
                      src[157])

    def test_probe20_timeout_is_zero(self):
        src = lines(self.P20)
        self.assertIn("memory.write_qword(timeout, 0)", src[133])
        self.assertIn("memory.write_qword(timeout + 8, 0)", src[134])

    def test_probe21_combines_with_zero_timeout(self):
        src = lines(self.P21)
        self.assertIn("syscall.sc_kevent(kq, batch, 10, events, 10, timeout)",
                      src[75])
        self.assertEqual(src[40].strip(), "memory.write_qword(timeout, 0)")
        self.assertEqual(src[41].strip(), "memory.write_qword(timeout + 8, 0)")

    def test_probe30c_combines_with_100ms_timeout(self):
        src = lines(self.P30C)
        self.assertIn("syscall.sc_kevent(kq_fd, kev, 1, out_kev, 1, timeout)",
                      src[261])
        self.assertIn("100000000", src[255])


class KevenCaptureTests(unittest.TestCase):
    C20 = "results/phase2_kernel_objects/20_kqueue_stress_20261015_193513.txt"
    C21 = "results/phase2_kernel_objects/21_kqueue_deep_20261015_193640.txt"
    C30C = "results/phase4_ipc_network/30c_fcntl_bypass_20261015_201500.txt"

    def test_probe20_registered_and_delivered(self):
        cap = lines(self.C20)
        self.assertIn("kevent register 10 READ filters: rv=0", cap[13])
        self.assertIn("kevent poll: 3 events", cap[16])
        self.assertIn("event[0]: fd=23", cap[17])

    def test_probe21_registered_at_scale(self):
        cap = lines(self.C21)
        joined = "\n".join(cap)
        self.assertIn("signals registered: 31/31", joined)
        self.assertIn("user events registered: 20/20", joined)
        self.assertIn("max knotes registered: 2000", joined)
        self.assertIn("live PIDs found: 50", joined)

    def test_probe30c_returned_minus_one(self):
        cap = lines(self.C30C)
        self.assertIn("kevent(add+poll): rv=-1", cap[47])


class Syscall430Tests(unittest.TestCase):
    PROBE = "probes/phase14_final_push/54b_jail_bypass.lua"
    CAPTURE = "results/54b_jail_bypass_20261018_090446.txt"
    P27 = "probes/phase4_ipc_network/27_thread_and_fd.lua"
    INDEX = "docs/dumps_13.60/sysent_index.json"
    KTEXT = "docs/dumps_13.60/kernel_text.bin"

    def test_phase2_labels_430_thr_new(self):
        src = lines(self.PROBE)
        self.assertIn('{430, "thr_new"}', src[135])

    def test_phase2_passes_null_arg0(self):
        src = lines(self.PROBE)
        joined = "\n".join(src[140:160])
        self.assertIn("uint64(0), uint64(outbuf), uint64(64)", joined)

    def test_capture_records_minus_one(self):
        cap = lines(self.CAPTURE)
        self.assertIn("430 thr_new", cap[27])
        self.assertIn("ret=-1", cap[27])

    def test_repo_pins_thr_new_at_455(self):
        src = lines(self.P27)
        self.assertIn("sc_thr_new = 455", src[18])

    def test_slots_differ(self):
        tab = json.loads((ROOT / self.INDEX).read_text())
        by_num = {e["num"]: e for e in tab["entries"]}
        self.assertEqual(by_num[430]["sy_call_off"], "0x265c10")
        self.assertEqual(by_num[455]["sy_call_off"], "0x265c50")
        self.assertNotEqual(by_num[430]["sy_call_off"],
                            by_num[455]["sy_call_off"])

    def test_bodies_differ(self):
        kt = (ROOT / self.KTEXT).read_bytes()
        targets = {}
        for num, slot in ((430, 0x265C10), (455, 0x265C50)):
            self.assertEqual(kt[slot], 0xE9, f"slot {num:#x} is not E9")
            rel = struct.unpack("<i", kt[slot + 1:slot + 5])[0]
            targets[num] = slot + 5 + rel
        self.assertEqual(targets[430], 0x437CF0)
        self.assertEqual(targets[455], 0x437DE0)

    def test_430_opens_with_large_copyin(self):
        kt = (ROOT / self.KTEXT).read_bytes()
        # mov edx,0x500 (BA 00 05 00 00) then copyin call E8 within body head.
        head = kt[0x437CF0:0x437CF0 + 0x60]
        self.assertIn(b"\xba\x00\x05\x00\x00", head)

    def test_455_opens_with_size_gate(self):
        kt = (ROOT / self.KTEXT).read_bytes()
        # cmp dword [rsi+8],0x68 (83 7E 08 68) in body head.
        head = kt[0x437DE0:0x437DE0 + 0x40]
        self.assertIn(b"\x83\x7e\x08\x68", head)


if __name__ == "__main__":
    unittest.main()
