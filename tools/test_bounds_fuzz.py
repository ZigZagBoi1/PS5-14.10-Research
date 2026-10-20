"""Tests for tools/bounds_fuzz.py that need no console."""

import struct
import unittest

from tools import bounds_fuzz as bf

try:
    from lupa.lua51 import LuaRuntime
except ImportError:  # the probe sandbox is optional, the driver is not
    LuaRuntime = None


def ok_output(num, layout, size):
    return "\n".join([
        bf.BEGIN.format(num=num, layout=layout, size=size),
        bf.BEFORE.format(num=num, layout=layout, size=size),
        bf.RESULT.format(num=num, layout=layout, size=size) + "-1 (num=-1)",
        bf.SCAN.format(num=num, layout=layout, size=size) + "inside=0 outside=0 first=-1",
        bf.DONE.format(num=num, layout=layout, size=size),
    ])


class BuildProbeTest(unittest.TestCase):
    def test_size_lands_in_the_declared_argument(self):
        src = bf.build_probe(576, "a1,size,buf", 0x40, a1=0)
        self.assertIn("make_syscall(576)(uint64(0), uint64(64), BUF", src)
        self.assertIn("BFUZZ BEGIN 576 a1,size,buf 64", src)

    def test_buffer_first_layout(self):
        src = bf.build_probe(600, "size,a1,buf", 0x10)
        self.assertIn("make_syscall(600)(uint64(16), uint64(0), BUF", src)

    def test_every_layout_substitutes(self):
        for name in bf.LAYOUTS:
            src = bf.build_probe(590, name, 1)
            self.assertNotIn("{size}", src)
            self.assertNotIn("{a1}", src)
            self.assertNotIn("{begin}", src)


class ParseResponseTest(unittest.TestCase):
    def test_full_response(self):
        out = "\n".join([
            "BFUZZ BEGIN 576 a1,size,buf 256",
            "BFUZZ BEFORE 576 a1,size,buf 256",
            "BFUZZ RESULT 576 a1,size,buf 256 0xffffffffffffffff (num=-1)",
            "BFUZZ SCAN 576 a1,size,buf 256 inside=3 outside=2 first=4096 kp=1 sample=8192:305419896",
            "BFUZZ DONE 576 a1,size,buf 256",
        ])
        status, detail = bf.parse_response(out, 576, "a1,size,buf", 256)
        self.assertEqual(status, bf.RETURNED)
        self.assertEqual(detail["inside"], 3)
        self.assertEqual(detail["outside"], 2)
        self.assertEqual(detail["first"], 4096)
        self.assertIn("num=-1", detail["ret"])
        self.assertEqual(detail["kp"], 1)
        self.assertEqual(detail["sample"], "8192:305419896")

    def test_died_inside_the_call(self):
        out = ("BFUZZ BEGIN 576 a1,size,buf 256\n"
               "BFUZZ BEFORE 576 a1,size,buf 256\n")
        status, _ = bf.parse_response(out, 576, "a1,size,buf", 256)
        self.assertEqual(status, bf.KILLED_IN_CALL)

    def test_never_reached_the_call(self):
        self.assertEqual(bf.parse_response("", 576, "a1,size,buf", 256)[0], bf.NO_OUTPUT)
        self.assertEqual(bf.parse_response(None, 576, "a1,size,buf", 256)[0],
                         bf.CONNECT_FAILED)


class VerdictTest(unittest.TestCase):
    def make(self, status, inside, outside, size, kp=0):
        return {"status": status, "inside": inside, "outside": outside,
                "size": size, "kp": kp}

    def test_kernel_pointer_wins_over_overflow(self):
        self.assertEqual(bf.verdict(self.make(bf.RETURNED, 8, 4, 0x100, kp=2)),
                         "KERNEL-POINTER")

    def test_overflow(self):
        self.assertEqual(bf.verdict(self.make(bf.RETURNED, 64, 1, 0x100)), "OVERFLOW")

    def test_write_at_zero_size(self):
        self.assertEqual(bf.verdict(self.make(bf.RETURNED, 4, 0, 0)),
                         "WROTE_AT_ZERO_SIZE")

    def test_quiet(self):
        self.assertEqual(bf.verdict(self.make(bf.RETURNED, 64, 0, 0x100)), "")
        self.assertEqual(bf.verdict(self.make(bf.KILLED_IN_CALL, None, None, 0x100)), "")


class FuzzLoopTest(unittest.TestCase):
    def test_waits_for_the_loader_after_a_kill(self):
        calls = []

        def transport(src):
            calls.append(src)
            if "make_syscall(577)" in src:
                return ("BFUZZ BEGIN 577 a1,size,buf 1\n"
                        "BFUZZ BEFORE 577 a1,size,buf 1\n")
            if len(calls) == 2:
                return None
            return ok_output(578, "a1,size,buf", 1)

        waits = []

        def wait():
            waits.append(True)
            return True

        records = bf.fuzz([577, 578], ["a1,size,buf"], [1], [0], transport,
                           delay=0, sleep=lambda _s: None, wait=wait)
        self.assertEqual([r["status"] for r in records],
                         [bf.KILLED_IN_CALL, bf.RETURNED])
        self.assertEqual([a["status"] for a in records[1]["attempts"]],
                         [bf.CONNECT_FAILED, bf.RETURNED])
        self.assertEqual(len(waits), 1)

    def test_no_wait_aborts(self):
        records = bf.fuzz([577, 578], ["a1,size,buf"], [1], [0],
                          lambda _src: None, delay=0, sleep=lambda _s: None, wait=None)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["aborted"])


@unittest.skipUnless(LuaRuntime, "lupa not installed")
class ProbeSandboxTest(unittest.TestCase):
    """Runs the generated probe against fake memory so the scan maths is exercised."""

    def run_probe(self, written_dwords, size=16):
        runtime = LuaRuntime(unpack_returned_tuples=True)
        mem = bytearray(0x100000)
        state = {"next": 0x1000}
        lines = []

        def alloc(n):
            base = state["next"]
            state["next"] += (n + 0xFFF) & ~0xFFF
            return base

        def read_dword(addr):
            return struct.unpack_from("<I", mem, addr)[0]

        def write_dword(addr, value):
            struct.pack_into("<I", mem, addr & 0xFFFFFFFF, value & 0xFFFFFFFF)

        def fake_call(*args):
            buf = args[2]
            for index in range(written_dwords):
                write_dword(buf + index * 4, 0x11111111)
            return -1

        globals_ = runtime.globals()
        globals_.memory = runtime.table_from(
            {"alloc": alloc, "read_dword": read_dword, "write_dword": write_dword})
        globals_.uint64 = int
        globals_.print = lambda *args: lines.append(" ".join(str(a) for a in args))
        runtime.execute("syscall = { pipe = {} }")
        globals_.fake_call = fake_call
        runtime.execute("setmetatable(syscall.pipe, "
                        "{ __call = function(self, ...) return fake_call(...) end })")
        runtime.execute(bf.build_probe(576, "a1,size,buf", size))
        return [line for line in lines if line.startswith("BFUZZ SCAN")][0]

    def test_write_inside_the_declared_size(self):
        self.assertIn("inside=4 outside=0", self.run_probe(4, size=16))

    def test_write_past_the_declared_size(self):
        line = self.run_probe(8, size=16)
        self.assertIn("inside=4 outside=4", line)
        self.assertNotIn("first=-1", line)

    def test_no_write(self):
        self.assertIn("inside=0 outside=0 first=-1", self.run_probe(0, size=16))


if __name__ == "__main__":
    unittest.main()
