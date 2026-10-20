"""Tests for tools/bounds_fuzz.py that need no console."""

import unittest

from tools import bounds_fuzz as bf


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
            "BFUZZ SCAN 576 a1,size,buf 256 inside=3 outside=2 first=4096",
            "BFUZZ DONE 576 a1,size,buf 256",
        ])
        status, detail = bf.parse_response(out, 576, "a1,size,buf", 256)
        self.assertEqual(status, bf.RETURNED)
        self.assertEqual(detail["inside"], 3)
        self.assertEqual(detail["outside"], 2)
        self.assertEqual(detail["first"], 4096)
        self.assertIn("num=-1", detail["ret"])

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
    def make(self, status, inside, outside, size):
        return {"status": status, "inside": inside, "outside": outside, "size": size}

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
        def transport(_src):
            return None

        records = bf.fuzz([577, 578], ["a1,size,buf"], [1], [0], transport,
                           delay=0, sleep=lambda _s: None, wait=None)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["aborted"])


if __name__ == "__main__":
    unittest.main()
