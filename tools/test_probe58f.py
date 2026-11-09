#!/usr/bin/env python3
"""Stub-loader tests for probes/phase2_kernel_objects/58f_kevent_timeout_matrix.lua.

The probe's job is to fill the missing cell of a 2x2 (split/combined x
zero/nonzero timeout) with fresh state per cell. The tests here check that it
actually does that: exact syscall sequence, exact argument shapes, exact
timeout struct values, one kqueue and one pipe per cell, and a recovery poll on
the 100ms combined kqueue. A second stub models a loader where a nonzero
timeout returns -1, so the probe's own reading lines are exercised too.

Offline and read-only: no console is contacted.
"""

import unittest
from pathlib import Path

import lupa

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probes" / "phase2_kernel_objects" / "58f_kevent_timeout_matrix.lua"

SETUP_LUA = r"""
syscall = {
    pipe = { syscall_no = 0 },
    resolve = function(_) return true end,
    sc_kqueue    = function() return __kqueue() end,
    sc_pipe2     = function(fds, flags) return __pipe2(fds, flags) end,
    sc_socketpair = function(a, b, c, sp) return __socketpair(a, b, c, sp) end,
    sc_write     = function(fd, buf, n) return __write(fd, buf, n) end,
    sc_kevent    = function(kq, ch, nch, ev, nev, to) return __kevent(kq, ch, nch, ev, nev, to) end,
    sc_close     = function(fd) return __close(fd) end,
}
uint64 = function(x) return x end
memory = {
    alloc = function(n) return __alloc(n) end,
    read_dword = function(a) return __read_dword(a) end,
    read_word = function(a) return __read_word(a) end,
    read_qword = function(a) return __read_qword(a) end,
    write_dword = function(a, v) return __write_dword(a, v) end,
    write_word = function(a, v) return __write_word(a, v) end,
    write_qword = function(a, v) return __write_qword(a, v) end,
}
print = function(...)
    local parts = {}
    for i = 1, select('#', ...) do parts[i] = tostring(select(i, ...)) end
    __capture(table.concat(parts, '\t'))
end
"""

KEVENT_SIZE = 32


class Loader:
    """A minimal kqueue/pipe loader. ``fail_nonzero_timeout`` models probe 30c."""

    def __init__(self, fail_nonzero_timeout=False):
        self.fail_nonzero_timeout = fail_nonzero_timeout
        self.mem = {}
        self.calls = []
        self.next_fd = 10
        self.next_addr = 0x40000000
        self.data = set()          # pipe read ends that hold a byte
        self.registered = {}       # kqueue fd -> registered read ends
        self.kqueues = []
        self.pipes = []

    # memory ------------------------------------------------------------
    def alloc(self, n):
        addr = self.next_addr
        self.next_addr += 0x1000
        return addr

    def read(self, addr, size):
        addr = int(addr)
        value = 0
        for i in range(size):
            value |= self.mem.get(addr + i, 0) << (8 * i)
        return value

    def write(self, addr, value, size):
        addr = int(addr)
        value = int(value) & ((1 << (8 * size)) - 1)
        for i in range(size):
            self.mem[addr + i] = (value >> (8 * i)) & 0xFF

    # syscalls ----------------------------------------------------------
    def kqueue(self):
        fd = self.next_fd
        self.next_fd += 1
        self.kqueues.append(fd)
        self.calls.append(("kqueue", fd))
        return fd

    def pipe2(self, fds, flags):
        rfd, wfd = self.next_fd, self.next_fd + 1
        self.next_fd += 2
        self.write(fds, rfd, 4)
        self.write(fds + 4, wfd, 4)
        self.pipes.append((rfd, wfd))
        self.calls.append(("pipe2", rfd, wfd))
        return 0

    def socketpair(self, a, b, c, sp):
        self.calls.append(("socketpair",))
        return -1

    def write_fd(self, fd, buf, n):
        self.calls.append(("write", int(fd), int(n)))
        for pair in self.pipes:
            if pair[1] == int(fd):
                self.data.add(pair[0])
        return int(n)

    def kevent(self, kq, ch, nch, ev, nev, to):
        kq, nch, nev = int(kq), int(nch), int(nev)
        timeout = (self.read(to, 8), self.read(to + 8, 8))
        change = None
        if nch:
            change = (self.read(ch, 8), self.read(ch + 8, 2),
                      self.read(ch + 10, 2))
        self.calls.append(("kevent", kq, nch, nev, timeout, change))

        if timeout[1] != 0 and self.fail_nonzero_timeout:
            return -1

        registered = self.registered.setdefault(kq, set())
        if nch:
            ident = change[0]
            if change[1] == 0xFFFF and change[2] & 0x0001:
                registered.add(ident)  # EV_ADD registers the fd

        if nev == 0:
            return 0

        for pair in self.pipes:
            if pair[0] in registered and pair[0] in self.data:
                self.write(ev, pair[0], 8)      # ident
                self.write(ev + 8, 0xFFFF, 2)   # filter
                self.write(ev + 10, 0x0010, 2)  # flags
                self.write(ev + 16, 1, 8)       # data
                return 1
        return 0

    def close(self, fd):
        self.calls.append(("close", int(fd)))
        return 0


def run_probe(fail_nonzero_timeout=False):
    captured = []
    runtime = lupa.LuaRuntime(unpack_returned_tuples=True)
    globals_ = runtime.globals()
    loader = Loader(fail_nonzero_timeout)

    globals_["__capture"] = captured.append
    globals_["__alloc"] = loader.alloc
    globals_["__kqueue"] = loader.kqueue
    globals_["__pipe2"] = loader.pipe2
    globals_["__socketpair"] = loader.socketpair
    globals_["__write"] = loader.write_fd
    globals_["__kevent"] = loader.kevent
    globals_["__close"] = loader.close
    globals_["__read_dword"] = lambda a: loader.read(a, 4)
    globals_["__read_word"] = lambda a: loader.read(a, 2)
    globals_["__read_qword"] = lambda a: loader.read(a, 8)
    globals_["__write_dword"] = lambda a, v: loader.write(a, v, 4)
    globals_["__write_word"] = lambda a, v: loader.write(a, v, 2)
    globals_["__write_qword"] = lambda a, v: loader.write(a, v, 8)

    runtime.execute(SETUP_LUA)
    runtime.execute(PROBE.read_text(encoding="utf-8"))
    return loader, "\n".join(captured) + "\n"


class ProbeSourceTests(unittest.TestCase):
    def test_probe_records_live_result(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("Live-tested 2026-10-19", source)
        self.assertIn("CRASH_CLASS: LOW", source)

    def test_probe_uses_lua_51_safe_constructs(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertNotIn("goto", source)
        self.assertIn("pcall(function()", source)
        self.assertIn("[BEFORE]", source)
        self.assertIn("[RETURNED]", source)

    def test_probe_names_the_untested_cell(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("split, 100ms timeout", source)
        self.assertIn("never run", source)


class KeventCallShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loader, cls.output = run_probe(fail_nonzero_timeout=False)
        cls.kevents = [c for c in cls.loader.calls if c[0] == "kevent"]

    def test_every_cell_gets_its_own_kqueue_and_pipe(self):
        kqueues = [c[1] for c in self.loader.calls if c[0] == "kqueue"]
        self.assertEqual(len(kqueues), 4)          # A, B, C, D
        self.assertEqual(len(set(kqueues)), 4)
        pipes = [c for c in self.loader.calls if c[0] == "pipe2"]
        self.assertEqual(len(pipes), 4)
        self.assertEqual(len({(p[1], p[2]) for p in pipes}), 4)

    def test_cell_a_is_split_with_zero_timeout(self):
        a1, a2 = self.kevents[0], self.kevents[1]
        self.assertEqual((a1[2], a1[3], a1[4]), (1, 0, (0, 0)))
        self.assertEqual((a2[2], a2[3], a2[4]), (0, 1, (0, 0)))
        self.assertEqual(a1[1], a2[1])             # same kqueue

    def test_cell_b_polls_with_a_100ms_timeout(self):
        b1, b2, b3 = self.kevents[2], self.kevents[3], self.kevents[4]
        self.assertEqual((b1[2], b1[3], b1[4]), (1, 0, (0, 0)))
        self.assertEqual((b2[2], b2[3], b2[4]), (0, 1, (0, 100_000_000)))
        self.assertEqual((b3[2], b3[3], b3[4]), (0, 1, (0, 0)))  # recovery

    def test_cell_c_and_d_are_combined(self):
        c1 = self.kevents[5]
        d1 = self.kevents[6]
        self.assertEqual((c1[2], c1[3], c1[4]), (1, 1, (0, 0)))
        self.assertEqual((d1[2], d1[3], d1[4]), (1, 1, (0, 100_000_000)))

    def test_cell_e_polls_d_kqueue_after_d(self):
        d1, e1 = self.kevents[6], self.kevents[7]
        self.assertEqual(e1[1], d1[1])
        self.assertEqual((e1[2], e1[3], e1[4]), (0, 1, (0, 0)))

    def test_every_change_is_ev_add_on_evfilt_read(self):
        for call in self.kevents:
            if call[2]:
                ident, filt, flags = call[5]
                self.assertEqual(filt, 0xFFFF)
                self.assertEqual(flags & 0x0001, 0x0001)

    def test_every_call_is_preceded_by_a_marker(self):
        for tag in ("A1", "A2", "B1", "B2", "B3", "C1", "D1", "E1"):
            self.assertIn(f"[BEFORE] {tag} ", self.output)


class ProbeReadingTests(unittest.TestCase):
    def test_working_loader_shows_all_cells_returning(self):
        _, output = run_probe(fail_nonzero_timeout=False)
        for tag in ("A1", "A2", "B1", "B2", "B3", "C1", "D1", "E1"):
            self.assertIn(f"[RETURNED] {tag} rv=", output)
        self.assertNotIn("PCALL-FAIL", output)
        self.assertIn("[RETURNED] B2 rv=1", output)
        self.assertIn("[RETURNED] D1 rv=1", output)

    def test_nonzero_timeout_failure_hits_only_the_timeout_cells(self):
        # 30c's shape: combined add+poll with a live timeout returns -1.
        _, output = run_probe(fail_nonzero_timeout=True)
        self.assertIn("[RETURNED] A2 rv=1", output)
        self.assertIn("[RETURNED] B2 rv=-1", output)
        self.assertIn("[RETURNED] C1 rv=1", output)
        self.assertIn("[RETURNED] D1 rv=-1", output)
        # The recovery poll still works: the kqueue was not left unusable.
        self.assertIn("[RETURNED] E1 rv=0", output)

    def test_probe_closes_what_it_opens(self):
        loader, _ = run_probe(fail_nonzero_timeout=False)
        closed = {c[1] for c in loader.calls if c[0] == "close"}
        for kq in loader.kqueues:
            self.assertIn(kq, closed)
        for rfd, wfd in loader.pipes:
            self.assertIn(rfd, closed)
            self.assertIn(wfd, closed)

    def test_completion_marker_is_last(self):
        _, output = run_probe(fail_nonzero_timeout=False)
        self.assertTrue(output.rstrip().endswith(
            "E1 rv=0 means no registration reached that kqueue, "
            "so D1 failed earlier."))


if __name__ == "__main__":
    unittest.main()
