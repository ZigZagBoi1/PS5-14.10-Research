#!/usr/bin/env python3
"""Rank handler bodies whose copyout of a stack record looks partial.

For every Sony handler (532-676) this finds `copyout(lea rdi,[rbp-X], user, N)`
with a constant N, then sums the byte widths of the direct stores into that
[rbp-X .. rbp-X+N) window that appear before the call. A copyout that covers
far fewer bytes than N is a candidate for leaking uninitialised kernel stack.

This is a coverage heuristic, not a proof: calls that fill the buffer (memset,
memcpy, structure copies) are not counted, so a low ratio means "read this
one", not "this leaks".

Usage: python tools/stack_leak_scan.py [--dump docs/dumps_13.60] [--min 0x20]
"""
import argparse
import os
import struct
import sys

import capstone

BASE = 0xffffffff8a9c0000
COPYOUT = 0x8ac191d0
STORE_W = {"byte": 1, "word": 2, "dword": 4, "qword": 8}


def body_of(kt, se, n):
    narg, _flags, call = struct.unpack_from("<IIQ", se, n * 48)
    addr = call
    for _ in range(4):
        off = addr - BASE
        if off < 0 or off + 5 > len(kt) or kt[off] == 0xCC:
            return None, narg
        if kt[off] != 0xE9:
            return addr, narg
        addr = addr + 5 + struct.unpack_from("<i", kt, off + 1)[0]
    return None, narg


def scan(kt, md, narg, body, min_size):
    off = body - BASE
    src, size, hits = None, None, []
    covered = {}
    for ins in md.disasm(kt[off:off + 0x1800], body):
        m, o = ins.mnemonic, ins.op_str
        if m == "lea" and o.startswith("rdi, [rbp - "):
            src = int(o.split("[rbp - ")[1].split("]")[0], 16)
        if m in ("mov", "lea") and o.startswith("rdx, "):
            v = o.split(", ")[1]
            size = int(v, 0) if v.startswith("0x") or v.isdigit() else None
        if m == "mov" and " ptr [rbp - " in o and src is not None:
            head, _, val = o.partition(", ")
            for kind, w in STORE_W.items():
                if kind + " ptr [rbp - " in head:
                    try:
                        d = int(head.split("[rbp - ")[1].split("]")[0], 16)
                    except ValueError:
                        break
                    lo, hi = src - d, src - d + w
                    for b in range(lo, hi):
                        if 0 <= b:
                            covered[b] = True
                    break
        if m == "call" and o == "0x%x" % COPYOUT:
            if src is not None and size and size >= min_size:
                got = sum(1 for b in range(size) if covered.get(b))
                hits.append((ins.address - BASE, src, size, got))
            src, size, covered = None, None, {}
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", default="docs/dumps_13.60")
    ap.add_argument("--min", type=lambda s: int(s, 0), default=0x20)
    args = ap.parse_args()
    kt = open(os.path.join(args.dump, "kernel_text.bin"), "rb").read()
    se = open(os.path.join(args.dump, "sysent_raw.bin"), "rb").read()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.skipdata = True
    rows = []
    for n in range(532, 677):
        body, narg = body_of(kt, se, n)
        if body is None:
            continue
        for at, src, size, got in scan(kt, md, narg, body, args.min):
            rows.append((got / float(size), n, narg, at, src, size, got))
    rows.sort()
    for ratio, n, narg, at, src, size, got in rows:
        if ratio <= 0.125:
            print("sys %-4d narg=%d copyout@%07x size=0x%-4x covered=0x%-4x (%.0f%%)"
                  % (n, narg, at, size, got, ratio * 100))
    print("%d low-coverage stack copyouts of %d scanned" %
          (sum(1 for r in rows if r[0] <= 0.125), len(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
