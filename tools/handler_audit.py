#!/usr/bin/env python3
"""Audit the 13.60 Sony handler bodies for copyin/free aliasing.

Only useful with the offline dump in docs/dumps_13.60/. Resolves each
sysent sy_call through its `jmp rel32` stub chain, disassembles the body
linearly, and reports handlers where the destination slot of a copyin is
later passed to free - the shape where a failed copyin leaves a stack
slot holding a stale pointer that is then freed.

Usage: python tools/handler_audit.py [--dump docs/dumps_13.60]
"""
import argparse
import os
import struct
import sys

import capstone

BASE = 0xffffffff8a9c0000
COPYIN = 0xffffffff8ac19280
FREE = 0xffffffff8b5c8df0
COPYOUT = 0xffffffff8aa63960
BODY_CAP = 0x1800


def load(dump):
    kt = open(os.path.join(dump, "kernel_text.bin"), "rb").read()
    se = open(os.path.join(dump, "sysent_raw.bin"), "rb").read()
    return kt, se


def resolve(kt, addr):
    for _ in range(4):
        off = addr - BASE
        if off < 0 or off + 5 > len(kt):
            return None
        if kt[off] == 0xE9:
            addr = addr + 5 + struct.unpack_from("<i", kt, off + 1)[0]
        elif kt[off] == 0xCC:
            return None
        else:
            return addr
    return None


def slot(op):
    """Return the rbp-relative slot referenced by an operand, or None."""
    if "[rbp - " not in op:
        return None
    try:
        return int(op.split("[rbp - ")[1].split("]")[0], 16)
    except ValueError:
        return None


def audit(kt, narg, body):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.skipdata = True
    loads, hits = {}, []
    off = body - BASE
    window = []
    for ins in md.disasm(kt[off:off + BODY_CAP], body):
        m, o = ins.mnemonic, ins.op_str
        window.append((ins.address - BASE, m, o))
        if len(window) > 64:
            window.pop(0)
        if m == "mov" and o.startswith("rdi, qword ptr [rbp - "):
            loads[o.split(",")[0]] = slot(o)
        if m == "lea" and o.startswith("rsi, [rbp - ") or (
                m == "mov" and o.startswith("rsi, ") and slot(o) is not None):
            pass
        if m == "call":
            tgt = int(o, 16) if o.startswith("0x") else None
            if tgt == COPYIN:
                for addr, mm, oo in reversed(window):
                    if mm == "lea" and oo.startswith("rsi, [rbp - "):
                        s = slot(oo)
                        if s is not None:
                            loads.setdefault("copyin", s)
                        break
            elif tgt == FREE:
                s = loads.get("rdi")
                if s is not None:
                    hits.append((ins.address - BASE, s))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", default="docs/dumps_13.60")
    args = ap.parse_args()
    kt, se = load(args.dump)
    rows = []
    for n in range(0, len(se) // 48):
        narg, _flags, call = struct.unpack_from("<IIQ", se, n * 48)
        if (call >> 48) != 0xFFFF:
            continue
        body = resolve(kt, call)
        if body is None:
            continue
        hits = audit(kt, narg, body)
        if hits:
            rows.append((n, narg, body - BASE, hits))
    for n, narg, off, hits in rows:
        seen = ", ".join("off %x slot -%x" % (a, s) for a, s in hits[:4])
        print("sys %-4d narg=%d body=%07x %s" % (n, narg, off, seen))
    print("%d handlers free a copyin destination slot" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
