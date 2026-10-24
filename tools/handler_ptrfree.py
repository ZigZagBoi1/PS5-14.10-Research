#!/usr/bin/env python3
"""Find handlers that free a pointer they copied in from user memory.

The shape searched for is:

    lea  rsi, [rbp-X]      ; destination
    mov  edx, 8            ; pointer-sized
    call copyin
    ...
    mov  rdi, [rbp-X]      ; the user-supplied pointer
    call free

If such a site is reachable, the kernel frees an address chosen by the
caller. Sites where the copied value is only compared or copied out are
not reported.

Usage: python tools/handler_ptrfree.py [--dump docs/dumps_13.60]
"""
import argparse
import os
import struct
import sys

import capstone

BASE = 0xffffffff8a9c0000
COPYIN = 0xffffffff8ac19280
FREE = 0xffffffff8b5c8df0
BODY_CAP = 0x1800
PTR_SIZES = {8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40}


def slot(op):
    if "[rbp - " not in op:
        return None
    try:
        return int(op.split("[rbp - ")[1].split("]")[0], 16)
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", default="docs/dumps_13.60")
    args = ap.parse_args()
    kt = open(os.path.join(args.dump, "kernel_text.bin"), "rb").read()
    se = open(os.path.join(args.dump, "sysent_raw.bin"), "rb").read()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.skipdata = True

    found = 0
    for n in range(len(se) // 48):
        narg, _flags, call = struct.unpack_from("<IIQ", se, n * 48)
        if (call >> 48) != 0xFFFF:
            continue
        addr = call
        for _ in range(4):
            off = addr - BASE
            if off < 0 or off + 5 > len(kt) or kt[off] == 0xCC:
                addr = None
                break
            if kt[off] != 0xE9:      # reached the body
                break
            addr = addr + 5 + struct.unpack_from("<i", kt, off + 1)[0]
        if addr is None:
            continue
        off = addr - BASE
        pend_slot = pend_size = None
        ptr_slots = {}
        hits = []
        for ins in md.disasm(kt[off:off + BODY_CAP], addr):
            m, o = ins.mnemonic, ins.op_str
            if m == "lea" and o.startswith("rsi, [rbp - "):
                pend_slot, pend_size = slot(o), None
            elif m == "mov" and o.startswith("edx, ") and pend_slot is not None:
                try:
                    pend_size = int(o.split(", ")[1], 0)
                except ValueError:
                    pend_size = None
            elif m == "call":
                try:
                    tgt = int(o, 16)
                except ValueError:
                    tgt = 0
                if tgt == COPYIN and pend_slot is not None and pend_size in PTR_SIZES:
                    ptr_slots[pend_slot] = (ins.address - BASE, pend_size)
                if tgt == FREE and o.startswith("0x"):
                    pass
                if tgt == FREE:
                    s = ld_slot
                    if s in ptr_slots:
                        hits.append((ptr_slots[s], ins.address - BASE, s))
            if m == "mov" and o.startswith("rdi, qword ptr [rbp - "):
                ld_slot = slot(o)
            elif m in ("call", "xor", "mov") and not o.startswith("rdi,"):
                if m != "mov" or not o.startswith("rdi,"):
                    pass
        if hits:
            found += 1
            for (src, size), at, s in hits[:6]:
                print("sys %-4d narg=%d copyin@%07x size=%-3d free@%07x slot -%x"
                      % (n, narg, src, size, at, s))
    print("%d sites" % found)
    return 0


if __name__ == "__main__":
    sys.exit(main())
