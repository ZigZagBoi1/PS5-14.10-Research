#!/usr/bin/env python3
"""Resolve 13.60 Sony syscall thunks and extract real handler code from kernel_text.bin.

Each handler_NNN.bin starts at the sysent sy_call address, which points into a
thunk table: `e9 <rel32> cc cc cc` (jmp + int3, 8-byte stride). The real handler
is at kernel_base + (sy_call_off + 5 + rel32). kernel_text.bin covers RVA
0x0..0xe6e5c0, which contains every thunk target.

Usage:
    python tools/offline/handler_extract.py            # inventory all 532-676
    python tools/offline/handler_extract.py 604 636    # extract + disasm
    python tools/offline/handler_extract.py --json out.json
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DUMPS = os.path.join(ROOT, "docs", "dumps_13.60")
TEXT = open(os.path.join(DUMPS, "kernel_text.bin"), "rb").read()
TEXT_SIZE = len(TEXT)
SYSCALL_RANGE = range(532, 677)


def load_sysent():
    idx = json.load(open(os.path.join(DUMPS, "sysent_index.json")))
    return {e["num"]: e for e in idx["entries"]}


def thunk_target(sy_call_off: int) -> int | None:
    """Read the JMP rel32 at RVA sy_call_off and return the target RVA."""
    off = int(sy_call_off, 16) if isinstance(sy_call_off, str) else int(sy_call_off)
    if off + 5 > TEXT_SIZE:
        return None
    if TEXT[off] != 0xE9:
        return None  # not a thunk (direct handler or nosys stub marker)
    rel = struct.unpack("<i", TEXT[off + 1 : off + 5])[0]
    return off + 5 + rel


def handler_bytes(rva: int, size: int) -> bytes:
    return TEXT[rva : min(rva + size, TEXT_SIZE)]


def estimate_size(rva: int, max_size: int = 0x20000) -> int:
    """Estimate handler extent: pad-to-16 gap of 0xCC/0x00 after the code, or next thunk target."""
    end = min(rva + max_size, TEXT_SIZE)
    # look for a run of >= 12 int3/nop bytes aligned-ish after 0x20 bytes of code
    i = rva + 0x10
    run = 0
    while i < end:
        b = TEXT[i]
        if b in (0xCC, 0x90):
            run += 1
            if run >= 12:
                return i - run - rva
        else:
            run = 0
        i += 1
    return max_size


def disasm(rva: int, size: int, resolve_calls=True, syent=None) -> str:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    out = []
    for insn in md.disasm(handler_bytes(rva, size), rva):
        line = f"  {insn.address:#010x}  {insn.bytes.hex():<20} {insn.mnemonic} {insn.op_str}"
        out.append(line.rstrip())
    return "\n".join(out)


def main():
    syent = load_sysent()
    args = sys.argv[1:]
    if args and args[0] == "--json":
        inv = {}
        for num in SYSCALL_RANGE:
            e = syent[num]
            tgt = thunk_target(e["sy_call_off"])
            inv[num] = {
                "narg": e["narg"],
                "sy_call_off": e["sy_call_off"],
                "handler_rva": hex(tgt) if tgt is not None else None,
                "est_size": estimate_size(tgt) if tgt else None,
            }
        json.dump(inv, open(args[1], "w"), indent=1)
        print(f"wrote {args[1]} ({len(inv)} entries)")
        return
    nums = [int(a) for a in args] if args else []
    for num in nums:
        e = syent[num]
        tgt = thunk_target(e["sy_call_off"])
        print(f"=== syscall {num} narg={e['narg']} thunk_rva={e['sy_call_off']} handler_rva={hex(tgt) if tgt is not None else None}")
        if tgt is None:
            print("  (no thunk / direct code?)")
            continue
        size = estimate_size(tgt)
        print(f"  estimated size: {size} bytes")
        print(disasm(tgt, size))


if __name__ == "__main__":
    main()
