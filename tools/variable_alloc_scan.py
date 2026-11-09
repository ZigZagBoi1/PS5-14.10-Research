"""Find variable-size kernel allocations that are filled from user memory.

A reclaim primitive for a use-after-free needs `malloc(user_len)` followed by a copy of the
caller's bytes into the new object. This scans every malloc call in the 13.60 text, keeps the ones
whose size comes from a register, and reports the ones with a copyin within 60 instructions.
"""
import capstone, json, bisect, re, sys

BASE = 0xffffffff8a9c0000
MALLOC = 0xffffffff8b5c8b50
COPYIN = {0xffffffff8ac19280, 0xffffffff8aa63960, 0xffffffff8ac191d0, 0xffffffff8ac19be0}
data = open("docs/dumps_13.60/kernel_text.bin", "rb").read()
idx = json.load(open("docs/dumps_13.60/sysent_index.json", encoding="utf-8"))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata = True

def at(va, n):
    o = va - BASE
    return data[o:o + n] if 0 <= o < len(data) else b""

def resolve(va):
    b = at(va, 8)
    if len(b) >= 5 and b[0] == 0xE9:
        return (va + 5 + int.from_bytes(b[1:5], "little", signed=True)) & 0xffffffffffffffff
    return va

bodies = []
for e in idx["entries"]:
    if 532 <= e["num"] <= 676:
        t = resolve(int(e["sy_call"], 16))
        if t:
            bodies.append((t, e["num"]))
bodies.sort()
addrs = [a for a, _ in bodies]

def owner(va):
    i = bisect.bisect_right(addrs, va) - 1
    return bodies[i][1] if i >= 0 else None

hits = []
for ins in md.disasm(data, BASE):
    if ins.mnemonic != "call" or ins.op_str != hex(MALLOC):
        continue
    prev = list(md.disasm(at(ins.address - 48, 48), ins.address - 48))
    size_op = None
    for p in reversed(prev[-8:]):
        if p.mnemonic == "mov" and re.match(r"e?di, ", p.op_str):
            size_op = p.op_str.split(", ")[1]
            break
    if size_op is None or size_op.startswith("0x"):
        continue
    fwd = list(md.disasm(at(ins.address + 5, 0x120), ins.address + 5))
    copies = [w for w in fwd[:70] if w.mnemonic == "call" and w.op_str in {hex(c) for c in COPYIN}]
    if copies:
        hits.append((owner(ins.address), ins.address, size_op, copies[0].address))

print("variable-size mallocs with a copyin nearby:", len(hits))
for n, a, s, c in hits:
    print("sys %s  0x%X  size=%s  copy@0x%X" % (n, a, s, c))
