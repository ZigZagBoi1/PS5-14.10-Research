"""Attribute every small allocation to the syscall handler that can reach it."""
import capstone, json, collections, bisect, re

BASE = 0xffffffff8a9c0000
MALLOC = 0xffffffff8b5c8b50
COPYIN = {0xffffffff8ac19280, 0xffffffff8aa63960, 0xffffffff8ac191d0}
data = open("docs/dumps_13.60/kernel_text.bin", "rb").read()
idx = json.load(open("docs/dumps_13.60/sysent_index.json", encoding="utf-8"))

def at(va, n=8):
    o = va - BASE
    return data[o:o + n] if 0 <= o < len(data) else b""

def resolve(va):
    b = at(va, 8)
    if len(b) < 6:
        return None
    if b[0] == 0xE9:
        return (va + 5 + int.from_bytes(b[1:5], "little", signed=True)) & 0xffffffffffffffff
    if b[0] == 0xFF and b[1] == 0x25:
        return None
    return va

bodies = {}
for e in idx["entries"]:
    n = e["num"]
    if not (532 <= n <= 676):
        continue
    t = resolve(int(e["sy_call"], 16))
    if t:
        bodies[n] = t
ordered = sorted((v, k) for k, v in bodies.items())
addrs = [a for a, _ in ordered]

def owner(va):
    i = bisect.bisect_right(addrs, va) - 1
    return ordered[i][1] if i >= 0 else None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata = True
small = []
for ins in md.disasm(data, BASE):
    if ins.mnemonic != "call" or ins.op_str != hex(MALLOC):
        continue
    owner_n = owner(ins.address)
    insns = list(md.disasm(at(ins.address - 90, 90), ins.address - 90)) if ins.address - 90 > BASE else []
    size = None
    for prev in reversed(insns[-14:]):
        if prev.mnemonic == "mov" and prev.op_str.startswith("edi, 0x"):
            size = int(prev.op_str.split(", ")[1], 16)
            break
        if prev.mnemonic == "mov" and prev.op_str == "edi, 0x30":
            size = 0x30
            break
    if size is not None and 0x20 <= size <= 0x40:
        fwd = list(md.disasm(at(ins.address + 5, 0x100), ins.address + 5))
        copy = any(w.mnemonic == "call" and int(w.op_str, 16) & 0xffffffffffffffff in COPYIN
                   for w in fwd[:60] if re.fullmatch(r"0x[0-9a-f]+", w.op_str))
        small.append((owner_n, ins.address, size, copy))

print("small allocs attributed:", len(small))
print("with a copyin within 60 insns:", sum(1 for x in small if x[3]))
for n in sorted({x[0] for x in small if x[0] is not None}):
    hits = [x for x in small if x[0] == n]
    if n in (601, 610, 622):
        txt = " ".join("%s@%X%s" % (hex(s)[2:], a, "*" if c else "") for _, a, s, c in hits)
    else:
        txt = ",".join("%s%s" % (hex(s)[2:], "*" if c else "") for _, a, s, c in hits)
    print("sys %d  n=%d  %s" % (n, len(hits), txt))
