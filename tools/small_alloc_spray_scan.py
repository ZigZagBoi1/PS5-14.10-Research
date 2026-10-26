"""Find kernel allocations in 0x20..0x40 that are filled from user memory.

Scans the 13.60 text capture for `mov edi, size` / `call malloc-like` pairs, then asks whether the
returned pointer reaches a copyin (or a loop that stores into it) before the next call. A hit is a
candidate reclaim target for a use-after-free of that size class.
"""
import capstone, sys, struct

BASE = 0xffffffff8a9c0000
MALLOC = {0xffffffff8b5c8b50, 0xffffffff8ac08b50, 0xffffffff8b5c8df0}
COPYIN = {0xffffffff8ac19280, 0xffffffff8aa63960, 0xffffffff8ac191d0, 0xffffffff8ac18ff0}

data = open("docs/dumps_13.60/kernel_text.bin", "rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

lo, hi = int(sys.argv[1], 0), int(sys.argv[2], 0)
start, end = lo - BASE, hi - BASE
insns = list(md.disasm(data[start:end], lo))

hits = []
for i, ins in enumerate(insns):
    if ins.mnemonic != "mov" or ins.op_str.split(",")[0].strip() not in ("edi", "rdi"):
        continue
    try:
        size = int(ins.op_str.split(",")[1].strip(), 0)
    except ValueError:
        continue
    if not (0x20 <= size <= 0x40):
        continue
    # next instruction must be the allocator call
    if i + 1 >= len(insns) or insns[i + 1].mnemonic != "call":
        continue
    try:
        tgt = int(insns[i + 1].op_str, 16) & 0xffffffffffffffff
    except ValueError:
        continue
    if tgt not in MALLOC:
        continue
    window = insns[i + 2:i + 40]
    copy = []
    for w in window:
        if w.mnemonic != "call":
            continue
        try:
            t = int(w.op_str, 16) & 0xffffffffffffffff
        except ValueError:
            continue
        if t in COPYIN:
            copy.append(w)
    stores = [w for w in window if w.mnemonic in ("mov", "rep stosq", "stosq") and "[rax" in w.op_str]
    hits.append((ins.address, size, bool(copy), len(stores), copy[0].address if copy else 0))

print("candidates", len(hits))
for a, size, c, n, ca in hits:
    if c:
        print("USER-FILLED 0x%X size=0x%X copyin@0x%X" % (a, size, ca))
print("--- all, sized 0x28-0x40 with a copyin:")
for a, size, c, n, ca in hits:
    if c and 0x28 <= size <= 0x40:
        print("0x%X size=0x%X" % (a, size))
