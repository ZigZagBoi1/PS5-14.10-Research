"""Census of kernel allocation sizes: every `call malloc` with a nearby `mov edi, size`."""
import capstone, collections, sys

BASE = 0xffffffff8a9c0000
MALLOC = {0xffffffff8b5c8b50}
d = open("docs/dumps_13.60/kernel_text.bin", "rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata = True

sizes = collections.Counter()
sites = collections.defaultdict(list)
for ins in md.disasm(d, BASE):
    if ins.mnemonic != "call":
        continue
    try:
        t = int(ins.op_str, 16) & 0xffffffffffffffff
    except ValueError:
        continue
    if t not in MALLOC:
        continue
    sizes["call"] += 1
    sites["call"].append(ins.address)
print("malloc calls:", sizes["call"])
print("sites:", [hex(a) for a in sites["call"][:20]])
