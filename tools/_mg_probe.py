
import sys, os, struct
import capstone
print("capstone", capstone.__version__)
p = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
print("size", os.path.getsize(p))
BASE = 0xffffffff8a9c0000
data = open(p,"rb").read()
print("first16", data[:16].hex())
# verify known site: VA 0x8b47b9d3 -> bytes should be 41 81 7e 20 00 00 00 40
va = 0x8b47b9d3
rva = (va - BASE) & 0xffffffffffffffff
print("rva of 8b47b9d3 =", hex(rva))
print("bytes:", data[rva:rva+8].hex())
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True
for i in md.disasm(data[rva:rva+24], va):
    print(hex(i.address), i.mnemonic, i.op_str, "id", i.id)
