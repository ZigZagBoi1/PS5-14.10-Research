
import capstone, json
P  = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data=open(P,"rb").read(); N=len(data)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
rva=0xabb9d3
print("bytes at gate:", data[rva-16:rva+32].hex())
for i in md.disasm(data[rva-0x40:rva+0x60], BASE+rva-0x40):
    print("  %08x %-24s %s %s" % (i.address-BASE, i.bytes.hex(), i.mnemonic, i.op_str))
raw=json.load(open(r"C:\PS5contrib\docs\_mg_raw.json"))
near=[h for h in raw if 0xabb900<=h["rva"]<=0xabbb00]
print("raw hits in 0xabb900-0xabbb00:", [(hex(h['rva']),hex(h['imm'])) for h in near])
print("raw hits with imm 0x40000000:", len([h for h in raw if h['imm']==0x40000000]))
print("  at rvas:", [hex(h['rva']) for h in raw if h['imm']==0x40000000][:25])
