
import capstone, json
P = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data = open(P,"rb").read()
surv = json.load(open(r"C:\PS5contrib\docs\_mg_surv.json"))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True

def ctx(rva, back=12, fwd=0x20):
    st=max(0,rva-back)
    out=[]
    for ins in md.disasm(data[st:rva+fwd], BASE+st):
        mark = "  <<<" if ins.address-BASE==rva else ""
        out.append("   %08x %-30s %s%s" % ((ins.address-BASE), ins.bytes.hex(), ins.mnemonic+" "+ins.op_str, mark))
    return "\n".join(out)

sel=[h for h in surv if h["imm"]==0x08ffffff][:4]
for h in sel:
    print("=== imm 0x%08x at rva %x" % (h["imm"], h["rva"]))
    print(ctx(h["rva"]))
print()
print("=== sample of 0xffffffff (cmp -1) group")
for h in [x for x in surv if x["imm"]==0xffffffff][:3]:
    print("--- rva %x" % h["rva"]); print(ctx(h["rva"]))
