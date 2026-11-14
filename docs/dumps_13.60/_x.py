
import capstone, os
D=r"C:\PS5contrib\docs\dumps_13.60"
data=open(os.path.join(D,"kernel_text.bin"),'rb').read()
BASE=0xffffffff8a9c0000
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
def sweep(s,e):
    out=[]; i=s
    while i<e:
        got=None
        for ins in md.disasm(data[i:i+15], BASE+i, count=1): got=ins; break
        if got is None: i+=1; continue
        out.append(got); i+=len(got.bytes)
    return out
def show(rva,t,n=45):
    print("=== %s (rva %06x) ==="%(t,rva)); k=0
    for ins in sweep(rva,rva+0x90):
        if ins.mnemonic in ('nop','int3'): continue
        print("%08x %-14s %s %s"%(ins.address-BASE, ins.bytes.hex(), ins.mnemonic, ins.op_str)); k+=1
        if k>=n: break
for rva,t in [(0x4C6A00,"0x8ae86a00"),(0x4C6FA0,"0x8ae86fa0"),(0xC06910,"0x8b5c6910"),(0x3B4190,"0x8ad74190")]:
    show(rva,t,28)

