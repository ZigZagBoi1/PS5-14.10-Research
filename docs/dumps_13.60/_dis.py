
import capstone, json
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
data=open(P,'rb').read()
BASE=0xffffffff8a9c0000
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
start=0x3b01f0; end=0x3b1200
lines=[]
n=0
for ins in md.disasm(data[start:end], BASE+start):
    txt="%08x  %-22s %s %s"%(ins.address-BASE, ins.bytes.hex(), ins.mnemonic, ins.op_str)
    lines.append(txt)
open(r"C:\PS5contrib\docs\dumps_13.60\_dis_663_full.txt","w").write("\n".join(lines))
print("total",len(lines))
# find rets and jumps to outside
import re
for i,l in enumerate(lines):
    if l.split()[1] in ('c3','c2') or ' ret' in l:
        print("RET:",l)

