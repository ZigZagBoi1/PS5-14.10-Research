
import sys, capstone
from capstone import x86
BASE = 0xffffffff8a9c0000
TEXT = open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
start = int(sys.argv[1],16); n = int(sys.argv[2]) if len(sys.argv)>2 else 40
code = TEXT[start:start+n*15]
i=0
for insn in md.disasm(code, start):
    print(f"{insn.address:08x}  {insn.bytes.hex():<20} {insn.mnemonic} {insn.op_str}")
    i+=1
    if i>=n: break
