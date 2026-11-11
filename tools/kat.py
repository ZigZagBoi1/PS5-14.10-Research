
import sys, capstone
BASE = 0xffffffff8a9c0000
TEXT = open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
start = int(sys.argv[1],16); n = int(sys.argv[2]); skip = int(sys.argv[3]) if len(sys.argv)>3 else 0
code = TEXT[start:start+(n+skip)*15]
i=0
for insn in md.disasm(code, start):
    if i>=skip: print(f"  {insn.address:08x} {insn.mnemonic} {insn.op_str}")
    i+=1
    if i>=n+skip: break
