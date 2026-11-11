
import sys
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
from kc import *
import capstone
md2=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); md2.detail=False
def lin(s,n):
    return list(md2.disasm(data[s:s+n], BASE+s))
def dump(s,n,tag=''):
    print("===== %s %08x ====="%(tag,s))
    for i in lin(s,n):
        print("%08x  %-20s %s %s"%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
dump(0x2522c0,0x120,"ctxsw A")
dump(0x2529c0,0x120,"ctxsw B")
dump(0x259a60,0xc0,"0x259aa3")
dump(0x259b40,0x60,"0x259b70")
