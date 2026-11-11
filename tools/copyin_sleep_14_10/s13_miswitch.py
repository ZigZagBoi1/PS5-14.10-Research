
import sys
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
from kc import *
import capstone
md2=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); md2.detail=False
def dump(s,n,tag=''):
    print("===== %s %08x ====="%(tag,s))
    for i in md2.disasm(data[s:s+n], BASE+s):
        print("%08x  %-18s %s %s"%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
dump(0x6b5d80,0x120,"caller A")
dump(0x6b6680,0x120,"caller B")
