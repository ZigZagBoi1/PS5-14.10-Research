
import sys
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
from kc import *
import capstone

def lin(start, nbytes):
    out=[]
    blob=data[start:start+nbytes]
    for i in MD.disasm(blob, BASE+start):
        out.append(i)
    return out

def dump(start,nbytes,tag=''):
    print("===== %s %08x ====="%(tag,start))
    for i in lin(start,nbytes):
        a=i.address-BASE
        print("%08x  %-22s %s %s"%(a,i.bytes.hex(),i.mnemonic,i.op_str))

dump(0x259280,0x90,"copyin?")
dump(0x258ff0,0x80,"copyout?")
dump(0x2591d0,0xa0,"variant")
dump(0x25d410,0x10,"jmp")
