
import sys
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
from kc import *
import capstone
md2=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); md2.detail=False

def func_start(addr, back=0x600):
    s=max(0,addr-back)
    # find last padding byte (0x90 or 0xcc) run before addr, then function begins after it
    best=None
    i=addr-1
    while i>s:
        if data[i] in (0x90,0xcc):
            j=i
            while j>s and data[j] in (0x90,0xcc): j-=1
            if j<addr-1:
                best=j+1
                break
        i-=1
    # align: candidate must decode a prologue
    print("candidate start for %08x: %s"%(addr, hex(best) if best else None))
    return best

for a in (0x252a20,0x25233c,0x259aa3):
    st=func_start(a)
    if st is not None:
        for i in md2.disasm(data[st:st+0x40], BASE+st):
            print("   %08x %-16s %s %s"%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
