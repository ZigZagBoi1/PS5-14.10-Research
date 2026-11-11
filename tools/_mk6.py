
import sys
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
for a in (0x42a2d0,0x42a4e0,0x503af0,0x503d80,0x4d9e60,0x43b880,0x747b30,0xc039f0):
    hits=[];firstret=None
    for i in md.disasm(data[a:a+0x600], BASE+a):
        if i.mnemonic=='call' and i.op_str.startswith('0x'):
            t=int(i.op_str,16)-BASE
            if t in (0xc08b50,0x794ee0,0xc039f0): hits.append('%08x->%08x'%(i.address-BASE,t))
        if i.mnemonic=='ret' and firstret is None: firstret=i.address-BASE
    print('%08x malloccalls=%s firstret=%s'%(a,hits[:3],hex(firstret) if firstret else None))
