
import sys
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
for a in (0x42a2d0,0x42a4e0,0x503af0,0x503d80,0x4d9e60,0x43b880,0x747b30,0xc039f0):
    print('== %08x'%a)
    n=0
    for i in md.disasm(data[a:a+0x40], BASE+a):
        print('   %08x %-16s %s %s'%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str)); n+=1
        if n>=7: break
