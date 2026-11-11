
import sys
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
def show(start,end,label=''):
    print('---',label,hex(start))
    for i in md.disasm(data[start:end], BASE+start):
        print('  %08x  %-24s %s %s'%(i.address-BASE, i.bytes.hex(), i.mnemonic, i.op_str))
show(0x530480,0x5305b0,'handler 0x530480')
print()
show(0x5304d8,0x5304f8,'narrow')
print()
show(0x6bdff0,0x6be000,'none-in-window site 0x6bdffc')
