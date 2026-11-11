
import sys
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
import struct
def hx(a,n):
    return ' '.join('%02x'%b for b in data[a:a+n])
print('bytes 0x6bdfd0..0x6be008:')
print(hx(0x6bdfd0,0x38))
print()
for st in (0x6bdfc0,0x6bdfce,0x6bdfe0,0x6bdfee,0x6bdff0):
    print('--- decode from %#x'%st)
    for i in md.disasm(data[st:0x6be000], BASE+st):
        print('   %08x %-20s %s %s'%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
