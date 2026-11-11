
import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
def show(E,S,before=0x90,after=0x20):
    a=max(E,S-before); print('=== fs %#x site %#x'%(E,S))
    for i in md.disasm(data[a:S+after], BASE+a):
        print('%s %08x %-18s %s %s'%('>>' if i.address-BASE==S else '  ',i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
show(0xa0ac60,0xa0ad68)
print()
show(0xb71e20,0xb71f8b)
