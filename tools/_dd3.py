
import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
def show(E,S,before=0x180,after=0x10):
    a=max(E,S-before); print('=== fs %#x site %#x'%(E,S))
    for i in md.disasm(data[a:S+after], BASE+a):
        print('%s %08x %-14s %s %s'%('>>' if i.address-BASE==S else '  ',i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
show(0x50cab0,0x50cb65,0x120)
print()
show(0xb71e20,0xb71f8b,0x120)
print()
print('== callee 0xb2a7b50 head ==')
for i in md.disasm(data[0xb2a7b50:0xb2a7b50+0x60], BASE+0xb2a7b50):
    print('%08x %-14s %s %s'%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
