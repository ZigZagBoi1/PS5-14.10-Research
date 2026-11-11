
import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
def win(E,S,before=0x40,after=0x30):
    a=max(E,S-before); print('--- fs %#x site %#x window %#x..%#x'%(E,S,a,S+after))
    cur=a
    for i in md.disasm(data[a:S+after], BASE+a):
        mark='>>' if i.address-BASE==S else '  '
        print('%s %08x %-18s %s %s'%(mark,i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
for E,S in [(0x50cab0,0x50cb65),(0x9aa380,0x9aa62d),(0x9aa8d0,0x9aaacf),(0x782530,0x782663),(0xbb1758,0xbb1758),(0x31cbe0,0x31ccb8)]:
    win(E,S)
    print()
