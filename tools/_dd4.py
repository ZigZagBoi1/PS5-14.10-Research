
import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
def show(E,S,n=16,after=6):
    print('=== fs %#x site %#x'%(E,S))
    a=max(E,S-0x60); ins=list(md.disasm(data[a:S+after], BASE+a))
    for i in ins[-n:]:
        print('%s %08x %-14s %s %s'%('>>' if i.address-BASE==S else '  ',i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
show(0x446fd0,0x44708e)
show(0xc89060,0xc89127)
show(0x313a90,0x313acc)
show(0x3ef380,0x3ef463)
show(0x31cbe0,0x31d2e8)
show(0x9855c0,0x985f76)
show(0x3b6c10,0x3b6dfa)
show(0x9aa380,0x9aa62d)
