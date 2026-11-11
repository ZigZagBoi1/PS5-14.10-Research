
import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
S=0xa1cf1d
print('bytes', data[S-0x30:S].hex())
a=S-0x28
for i in md.disasm(data[a:S+8], BASE+a):
    print('%s %08x %-14s %s %s'%('>>' if i.address-BASE==S else '  ',i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
