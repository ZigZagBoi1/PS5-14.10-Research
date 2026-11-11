
import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
recs={r['site']:r for r in json.load(open(r'C:\PS5contrib\tools\_final.json'))}
r=recs[0xa1cf1d]; E=r['fs']; S=0xa1cf1d
a=max(E,S-0x70)
for i in md.disasm(data[a:S+8], BASE+a):
    print('%s %08x %-14s %s %s'%('>>' if i.address-BASE==S else '  ',i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
