
import json,struct,sys
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
from collections import defaultdict
recs=json.load(open(r'C:\PS5contrib\tools\_census2.json'))
B=defaultdict(list)
for r in recs: B[r['cls']].append(r)
for cls in ['derived:unknown','derived:imm','derived:spill','loadfrom:clobbered','global','none-in-window']:
    print('===',cls,len(B[cls]))
    for r in B[cls]:
        d=r.get('dec') or {}
        print('  %08x fs=%08x sc=%s | %s %s | root=%s deref=%s expr=%s'%(r['site'],r['fstart'],r.get('score'),d.get('mnem',''),d.get('op',''),r.get('root'),r.get('derefs'),r.get('expr')))
print()
def dis(rva,n=0x60,label=''):
    print('--- %s %#x'%(label,rva))
    cur=rva
    for i in md.disasm(data[rva:rva+n], BASE+rva):
        print('   %08x %-20s %s %s'%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
for t in (0xc08b50,0x794ee0,0x42a2d0,0x42a4e0,0x503d80,0x4d9e60,0x43b880,0xc039f0):
    dis(t,0x50,'retval-callee')
